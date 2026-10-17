// Package tunnel implements the Mirage client and server.
//
// Client: listens as a SOCKS5 proxy, encapsulates outbound traffic in
// polymorphic protocol packets, and sends them to the server over TCP.
//
// Server: receives morphed packets, extracts tunnel data, and forwards
// to the intended destination.
package tunnel

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/arashmh13/mirage/pkg/crypto"
	"github.com/arashmh13/mirage/pkg/morph"
	"github.com/arashmh13/mirage/pkg/protocol"
)

const (
	// MaxPacketSize is the maximum size of a morphed packet on the wire.
	MaxPacketSize = 1500

	// FrameHeaderSize is the size of the internal frame header.
	// [StreamID:4][DataLen:2] = 6 bytes
	FrameHeaderSize = 6

	// MaxPayloadSize is the maximum payload per morphed packet.
	MaxPayloadSize = MaxPacketSize - FrameHeaderSize - 64 // 64 for worst-case morph overhead

	// HandshakeTimeout for initial connection.
	HandshakeTimeout = 10 * time.Second
)

// Server implements the Mirage tunnel server.
type Server struct {
	listenAddr string
	psk        []byte
	morphSched *morph.EpochSchedule
}

// NewServer creates a new Mirage server.
func NewServer(listenAddr string, psk []byte) *Server {
	return &Server{
		listenAddr: listenAddr,
		psk:        psk,
		morphSched: morph.NewEpochSchedule(psk, 30*time.Second),
	}
}

// Run starts the server and blocks until an error occurs.
func (s *Server) Run() error {
	listener, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("server listen: %w", err)
	}
	defer listener.Close()

	log.Printf("[server] Mirage tunnel listening on %s", s.listenAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("[server] accept error: %v", err)
			continue
		}
		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()
	log.Printf("[server] new connection from %s", conn.RemoteAddr())

	// Handshake: read the session key from the first packet
	// The first packet is always a TLSClientHello morph containing
	// the encrypted session init frame
	sessionKey, err := s.readHandshake(conn)
	if err != nil {
		log.Printf("[server] handshake failed: %v", err)
		return
	}

	log.Printf("[server] session established with %s", conn.RemoteAddr())

	// Create per-session morph schedule
	sched := morph.NewSchedule(sessionKey)

	// Read loop: receive morphed packets, extract data
	streams := make(map[uint32]net.Conn)
	var streamsMu sync.Mutex

	for {
		// Read the next morphed type (1 byte)
		actualType, data, err := s.readFrame(conn, sched)
		if err != nil {
			if err != io.EOF {
				log.Printf("[server] read error: %v", err)
			}
			break
		}

		// Type is read from the wire — use it directly (sender may skip
		// morph types that don't fit the payload, so we just accept what we get)
		_ = sched.Next() // advance schedule to stay roughly in sync

		// Extract the payload
		payload, err := protocol.ExtractPayload(actualType, data)
		if err != nil {
			log.Printf("[server] extract payload: %v", err)
			continue
		}

		// Decrypt
		plaintext, err := crypto.Open(sessionKey, payload)
		if err != nil {
			log.Printf("[server] decrypt: %v", err)
			continue
		}

		// Parse frame header
		if len(plaintext) < FrameHeaderSize {
			log.Printf("[server] frame too short: %d bytes", len(plaintext))
			continue
		}
		streamID := binary.BigEndian.Uint32(plaintext[0:4])
		dataLen := binary.BigEndian.Uint16(plaintext[4:6])
		frameData := plaintext[FrameHeaderSize:]

		if int(dataLen) != len(frameData) {
			log.Printf("[server] data length mismatch: %d != %d", dataLen, len(frameData))
			continue
		}

		// Stream 0 is control; non-zero streams are proxied connections
		if streamID == 0 {
			// Control frame - handle specially
			log.Printf("[server] control frame: %d bytes", len(frameData))
			continue
		}

		streamsMu.Lock()
		stream, ok := streams[streamID]
		if !ok {
			// New stream - connect to the target specified in first frame
			// First frame for a stream contains: [targetLen:2][targetAddr][extraData...]
			if len(frameData) < 2 {
				streamsMu.Unlock()
				log.Printf("[server] new stream frame too short")
				continue
			}
			targetLen := binary.BigEndian.Uint16(frameData[0:2])
			if len(frameData) < int(2+targetLen) {
				streamsMu.Unlock()
				log.Printf("[server] target address truncated")
				continue
			}
			targetAddr := string(frameData[2 : 2+targetLen])
			extraData := frameData[2+targetLen:] // data after the address

			log.Printf("[server] new stream %d to %s", streamID, targetAddr)
			stream, err = net.DialTimeout("tcp", targetAddr, 10*time.Second)
			if err != nil {
				streamsMu.Unlock()
				log.Printf("[server] dial %s: %v", targetAddr, err)
				continue
			}
			streams[streamID] = stream
			streamsMu.Unlock()

			// Read from target and send back
			go s.proxyTargetToClient(stream, streamID, conn, sched, sessionKey)

			// Write any extra data that followed the address
			if len(extraData) > 0 {
				stream.SetWriteDeadline(time.Now().Add(30 * time.Second))
				if _, err := stream.Write(extraData); err != nil {
					log.Printf("[server] write extra data to stream %d: %v", streamID, err)
				}
			}
			continue // done processing this frame
		} else {
			streamsMu.Unlock()
		}

		// Write data to target
		if len(frameData) > 0 {
			stream.SetWriteDeadline(time.Now().Add(30 * time.Second))
			if _, err := stream.Write(frameData); err != nil {
				log.Printf("[server] write to stream %d: %v", streamID, err)
			}
		}
	}

	// Cleanup
	streamsMu.Lock()
	for id, stream := range streams {
		stream.Close()
		delete(streams, id)
	}
	streamsMu.Unlock()
}

func (s *Server) readHandshake(conn net.Conn) ([]byte, error) {
	conn.SetReadDeadline(time.Now().Add(HandshakeTimeout))
	defer conn.SetReadDeadline(time.Time{})

	// Read type byte
	typeBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, typeBuf); err != nil {
		return nil, fmt.Errorf("read handshake type: %w", err)
	}

	mt := protocol.MorphType(typeBuf[0])
	if mt != protocol.MorphTLSClientHello {
		return nil, fmt.Errorf("expected TLSClientHello handshake, got %s", mt)
	}

	// Read length (2 bytes)
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return nil, fmt.Errorf("read handshake length: %w", err)
	}
	packetLen := binary.BigEndian.Uint16(lenBuf)

	if packetLen > MaxPacketSize {
		return nil, fmt.Errorf("handshake packet too large: %d", packetLen)
	}

	// Read packet data
	packetData := make([]byte, packetLen)
	if _, err := io.ReadFull(conn, packetData); err != nil {
		return nil, fmt.Errorf("read handshake data: %w", err)
	}

	// Extract payload
	payload, err := protocol.ExtractPayload(mt, packetData)
	if err != nil {
		return nil, fmt.Errorf("extract handshake payload: %w", err)
	}

	// Decrypt with master PSK
	sessionKey, err := crypto.Open(s.psk, payload)
	if err != nil {
		return nil, fmt.Errorf("handshake decrypt: %w", err)
	}

	if len(sessionKey) != 32 {
		return nil, fmt.Errorf("invalid session key length: %d", len(sessionKey))
	}

	return sessionKey, nil
}

func (s *Server) readFrame(conn net.Conn, sched *morph.Schedule) (protocol.MorphType, []byte, error) {
	// Read type byte
	typeBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, typeBuf); err != nil {
		return 0, nil, err
	}

	mt := protocol.MorphType(typeBuf[0])

	// Read length (2 bytes)
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return mt, nil, err
	}
	packetLen := binary.BigEndian.Uint16(lenBuf)

	if packetLen > MaxPacketSize {
		return mt, nil, fmt.Errorf("packet too large: %d", packetLen)
	}

	packetData := make([]byte, packetLen)
	if _, err := io.ReadFull(conn, packetData); err != nil {
		return mt, nil, err
	}

	return mt, packetData, nil
}

func (s *Server) proxyTargetToClient(target net.Conn, streamID uint32, client net.Conn, sched *morph.Schedule, key []byte) {
	defer target.Close()

	buf := make([]byte, MaxPayloadSize-FrameHeaderSize)
	for {
		target.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := target.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.Printf("[server] read from target stream %d: %v", streamID, err)
			}
			break
		}

		// Build frame
		frame := make([]byte, FrameHeaderSize+n)
		binary.BigEndian.PutUint32(frame[0:4], streamID)
		binary.BigEndian.PutUint16(frame[4:6], uint16(n))
		copy(frame[FrameHeaderSize:], buf[:n])

		// Encrypt
		sealed, err := crypto.Seal(key, frame)
		if err != nil {
			log.Printf("[server] seal: %v", err)
			break
		}

		// Try morph types until one fits
		var pkt *protocol.Packet
		var mt protocol.MorphType
		maxTries := int(protocol.MorphCount) * 2
		for tries := 0; tries < maxTries; tries++ {
			mt = sched.Next()
			pkt, err = protocol.BuildPacket(mt, sealed)
			if err == nil {
				break
			}
		}
		if pkt == nil {
			log.Printf("[server] no morph type fits payload of %d bytes", len(sealed))
			break
		}

		// Send: [type:1][len:2][data]
		wire := make([]byte, 3+len(pkt.Raw))
		wire[0] = byte(pkt.Type)
		binary.BigEndian.PutUint16(wire[1:3], uint16(len(pkt.Raw)))
		copy(wire[3:], pkt.Raw)

		client.SetWriteDeadline(time.Now().Add(30 * time.Second))
		if _, err := client.Write(wire); err != nil {
			log.Printf("[server] write to client: %v", err)
			break
		}
	}
}

// Client implements the Mirage tunnel client (SOCKS5 proxy).
type Client struct {
	serverAddr string
	psk        []byte
	socksAddr  string
}

// NewClient creates a new Mirage client.
func NewClient(serverAddr, socksAddr string, psk []byte) *Client {
	return &Client{
		serverAddr: serverAddr,
		psk:        psk,
		socksAddr:  socksAddr,
	}
}

// Run starts the SOCKS5 proxy and blocks until an error occurs.
func (c *Client) Run() error {
	listener, err := net.Listen("tcp", c.socksAddr)
	if err != nil {
		return fmt.Errorf("socks listen: %w", err)
	}
	defer listener.Close()

	log.Printf("[client] SOCKS5 proxy listening on %s", c.socksAddr)
	log.Printf("[client] tunneling to server %s", c.serverAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("[client] accept error: %v", err)
			continue
		}
		go c.handleSocks(conn)
	}
}

func (c *Client) handleSocks(local net.Conn) {
	defer local.Close()

	// ── SOCKS5 handshake ──
	// Read: [VER:1][NMETHODS:1][METHODS:NMETHODS]
	local.SetReadDeadline(time.Now().Add(10 * time.Second))
	header := make([]byte, 2)
	if _, err := io.ReadFull(local, header); err != nil {
		log.Printf("[client] socks handshake read: %v", err)
		return
	}
	if header[0] != 0x05 {
		log.Printf("[client] not SOCKS5: ver=%d", header[0])
		return
	}
	nmethods := int(header[1])
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(local, methods); err != nil {
		log.Printf("[client] socks methods read: %v", err)
		return
	}
	// Respond: no auth required
	if _, err := local.Write([]byte{0x05, 0x00}); err != nil {
		log.Printf("[client] socks handshake write: %v", err)
		return
	}

	// ── SOCKS5 request ──
	// Read: [VER:1][CMD:1][RSV:1][ATYP:1][DST...]
	reqHeader := make([]byte, 4)
	if _, err := io.ReadFull(local, reqHeader); err != nil {
		log.Printf("[client] socks request read: %v", err)
		return
	}
	if reqHeader[0] != 0x05 {
		log.Printf("[client] bad socks ver in request: %d", reqHeader[0])
		return
	}
	cmd := reqHeader[1]
	if cmd != 0x01 { // CONNECT only
		log.Printf("[client] unsupported SOCKS5 command: %d", cmd)
		local.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // CMD not supported
		return
	}

	var targetAddr string
	atyp := reqHeader[3]
	switch atyp {
	case 0x01: // IPv4
		addr := make([]byte, 4)
		if _, err := io.ReadFull(local, addr); err != nil {
			log.Printf("[client] socks ipv4 read: %v", err)
			return
		}
		port := make([]byte, 2)
		if _, err := io.ReadFull(local, port); err != nil {
			log.Printf("[client] socks port read: %v", err)
			return
		}
		targetAddr = fmt.Sprintf("%d.%d.%d.%d:%d", addr[0], addr[1], addr[2], addr[3],
			binary.BigEndian.Uint16(port))
	case 0x03: // Domain name
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(local, lenBuf); err != nil {
			log.Printf("[client] socks domain len read: %v", err)
			return
		}
		domain := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(local, domain); err != nil {
			log.Printf("[client] socks domain read: %v", err)
			return
		}
		port := make([]byte, 2)
		if _, err := io.ReadFull(local, port); err != nil {
			log.Printf("[client] socks port read: %v", err)
			return
		}
		targetAddr = fmt.Sprintf("%s:%d", string(domain), binary.BigEndian.Uint16(port))
	case 0x04: // IPV6
		addr := make([]byte, 16)
		if _, err := io.ReadFull(local, addr); err != nil {
			log.Printf("[client] socks ipv6 read: %v", err)
			return
		}
		port := make([]byte, 2)
		if _, err := io.ReadFull(local, port); err != nil {
			log.Printf("[client] socks port read: %v", err)
			return
		}
		targetAddr = fmt.Sprintf("[%s]:%d", net.IP(addr).String(), binary.BigEndian.Uint16(port))
	default:
		log.Printf("[client] unsupported SOCKS5 ATYP: %d", atyp)
		local.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	local.SetDeadline(time.Time{})

	log.Printf("[client] new proxy request to %s", targetAddr)

	// Connect to Mirage server
	server, err := net.DialTimeout("tcp", c.serverAddr, 10*time.Second)
	if err != nil {
		log.Printf("[client] connect server: %v", err)
		// Send SOCKS5 error
		local.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer server.Close()

	// Generate session key
	sessionKey, err := crypto.GeneratePSK()
	if err != nil {
		log.Printf("[client] generate session key: %v", err)
		return
	}

	// Send handshake: encrypt session key with master PSK, wrap in TLSClientHello morph
	sealedKey, err := crypto.Seal(c.psk, sessionKey)
	if err != nil {
		log.Printf("[client] seal session key: %v", err)
		return
	}

	pkt, err := protocol.BuildPacket(protocol.MorphTLSClientHello, sealedKey)
	if err != nil {
		log.Printf("[client] build handshake: %v", err)
		return
	}

	// Send: [type:1][len:2][data]
	wire := make([]byte, 3+len(pkt.Raw))
	wire[0] = byte(pkt.Type)
	binary.BigEndian.PutUint16(wire[1:3], uint16(len(pkt.Raw)))
	copy(wire[3:], pkt.Raw)

	server.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := server.Write(wire); err != nil {
		log.Printf("[client] send handshake: %v", err)
		return
	}

	// Create per-session morph schedule (must match server)
	sched := morph.NewSchedule(sessionKey)

	// Assign stream ID
	streamID := uint32(time.Now().UnixNano() & 0xFFFFFFFF)

	// Send target address as first frame
	targetFrame := make([]byte, 2+len(targetAddr))
	binary.BigEndian.PutUint16(targetFrame[0:2], uint16(len(targetAddr)))
	copy(targetFrame[2:], targetAddr)

	if err := c.sendFrame(server, sched, sessionKey, streamID, targetFrame); err != nil {
		log.Printf("[client] send target frame: %v", err)
		return
	}

	// Send SOCKS5 success response to local app
	local.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	// Bidirectional relay
	var wg sync.WaitGroup
	wg.Add(2)

	// Local → Server
	go func() {
		defer wg.Done()
		buf := make([]byte, MaxPayloadSize-FrameHeaderSize)
		for {
			local.SetReadDeadline(time.Now().Add(30 * time.Second))
			n, err := local.Read(buf)
			if err != nil {
				return
			}
			if err := c.sendFrame(server, sched, sessionKey, streamID, buf[:n]); err != nil {
				log.Printf("[client] send data frame: %v", err)
				return
			}
		}
	}()

	// Server → Local
	go func() {
		defer wg.Done()
		for {
			mt, data, err := c.readFrame(server)
			if err != nil {
				return
			}

			_ = sched.Next() // advance schedule (sender may have skipped types)
			// Use the type from the wire directly

			payload, err := protocol.ExtractPayload(mt, data)
			if err != nil {
				log.Printf("[client] extract payload: %v", err)
				continue
			}

			plaintext, err := crypto.Open(sessionKey, payload)
			if err != nil {
				log.Printf("[client] decrypt: %v", err)
				continue
			}

			if len(plaintext) < FrameHeaderSize {
				continue
			}
			dataLen := binary.BigEndian.Uint16(plaintext[4:6])
			frameData := plaintext[FrameHeaderSize:]

			if int(dataLen) != len(frameData) {
				continue
			}

			local.SetWriteDeadline(time.Now().Add(30 * time.Second))
			if _, err := local.Write(frameData); err != nil {
				return
			}
		}
	}()

	wg.Wait()
}

func (c *Client) sendFrame(conn net.Conn, sched *morph.Schedule, key []byte, streamID uint32, data []byte) error {
	// Build frame
	frame := make([]byte, FrameHeaderSize+len(data))
	binary.BigEndian.PutUint32(frame[0:4], streamID)
	binary.BigEndian.PutUint16(frame[4:6], uint16(len(data)))
	copy(frame[FrameHeaderSize:], data)

	// Encrypt
	sealed, err := crypto.Seal(key, frame)
	if err != nil {
		return fmt.Errorf("seal: %w", err)
	}

	// Try morph types until one fits the payload
	var pkt *protocol.Packet
	var mt protocol.MorphType
	maxTries := int(protocol.MorphCount) * 2
	for tries := 0; tries < maxTries; tries++ {
		mt = sched.Next()
		pkt, err = protocol.BuildPacket(mt, sealed)
		if err == nil {
			break
		}
		// Payload too large for this morph type — skip and try next
	}
	if pkt == nil {
		return fmt.Errorf("no morph type fits payload of %d bytes after %d tries", len(sealed), maxTries)
	}

	// Send: [type:1][len:2][data]
	wire := make([]byte, 3+len(pkt.Raw))
	wire[0] = byte(pkt.Type)
	binary.BigEndian.PutUint16(wire[1:3], uint16(len(pkt.Raw)))
	copy(wire[3:], pkt.Raw)

	conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	if _, err := conn.Write(wire); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	return nil
}

func (c *Client) readFrame(conn net.Conn) (protocol.MorphType, []byte, error) {
	typeBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, typeBuf); err != nil {
		return 0, nil, err
	}

	mt := protocol.MorphType(typeBuf[0])

	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return mt, nil, err
	}
	packetLen := binary.BigEndian.Uint16(lenBuf)

	if packetLen > MaxPacketSize {
		return mt, nil, fmt.Errorf("packet too large: %d", packetLen)
	}

	packetData := make([]byte, packetLen)
	if _, err := io.ReadFull(conn, packetData); err != nil {
		return mt, nil, err
	}

	return mt, packetData, nil
}