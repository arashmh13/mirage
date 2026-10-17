// Package protocol defines the protocol morphing types and template generation
// for Mirage's polymorphic transport.
//
// Each protocol type defines a benign-looking byte pattern that the tunnel
// traffic will mimic. The actual encrypted tunnel data is embedded within
// these patterns at varying offsets, making each packet appear to be a
// different protocol to DPI systems.
package protocol

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// MorphType represents a protocol disguise.
type MorphType uint8

const (
	MorphTLSClientHello MorphType = iota
	MorphTLSServerHello
	MorphDNSQuery
	MorphDNSResponse
	MorphHTTPRequest
	MorphHTTPResponse
	MorphICMPEcho
	MorphSSHKex
	MorphQUICInitial
	MorphNTPRequest
	MorphCount // number of morph types
)

// String returns the human-readable name of the morph type.
func (m MorphType) String() string {
	switch m {
	case MorphTLSClientHello:
		return "TLSClientHello"
	case MorphTLSServerHello:
		return "TLSServerHello"
	case MorphDNSQuery:
		return "DNSQuery"
	case MorphDNSResponse:
		return "DNSResponse"
	case MorphHTTPRequest:
		return "HTTPRequest"
	case MorphHTTPResponse:
		return "HTTPResponse"
	case MorphICMPEcho:
		return "ICMPEcho"
	case MorphSSHKex:
		return "SSHKex"
	case MorphQUICInitial:
		return "QUICInitial"
	case MorphNTPRequest:
		return "NTPRequest"
	default:
		return fmt.Sprintf("Unknown(%d)", m)
	}
}

// Packet represents a morphed packet ready for transmission.
type Packet struct {
	// Type is the protocol this packet mimics
	Type MorphType
	// Raw bytes to send on the wire
	Raw []byte
	// Offset within Raw where the encrypted payload starts
	PayloadOffset int
	// Length of the encrypted payload within Raw
	PayloadLen int
}

// Template defines fixed and variable regions for a protocol disguise.
type Template struct {
	// Fixed prefix bytes (e.g., TLS record header, DNS header)
	Prefix []byte
	// Fixed suffix bytes (e.g., padding extensions)
	Suffix []byte
	// Length of random/variable region before payload
	PrePayloadVarLen int
	// Length of random/variable region after payload
	PostPayloadVarLen int
	// Total maximum packet size
	MaxSize int
}

// Templates for each protocol morph type.
// These are carefully crafted to look like real protocol messages
// while providing space for encrypted tunnel data.
var templates = map[MorphType]Template{
	MorphTLSClientHello: {
		// TLS 1.2 record header + handshake header + client version + random
		Prefix: []byte{
			0x16, 0x03, 0x01, // TLS record: handshake, TLS 1.0
			0x00, 0x00, // length (placeholder)
			0x01,       // handshake type: client_hello
			0x00, 0x00, 0x00, // length (placeholder)
			0x03, 0x03, // client version: TLS 1.2
			// 32 bytes of random follow (pre-payload var)
		},
		PrePayloadVarLen:  32, // random bytes
		PostPayloadVarLen: 0,
		Suffix: []byte{
			// Cipher suites (2 suites = 4 bytes) + compression (1) + extensions length
			0x00, 0x04, // 2 cipher suites
			0x13, 0x01, // TLS_AES_128_GCM_SHA256
			0x13, 0x02, // TLS_AES_256_GCM_SHA384
			0x01,       // 1 compression method
			0x00,       // null compression
			0x00, 0x00, // extensions length (placeholder)
		},
		MaxSize: 1500,
	},

	MorphTLSServerHello: {
		Prefix: []byte{
			0x16, 0x03, 0x03, // TLS record: handshake, TLS 1.2
			0x00, 0x00, // length (placeholder)
			0x02,       // handshake type: server_hello
			0x00, 0x00, 0x00, // length (placeholder)
			0x03, 0x03, // server version: TLS 1.2
		},
		PrePayloadVarLen:  32, // server random
		PostPayloadVarLen: 0,
		Suffix: []byte{
			0x13, 0x01, // cipher suite: TLS_AES_128_GCM_SHA256
			0x00,       // null compression
			0x00, 0x00, // extensions length (placeholder)
		},
		MaxSize: 1500,
	},

	MorphDNSQuery: {
		Prefix: []byte{
			0x00, 0x00, // transaction ID (placeholder)
			0x01, 0x00, // flags: standard query
			0x00, 0x01, // questions: 1
			0x00, 0x00, // answer RRs: 0
			0x00, 0x00, // authority RRs: 0
			0x00, 0x00, // additional RRs: 0
		},
		PrePayloadVarLen:  0,
		PostPayloadVarLen: 0,
		Suffix: []byte{
			0x00, 0x01, // query type: A
			0x00, 0x01, // query class: IN
		},
		MaxSize: 512,
	},

	MorphDNSResponse: {
		Prefix: []byte{
			0x00, 0x00, // transaction ID (placeholder)
			0x81, 0x80, // flags: standard response, no error
			0x00, 0x01, // questions: 1
			0x00, 0x01, // answer RRs: 1
			0x00, 0x00, // authority RRs: 0
			0x00, 0x00, // additional RRs: 0
		},
		PrePayloadVarLen:  0,
		PostPayloadVarLen: 0,
		Suffix: []byte{
			// Answer section
			0xc0, 0x0c, // name pointer
			0x00, 0x01, // type: A
			0x00, 0x01, // class: IN
			0x00, 0x00, 0x00, 0x3c, // TTL: 60
			0x00, 0x04, // data length: 4
			// 4 bytes of IP address follow
		},
		MaxSize: 512,
	},

	MorphHTTPRequest: {
		Prefix: []byte("GET /"),
		PrePayloadVarLen:  8, // random path segment
		PostPayloadVarLen: 0,
		Suffix: []byte(" HTTP/1.1\r\n" +
			"Host: cdnjs.cloudflare.com\r\n" +
			"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n" +
			"Accept: */*\r\n" +
			"Accept-Language: en-US,en;q=0.9\r\n" +
			"Accept-Encoding: gzip, deflate, br\r\n" +
			"Connection: keep-alive\r\n" +
			"\r\n"),
		MaxSize: 1500,
	},

	MorphHTTPResponse: {
		Prefix: []byte("HTTP/1.1 200 OK\r\n" +
			"Content-Type: application/octet-stream\r\n" +
			"Content-Length: "),
		PrePayloadVarLen:  0,
		PostPayloadVarLen: 0,
		Suffix: []byte("\r\n" +
			"Cache-Control: no-cache\r\n" +
			"Server: cloudflare\r\n" +
			"\r\n"),
		MaxSize: 1500,
	},

	MorphICMPEcho: {
		Prefix: []byte{
			0x08,             // type: echo request
			0x00,             // code: 0
			0x00, 0x00,       // checksum (placeholder)
			0x00, 0x00,       // identifier
			0x00, 0x00,       // sequence number
		},
		PrePayloadVarLen:  0,
		PostPayloadVarLen: 0,
		Suffix:            nil,
		MaxSize:           1500,
	},

	MorphSSHKex: {
		Prefix: []byte{
			'S', 'S', 'H', '-', '2', '.', '0', '-',
		},
		PrePayloadVarLen:  8, // random version suffix
		PostPayloadVarLen: 0,
		Suffix: []byte{
			'\r', '\n',
			0x00, 0x00, 0x00, 0x00, // packet length (placeholder)
			0x00,                   // padding length
			0x14,                   // SSH_MSG_KEXECDH_INIT
		},
		MaxSize: 1500,
	},

	MorphQUICInitial: {
		Prefix: []byte{
			0xc0,       // Long header, initial packet type
			0x00, 0x00, 0x00, 0x01, // QUIC version 1
			0x00, // DCID length
			0x00, // SCID length
		},
		PrePayloadVarLen:  8, // random connection IDs
		PostPayloadVarLen: 0,
		Suffix: []byte{
			0x00, // token length
		},
		MaxSize: 1200,
	},

	MorphNTPRequest: {
		Prefix: []byte{
			0x23,       // LI(0) VN(4) Mode(3) = client
			0x00,       // stratum
			0x08,       // poll interval
			0xec,       // precision
			0x00, 0x00, 0x00, 0x00, // root delay
			0x00, 0x00, 0x00, 0x00, // root dispersion
			0x00, 0x00, 0x00, 0x00, // reference ID
		},
		PrePayloadVarLen:  32, // reference timestamp + originate timestamp
		PostPayloadVarLen: 0,
		Suffix:            nil,
		MaxSize:           48,
	},
}

// GetTemplate returns the template for a given morph type.
func GetTemplate(mt MorphType) (Template, bool) {
	t, ok := templates[mt]
	return t, ok
}

// randomBytes generates cryptographically random bytes.
func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}

// randomAlphaNum generates random alphanumeric bytes.
func randomAlphaNum(n int) ([]byte, error) {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return nil, err
		}
		b[i] = charset[idx.Int64()]
	}
	return b, nil
}

// BuildPacket constructs a morphed packet of the given type containing the
// encrypted payload. The payload is embedded at an offset determined by
// the template structure.
func BuildPacket(mt MorphType, payload []byte) (*Packet, error) {
	tmpl, ok := templates[mt]
	if !ok {
		return nil, fmt.Errorf("unknown morph type: %d", mt)
	}

	// Calculate total size
	totalSize := len(tmpl.Prefix) + tmpl.PrePayloadVarLen + len(payload) + tmpl.PostPayloadVarLen + len(tmpl.Suffix)
	if totalSize > tmpl.MaxSize && tmpl.MaxSize > 0 {
		return nil, fmt.Errorf("payload too large: %d bytes exceeds max %d for %s", len(payload), tmpl.MaxSize, mt)
	}

	// Build the packet
	raw := make([]byte, 0, totalSize)
	raw = append(raw, tmpl.Prefix...)

	// Pre-payload variable region
	if tmpl.PrePayloadVarLen > 0 {
		rnd, err := randomBytes(tmpl.PrePayloadVarLen)
		if err != nil {
			return nil, err
		}
		raw = append(raw, rnd...)
	}

	// Payload position
	payloadOffset := len(raw)
	raw = append(raw, payload...)
	payloadLen := len(payload)

	// Post-payload variable region
	if tmpl.PostPayloadVarLen > 0 {
		rnd, err := randomBytes(tmpl.PostPayloadVarLen)
		if err != nil {
			return nil, err
		}
		raw = append(raw, rnd...)
	}

	// Suffix
	raw = append(raw, tmpl.Suffix...)

	// Post-build fixes for specific protocols
	switch mt {
	case MorphDNSQuery, MorphDNSResponse:
			// Fix DNS transaction ID
		if len(raw) >= 2 {
			txID, _ := randomBytes(2)
			raw[0] = txID[0]
			raw[1] = txID[1]
		}
		// Fix DNS question name: embed random-looking domain
		// The payload area serves as the QNAME
	case MorphHTTPRequest:
			// Replace the path random area with random-looking path
		pathStart := len(tmpl.Prefix)
		if tmpl.PrePayloadVarLen > 0 {
			alpha, err := randomAlphaNum(tmpl.PrePayloadVarLen)
			if err != nil {
				return nil, err
			}
			copy(raw[pathStart:pathStart+tmpl.PrePayloadVarLen], alpha)
		}
	}

	return &Packet{
		Type:         mt,
		Raw:          raw,
		PayloadOffset: payloadOffset,
		PayloadLen:    payloadLen,
	}, nil
}

// ExtractPayload extracts the encrypted payload from a morphed packet.
func ExtractPayload(mt MorphType, raw []byte) ([]byte, error) {
	tmpl, ok := templates[mt]
	if !ok {
		return nil, fmt.Errorf("unknown morph type: %d", mt)
	}

	payloadOffset := len(tmpl.Prefix) + tmpl.PrePayloadVarLen
	payloadLen := len(raw) - payloadOffset - tmpl.PostPayloadVarLen - len(tmpl.Suffix)

	if payloadOffset < 0 || payloadLen <= 0 || payloadOffset+payloadLen > len(raw) {
		return nil, fmt.Errorf("packet too short for %s: len=%d need at least %d", mt, len(raw), payloadOffset+1)
	}

	return raw[payloadOffset : payloadOffset+payloadLen], nil
}

// AllTypes returns all available morph types.
func AllTypes() []MorphType {
	types := make([]MorphType, 0, MorphCount)
	for i := MorphType(0); i < MorphCount; i++ {
		if _, ok := templates[i]; ok {
			types = append(types, i)
		}
	}
	return types
}

// MaxPayloadSize returns the maximum payload size that can fit in a packet
// of the given morph type.
func MaxPayloadSize(mt MorphType) int {
	tmpl, ok := templates[mt]
	if !ok {
		return 0
	}
	return tmpl.MaxSize - len(tmpl.Prefix) - tmpl.PrePayloadVarLen - tmpl.PostPayloadVarLen - len(tmpl.Suffix)
}