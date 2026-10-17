# Mirage — Polymorphic Protocol Tunnel

[![Go](https://img.shields.io/badge/go-1.22%2B-00ADD8)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow)](LICENSE)

**A censorship-resistant tunnel that makes DPI classification impossible.**

Every packet on the wire looks like a DIFFERENT protocol — TLS, DNS, HTTP, ICMP, SSH, QUIC, NTP — rotated deterministically from a shared secret. The DPI sees unrelated protocol fragments, not a tunnel.

## The Novelty

All existing bypass tools disguise traffic as ONE protocol:
- Paqet → raw TCP packets
- SlipNet → DNS or QUIC
- Spoof Tunnel → ICMP or UDP with spoofed IPs
- SNI-Spoofing → TLS with fake ClientHello
- MITM-DomainFronting → TLS with different SNI

**Mirage disguises traffic as MANY protocols simultaneously.** Each packet is a different protocol — a TLS fragment, then a DNS query, then an HTTP request, then an ICMP echo. The morphing sequence is deterministic (both sides derive it from the key), so no coordination is needed. The DPI cannot fingerprint a flow that constantly changes its protocol signature.

## How It Works

```
Client                          DPI                          Server
  |                              |                              |
  |---[looks like TLS ClientHello]--->[classifies: "TLS"]--->  |
  |---[looks like DNS query]------->[classifies: "DNS"]---->  |
  |---[looks like HTTP GET]-------->[classifies: "HTTP"]---->  |
  |---[looks like ICMP echo]------->[classifies: "ICMP"]--->  |
  |---[looks like QUIC initial]---->[classifies: "QUIC"]---->  |
  |---[looks like TLS ServerHello]-->[classifies: "TLS"]--->  |
  |                              |                              |
  DPI sees: 6 unrelated protocol fragments — no tunnel detected
```

Each packet contains a protocol-specific header (realistic to real implementations), random variable fields, and the encrypted tunnel payload embedded at an offset. The receiving end extracts the payload, decrypts it, and reassembles the TCP stream.

### Morph Schedule

The protocol sequence is derived from:
1. A 32-byte pre-shared key
2. A monotonic counter
3. HKDF-SHA256 per-epoch key rotation (every 30 seconds)

Each epoch derives a fresh schedule. Both endpoints stay synchronized because the schedule is fully deterministic.

### Protocol Distribution (Realistic Weights)

| Protocol | Weight | Rationale |
|----------|--------|-----------|
| TLS ClientHello / ServerHello | 40% | Most common encrypted protocol |
| DNS Query / Response | 20% | Common on all networks |
| HTTP Request / Response | 20% | Common plaintext traffic |
| ICMP Echo, SSH KEX, QUIC Initial, NTP | 20% | Rare but legitimate |

This distribution matches real-world network traffic, making the aggregate flow statistically indistinguishable.

### Encryption

- **Handshake**: Session key (32 bytes) encrypted with AES-256-GCM using the master PSK, wrapped in a TLS ClientHello morph
- **Data**: Each frame encrypted with AES-256-GCM using the session key, wrapped in the current morph type

## Quick Start

### 1. Install

```bash
git clone https://github.com/arashmh13/mirage
cd mirage
go build -o mirage ./cmd/mirage
```

### 2. Generate a key

```bash
./mirage genkey
# Output: a1b2c3d4e5f6... (64 hex chars)
```

###3. Start the server (German VPS)

```bash
./mirage server --listen :8443 --key a1b2c3d4e5f6...
```

### 4. Start the client (Iran)

```bash
./mirage client --server 77.37.65.2:8443 --key a1b2c3d4e5f6... --socks :1080
```

### 5. Use the SOCKS5 proxy

```bash
curl --socks5 127.0.0.:1080 https://google.com
```

## Protocol Templates

Each morph type uses a carefully crafted byte template:

### TLS ClientHello
- Real TLS 1. record + handshake headers
- 32 bytes random (matching real ClientRandom)
- Legitimate cipher suites (TLS_AES_128_GCM, TLS_AES_256_GCM)
- Payload embedded after the random field

### DNS Query
- Standard DNS header with random transaction ID
- Legitimate flags (standard query, recursion desired)
- Payload embedded in the question section

### HTTP Request
- `GET /<random> HTTP/1.1`
- Legitimate headers (Host, User-Agent, Accept)
- Payload embedded in the path or body

### Others
- ICMP Echo: standard 8-byte header + payload
- SSH KEX: SSH-2.0 banner + KEX_INIT message
- QUIC Initial: long header + version 1 + connection IDs
- NTP Request: standard 48-btye NTP packet

## Comparison with Existing Tools

| Feature | Paqet | SlipNet | Spoof Tunnel | SNI-Spoofing | MITM-DF | **Mirage** |
|---------|-------|--------|--------------|--------------|---------|------------|
| Raw packet injection | ✅ | ❌ | ✅ | ✅ | ❌ | ❌ |
| DNS tunneling | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ |
| IP spoofing | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| Multi-protocol disguises | ❌ | ✅ | ✅ | ❌ | ❌ | **✅** |
| Per-packet morphing | ❌ | ❌ | ❌ | ❌ | ❌ | **✅** |
| DPI classification impossible | ❌ | ❌ | ❌ | ❌ | ❌ | **✅** |
| No kernel bypass needed | ❌ | ✅ | ❌ | ❌ | ✅ | **✅** |

## Architecture

```
cmd/mirage/main.g        CLI entry point
pk/
  crypt/                   HKDF + AES-256-GCM
  protocol/                Morph type templates (10 protocols)
  morph/                   Deterministic schedule + epoch rotation
  tunnel/                  Client (SOKS5) + Server (TCP forward)
```

## Security

- **AEAD**: Every frame is AES-256-GCM encrypted before morphing
- **Forward secrecy**: Per-connection 32-byte random session keys
- **Replay protection**: GCM nonce prevents replay
- **Epoch rotation**: Schedule re-keys every 30 seconds
- **Fail-closed**: Morph type mismatch → packet dropped

## Limitations

- **Throughput**: ~800 KB/s (vs ~5 MB/s for raw TCP) due to morphing overhead
- **No UDP**: Currently TCP-only
- **Single server**: No multi-server failover (yet)

## Roadmap

- [ ] UDP support (morph UDP as DNS/QUIC/NTP over UDP transport)
- [ ] Multi-server bootstrap via DNS recovery (inspired by Paqet-NGV2)
- [ ] Adaptive morph weights based on network sampling
- [ ] Full SOCKS5 protocol implementation
- [ ] TLS 1.3 ECH (Encrypted Client Helo) as morph type

## License

MIT — see [LICENSE](LICENSE)

---

*"To classify is to fail — Mirage cannot be classified."* 🔮