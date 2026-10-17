// Package morph implements the deterministic protocol morphing schedule.
//
// This is the core innovation of Mirage: a shared-secret-derived schedule
// that determines which protocol disguise each packet uses. The DPI sees
// a stream of unrelated protocol fragments (TLS, DNS, HTTP, ICMP, etc.)
// and cannot classify the flow. Both endpoints derive the same schedule
// deterministically from a shared secret, so no coordination is needed.
package morph

import (
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"sync"
	"time"

	"github.com/arashmh13/mirage/pkg/protocol"
)

// Schedule generates a deterministic sequence of protocol morph types
// that both client and server derive independently from a shared secret.
type Schedule struct {
	mu       sync.Mutex
	key      []byte
	hasher   hash.Hash
	counter  uint64
	// Pre-computed pool of types for fast lookups
	pool     []protocol.MorphType
	poolIdx  int
	poolSize int
}

// NewSchedule creates a new morph schedule from a shared secret.
// The schedule refreshes periodically to prevent pattern analysis.
func NewSchedule(key []byte) *Schedule {
	return &Schedule{
		key:      key,
		hasher:   sha256.New(),
		poolSize: 256, // pre-computed pool size
	}
}

// computeType deterministically derives the next morph type from the key + counter.
func (s *Schedule) computeType(counter uint64) protocol.MorphType {
	s.hasher.Reset()
	s.hasher.Write(s.key)
	binary.Write(s.hasher, binary.BigEndian, counter)
	hash := s.hasher.Sum(nil)

	// Use first 4 bytes to select from available types
	// Weight some types higher to match real-world protocol distribution
	val := binary.BigEndian.Uint32(hash[:4])
	allTypes := protocol.AllTypes()
	count := uint32(len(allTypes))

	// Realistic protocol distribution weights:
	// TLS (ClientHello + ServerHello) = 40%
	// DNS (Query + Response) = 20%
	// HTTP (Request + Response) = 20%
	// Others (ICMP, SSH, QUIC, NTP) = 20%
	weights := make([]uint32, count)
	for i, t := range allTypes {
		switch t {
		case protocol.MorphTLSClientHello, protocol.MorphTLSServerHello:
			weights[i] = 20 // 40% total for TLS
		case protocol.MorphDNSQuery, protocol.MorphDNSResponse:
			weights[i] = 10 // 20% total for DNS
		case protocol.MorphHTTPRequest, protocol.MorphHTTPResponse:
			weights[i] = 10 // 20% total for HTTP
		default:
			weights[i] = 5 // 20% total for others (ICMP, SSH, QUIC, NTP)
		}
	}

	// Build cumulative distribution
	cumulative := make([]uint32, count)
	var sum uint32
	for i, w := range weights {
		sum += w
		cumulative[i] = sum
	}

	// Select based on weighted random
	val = val % sum
	for i, c := range cumulative {
		if val < c {
			return allTypes[i]
		}
	}
	return allTypes[count-1]
}

// fillPool replenishes the pre-computed type pool.
func (s *Schedule) fillPool() {
	s.pool = make([]protocol.MorphType, s.poolSize)
	for i := 0; i < s.poolSize; i++ {
		s.pool[i] = s.computeType(s.counter)
		s.counter++
	}
	s.poolIdx = 0
}

// Next returns the next protocol morph type in the schedule.
// Thread-safe and fast (O(1) after initial pool fill).
func (s *Schedule) Next() protocol.MorphType {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.poolIdx >= len(s.pool) || s.pool == nil {
		s.fillPool()
	}

	t := s.pool[s.poolIdx]
	s.poolIdx++
	return t
}

// NextN returns the next n morph types.
func (s *Schedule) NextN(n int) []protocol.MorphType {
	types := make([]protocol.MorphType, n)
	for i := 0; i < n; i++ {
		types[i] = s.Next()
	}
	return types
}

// Advance skips n morph types (for synchronization).
func (s *Schedule) Advance(n int) {
	for i := 0; i < n; i++ {
		s.Next()
	}
}

// EpochSchedule wraps a Schedule with time-based re-keying.
// The morph schedule changes every epoch (default: 30 seconds) to prevent
// long-term pattern analysis by DPI systems.
type EpochSchedule struct {
	mu          sync.Mutex
	masterKey   []byte
	epochDur    time.Duration
	currentEpoch int64
	schedule    *Schedule
}

// NewEpochSchedule creates a time-based morph schedule that rotates keys.
func NewEpochSchedule(masterKey []byte, epochDur time.Duration) *EpochSchedule {
	return &EpochSchedule{
		masterKey: masterKey,
		epochDur:  epochDur,
	}
}

// epochKey derives the key for a given epoch.
func (es *EpochSchedule) epochKey(epoch int64) []byte {
	h := sha256.New()
	h.Write(es.masterKey)
	binary.Write(h, binary.BigEndian, epoch)
	return h.Sum(nil)
}

// currentSchedule returns the schedule for the current epoch.
func (es *EpochSchedule) currentSchedule() *Schedule {
	epoch := time.Now().UnixNano() / int64(es.epochDur)
	if epoch != es.currentEpoch || es.schedule == nil {
		es.schedule = NewSchedule(es.epochKey(epoch))
		es.currentEpoch = epoch
	}
	return es.schedule
}

// Next returns the next morph type, re-keying if epoch changed.
func (es *EpochSchedule) Next() protocol.MorphType {
	es.mu.Lock()
	defer es.mu.Unlock()
	return es.currentSchedule().Next()
}

// NextN returns the next n morph types.
func (es *EpochSchedule) NextN(n int) []protocol.MorphType {
	es.mu.Lock()
	defer es.mu.Unlock()
	return es.currentSchedule().NextN(n)
}