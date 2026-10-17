// Package crypto provides key derivation and AEAD encryption for Mirage.
// Uses HKDF-SHA256 for key derivation and AES-256-GCM for encryption.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
)

var (
	ErrTagMismatch  = errors.New("aead: authentication tag mismatch")
	ErrShortMessage = errors.New("aead: message too short")
)

// DeriveKeys derives separate encryption keys for each protocol layer
// from a master PSK. Returns a slice of keys, one per protocol type.
func DeriveKeys(psk []byte, numKeys int) [][]byte {
	keys := make([][]byte, numKeys)
	master := sha256.Sum256(psk)

	for i := 0; i < numKeys; i++ {
		info := make([]byte, 4)
		binary.BigEndian.PutUint32(info, uint32(i))
		reader := hkdf.New(sha256.New, master[:], nil, append([]byte("mirage-layer-"), info...))
		key := make([]byte, 32) // AES-256
		io.ReadFull(reader, key)
		keys[i] = key
	}
	return keys
}

// DeriveSessionKey derives a session-specific key for a morph schedule epoch.
func DeriveSessionKey(psk []byte, sessionID uint64) []byte {
	master := sha256.Sum256(psk)
	sid := make([]byte, 8)
	binary.BigEndian.PutUint64(sid, sessionID)
	reader := hkdf.New(sha256.New, master[:], nil, append([]byte("mirage-session-"), sid...))
	key := make([]byte, 32)
	io.ReadFull(reader, key)
	return key
}

// Seal encrypts and authenticates data using AES-256-GCM.
// Returns nonce + ciphertext + tag.
func Seal(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	// Prepend nonce
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	return append(nonce, ciphertext...), nil
}

// Open decrypts and authenticates data.
// Input format: nonce + ciphertext + tag.
func Open(key, sealed []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := aesgcm.NonceSize()
	if len(sealed) < nonceSize {
		return nil, ErrShortMessage
	}
	nonce := sealed[:nonceSize]
	ciphertext := sealed[nonceSize:]
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrTagMismatch
	}
	return plaintext, nil
}

// GeneratePSK generates a cryptographically random 32-byte pre-shared key.
func GeneratePSK() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}