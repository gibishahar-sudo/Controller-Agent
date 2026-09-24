package relay

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// ---- End-to-end payload encryption (AES-256-GCM) ----
//
// The MQTT relay crosses third-party servers, so payloads can carry a
// second encryption layer the brokers cannot read. Keys are per-agent
// data keys, wrapped once via the controller's RSA public key
// (see TypeKeyExchange); direct TLS connections skip this (already
// encrypted). Plaintext (Enc=false) stays accepted for old agents.

// GenDataKey makes a fresh 32-byte payload key.
func GenDataKey() ([32]byte, error) {
	var k [32]byte
	_, err := rand.Read(k[:])
	return k, err
}

// SealPayload encrypts plaintext for the wire: base64(nonce||ciphertext)
// wrapped as a JSON string for the Payload field.
func SealPayload(key [32]byte, plaintext []byte) (json.RawMessage, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	sealed := gcm.Seal(nonce, nonce, plaintext, nil)
	b, err := json.Marshal(base64.StdEncoding.EncodeToString(sealed))
	if err != nil {
		return nil, err
	}
	return json.RawMessage(b), nil
}

// SealRaw encrypts raw bytes for binary topics: nonce||ciphertext.
// Unlike SealPayload it skips base64/JSON (binary callers frame bytes
// directly; ~45% smaller than seal-after-base64 for media chunks).
func SealRaw(key [32]byte, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// OpenRaw reverses SealRaw.
func OpenRaw(key [32]byte, sealed []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	n := gcm.NonceSize()
	if len(sealed) < n {
		return nil, fmt.Errorf("sealed payload too short")
	}
	return gcm.Open(nil, sealed[:n], sealed[n:], nil)
}

// OpenPayload reverses SealPayload.
func OpenPayload(key [32]byte, payload json.RawMessage) ([]byte, error) {
	var b64 string
	if err := json.Unmarshal(payload, &b64); err != nil {
		return nil, fmt.Errorf("not a sealed payload")
	}
	sealed, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	n := gcm.NonceSize()
	if len(sealed) < n {
		return nil, fmt.Errorf("sealed payload too short")
	}
	return gcm.Open(nil, sealed[:n], sealed[n:], nil)
}

type Envelope struct {
	From    string          `json:"from"` // "controller" or "agent:<hostname>"
	To      string          `json:"to,omitempty"`
	ID      string          `json:"id,omitempty"`
	Payload json.RawMessage `json:"payload"`
	// Enc marks AES-256-GCM end-to-end payloads (brokers see ciphertext
	// only). Payload then holds a JSON string: base64(nonce||ciphertext).
	Enc     bool            `json:"enc,omitempty"`
	Time    int64           `json:"time"` // client millis (for display); NOT used for `since`
}

