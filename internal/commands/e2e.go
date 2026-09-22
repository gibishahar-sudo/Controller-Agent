package commands

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"sync/atomic"

	"rmm/internal/protocol"
	"rmm/internal/relay"
)

// Agent-side end-to-end state for relay transports (MQTT/ntfy). Direct TLS
// connections skip E2E (already encrypted). The data key is generated per
// connect, wrapped with the controller's RSA public key (from the shipped
// server.crt), and enabled only after an ack proving controller support —
// so new agents never blackhole against old controllers.

var (
	e2eKey     [32]byte
	e2eWrapped string
	e2eHave    atomic.Bool
	e2eReady   atomic.Bool
)

// E2EWrapped returns the cached RSA-wrapped key for (re)announces.
func E2EWrapped() (string, bool) {
	if !e2eHave.Load() || e2eWrapped == "" {
		return "", false
	}
	return e2eWrapped, true
}

// E2EInitControllerKey generates a fresh data key, stores it, and returns
// the RSA-OAEP-wrapped form for the keyxchg message. Empty CA (insecure
// mode) means no E2E.
func E2EInitControllerKey(caFile string) (string, error) {
	if caFile == "" {
		return "", fmt.Errorf("no ca file")
	}
	caData, err := os.ReadFile(caFile)
	if err != nil {
		return "", err
	}
	var pub *rsa.PublicKey
	for {
		var block *pem.Block
		block, caData = pem.Decode(caData)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		if p, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			pub = p
			break
		}
	}
	if pub == nil {
		return "", fmt.Errorf("no RSA public key in %s", caFile)
	}
	k, err := relay.GenDataKey()
	if err != nil {
		return "", err
	}
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, k[:], nil)
	if err != nil {
		return "", err
	}
	e2eKey = k
	e2eWrapped = base64.StdEncoding.EncodeToString(wrapped)
	e2eHave.Store(true)
	e2eReady.Store(false)
	return e2eWrapped, nil
}

// E2EEnable flips encryption on/off (on = controller acked E2E support).
func E2EEnable(on bool) { e2eReady.Store(on) }

// E2EActive reports whether outbound relay payloads are being sealed.
func E2EActive() bool { return e2eHave.Load() && e2eReady.Load() }

// E2ESeal converts a protocol message to a relay payload, sealed when active.
func E2ESeal(msg protocol.Message) (json.RawMessage, bool) {
	if !E2EActive() {
		b, _ := json.Marshal(msg)
		return b, false
	}
	b, err := json.Marshal(msg)
	if err != nil {
		bb, _ := json.Marshal(msg)
		return bb, false
	}
	sealed, err := relay.SealPayload(e2eKey, b)
	if err != nil {
		bb, _ := json.Marshal(msg)
		return bb, false
	}
	return sealed, true
}

// E2EOpen decrypts an inbound Enc payload. ok=false means drop the message.
func E2EOpen(payload json.RawMessage) ([]byte, bool) {
	if !e2eHave.Load() {
		return nil, false
	}
	plain, err := relay.OpenPayload(e2eKey, payload)
	if err != nil {
		return nil, false
	}
	return plain, true
}

// E2EEnvelope builds a relay envelope, sealed when active. Hellos,
// announces, pings and keyxchg itself must stay plaintext (callers opt in
// by using this helper only for data messages).
func E2EEnvelope(from, to string, msg protocol.Message, nowMillis int64) relay.Envelope {
	payload, enc := E2ESeal(msg)
	return relay.Envelope{From: from, To: to, Payload: payload, Enc: enc, Time: nowMillis}
}
