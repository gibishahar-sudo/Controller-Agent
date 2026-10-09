package main

import (
	"testing"

	"rmm/internal/protocol"
)

// a.send on a session without a direct connection must fail LOUDLY with
// "no connection" (v1.46.93: the push loop published through this on
// MQTT-only agents, mistook the instant failure for a dead peer, and
// starved the stream; the fix routes push through the owning session's
// send func instead — this pins the contract it routes around).
func TestSendNilDirectConn(t *testing.T) {
	a := &agent{}
	if err := a.send(protocol.Message{}); err == nil || err.Error() != "no connection" {
		t.Fatalf("nil direct send = %v, want 'no connection'", err)
	}
}
