package mqttrelay

import "testing"

// Regression test for the fleet-wide deaf-sub outage: paho only restores
// subscriptions across reconnects when ResumeSubs is set (CleanSession
// alone is not enough). Every dial path goes through baseOptions, so
// assert the invariants there.
func TestBaseOptionsReconnectInvariants(t *testing.T) {
	opts := baseOptions("ssl://broker.emqx.io:8883", "rmm-test-id", nil)
	if !opts.CleanSession {
		t.Fatal("CleanSession must stay true (no broker-side replay storms)")
	}
	if !opts.AutoReconnect {
		t.Fatal("AutoReconnect must stay true")
	}
	if !opts.ResumeSubs {
		t.Fatal("ResumeSubs must be true or reconnects silently drop subscriptions")
	}
	if opts.MaxReconnectInterval <= 0 {
		t.Fatal("MaxReconnectInterval must be positive")
	}
	// NOTE: the default OnConnect reconnect-logger can't be asserted:
	// paho keeps its handlers unexported. Its presence is covered by
	// inspection (baseOptions sets it whenever onConnect == nil).
}
