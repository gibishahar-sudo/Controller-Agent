package mqttrelay

import (
	"os"
	"testing"
)

// Live test: every configured broker must complete a VERIFIED TLS
// handshake (no InsecureSkipVerify anywhere in the package). Needs
// internet; set RMM_LIVE_TEST=1 to run.
func TestBrokersTLSVerified(t *testing.T) {
	if os.Getenv("RMM_LIVE_TEST") != "1" {
		t.Skip("set RMM_LIVE_TEST=1 for live broker checks")
	}
	for _, b := range Brokers {
		t.Run(b, func(t *testing.T) {
			c, err := dial(b, "rmm-tlstest-"+randHex(3), nil)
			if err != nil {
				t.Fatalf("verified TLS dial failed: %v", err)
			}
			defer c.Disconnect(250)
		})
	}
}
