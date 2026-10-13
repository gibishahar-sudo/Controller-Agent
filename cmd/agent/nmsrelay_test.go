package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"rmm/internal/protocol"
)

var errTestSend = errors.New("send failed")

func TestNMSReportTick(t *testing.T) {
	if nmsReportTick([]byte(`{"prober":"h","tick":41}`)) != 41 {
		t.Fatal("tick must parse")
	}
	if nmsReportTick([]byte(`{"prober":"h"}`)) != 0 {
		t.Fatal("missing tick must be 0")
	}
	if nmsReportTick([]byte(`not json`)) != 0 {
		t.Fatal("garbage must be 0")
	}
}

// The ferry ships strictly-newer spools once; failures stay unrecorded.
func TestForwardNMSReport(t *testing.T) {
	dir := t.TempDir()
	oldPath := nmsSpoolPath
	nmsSpoolPath = func() string { return filepath.Join(dir, "nms-report.json") }
	t.Cleanup(func() { nmsSpoolPath = oldPath })
	lastNMSFwdTick.Store(0)
	t.Cleanup(func() { lastNMSFwdTick.Store(0) })

	var sent []protocol.Message
	okSend := func(m protocol.Message) error { sent = append(sent, m); return nil }

	forwardNMSReport(okSend) // absent file: silent
	if len(sent) != 0 {
		t.Fatal("absent spool must not send")
	}
	mustWrite := func(body string) {
		t.Helper()
		if err := os.WriteFile(nmsSpoolPath(), []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite(`{"prober":"h","tick":3}`)
	forwardNMSReport(okSend)
	if len(sent) != 1 || sent[0].Type != protocol.TypeHealth {
		t.Fatalf("fresh spool must send once as health, got %v", sent)
	}
	forwardNMSReport(okSend) // same tick: no replay
	if len(sent) != 1 {
		t.Fatal("same tick must not resend")
	}
	mustWrite(`oops`)
	forwardNMSReport(okSend) // unparsable: silent
	if len(sent) != 1 {
		t.Fatal("garbage spool must not send")
	}
	mustWrite(`{"prober":"h","tick":4}`)
	forwardNMSReport(func(m protocol.Message) error { return errTestSend })
	if len(sent) != 1 || lastNMSFwdTick.Load() != 3 {
		t.Fatal("failed send must leave the tick unrecorded for retry")
	}
	forwardNMSReport(okSend)
	if len(sent) != 2 || lastNMSFwdTick.Load() != 4 {
		t.Fatal("retry after failure must send and record")
	}
}
