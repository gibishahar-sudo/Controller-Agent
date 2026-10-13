package main

import (
	"encoding/json"
	"os"
	"sync/atomic"

	"rmm/internal/commands"
	"rmm/internal/protocol"
)

// NMS relay ferry: the monitor (separate process, direct-TLS only) spools
// its latest report when its own link is down; the agent ferries fresh
// spools over whichever uplink IT holds (direct or MQTT relay). Replays
// (agent restarts re-send the same spool) are dropped controller-side by
// report tick, so at-most-once here is unnecessary — at-least-once is fine.

// nmsSpoolPath locates the spool file. Var so tests stay hermetic.
var nmsSpoolPath = commands.NMSReportPath

// lastNMSFwdTick is the newest spooled report tick already ferried (process
// memory only).
var lastNMSFwdTick atomic.Uint64

// nmsReportTick extracts the report tick (0 when unparsable).
func nmsReportTick(raw []byte) uint64 {
	var r struct {
		Tick uint64 `json:"tick"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return 0
	}
	return r.Tick
}

// forwardNMSReport ships the spooled monitor report if newer than anything
// ferried this process lifetime. Silent no-op when absent, stale, or
// unparsable; a send failure leaves the tick unrecorded for retry.
func forwardNMSReport(send func(protocol.Message) error) {
	raw, err := os.ReadFile(nmsSpoolPath())
	if err != nil || len(raw) == 0 {
		return
	}
	tick := nmsReportTick(raw)
	if tick == 0 || tick <= lastNMSFwdTick.Load() {
		return
	}
	if err := send(protocol.Message{Type: protocol.TypeHealth, Result: string(raw)}); err != nil {
		return
	}
	lastNMSFwdTick.Store(tick)
}
