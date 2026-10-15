package controller

import (
	"encoding/json"
	"testing"
	"time"
)

func TestParseHealthID(t *testing.T) {
	p, tick := parseHealthID(`{"prober":"Shahar-LT","tick":12}`)
	if p != "Shahar-LT" || tick != 12 {
		t.Fatalf("got %q,%d", p, tick)
	}
	if p, tick := parseHealthID(`nope`); p != "" || tick != 0 {
		t.Fatalf("garbage must empty, got %q,%d", p, tick)
	}
}

// Dedupe: same prober+tick stored once; newer ticks pass; tickless passes
// through (old shapes carry no clock).
func TestNoteHealthDeduped(t *testing.T) {
	s := &Server{}
	if !s.noteHealthDeduped("id1", `{"prober":"H","tick":5}`) {
		t.Fatal("first sighting must store")
	}
	if s.noteHealthDeduped("id1", `{"prober":"H","tick":5}`) {
		t.Fatal("replay must drop")
	}
	if s.noteHealthDeduped("id2", `{"prober":"H","tick":5}`) {
		t.Fatal("replay under another id must drop")
	}
	if !s.noteHealthDeduped("id1", `{"prober":"H","tick":6}`) {
		t.Fatal("newer tick must store")
	}
	if !s.noteHealthDeduped("id1", `{"prober":"H"}`) {
		t.Fatal("tickless must pass through")
	}
	s.nmsHealthMu.Lock()
	n := len(s.nmsHealth)
	s.nmsHealthMu.Unlock()
	if n != 1 {
		t.Fatalf("all writes key one id, have %d rows", n)
	}
}

// Attribution prefers a live direct NMS row for the prober.
func TestFindNMSAgent(t *testing.T) {
	s := &Server{agents: map[string]*AgentConn{
		"a1": {id: "a1", hostname: "Shahar-LT", role: ""},
		"a2": {id: "a2", hostname: "Shahar-LT", role: "nms"},
	}}
	if ac := s.findNMSAgent("shahar-lt"); ac == nil || ac.id != "a2" {
		t.Fatalf("must find the nms row case-insensitively, got %+v", ac)
	}
	if ac := s.findNMSAgent("nope"); ac != nil {
		t.Fatalf("unknown prober must miss, got %+v", ac)
	}
	if ac := s.findNMSAgent(""); ac != nil {
		t.Fatal("empty prober must miss")
	}
}

// Staleness: 3x interval + 2min grace; unparsable never stale on content.
func TestHealthReportStale(t *testing.T) {
	now := time.Now()
	mk := func(at time.Time, interval int) json.RawMessage {
		b, _ := json.Marshal(map[string]interface{}{
			"at":           at.UTC().Format(time.RFC3339),
			"interval_sec": interval,
		})
		return b
	}
	if healthReportStale(mk(now, 60), now) {
		t.Fatal("fresh 60s report must keep")
	}
	if !healthReportStale(mk(now.Add(-10*time.Minute), 60), now) {
		t.Fatal("10min-old 60s report must expire")
	}
	if healthReportStale(mk(now.Add(-10*time.Minute), 300), now) {
		t.Fatal("10min-old 300s report must keep (grace 17min)")
	}
	if !healthReportStale(mk(now.Add(-20*time.Minute), 300), now) {
		t.Fatal("20min-old 300s report must expire")
	}
	if healthReportStale(json.RawMessage("{"), now) {
		t.Fatal("unparsable report must not stale on content")
	}
}
