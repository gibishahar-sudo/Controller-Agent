//go:build windows

package commands

import (
	"encoding/csv"
	"os/user"
	"strings"
	"sync"
	"time"
)

// NMSPriv describes the identity and power of the running process: WHO it
// is, whether the token is elevated, which integrity it runs at, and
// whether it holds Administrators membership. The NMS reports this about
// itself (nms-status + every report) so privilege problems are facts on
// the dashboard, not guesses.
//
// NOTE: this process never self-elevates — elevation arrives at install
// time (UAC), the task (HighestAvailable), or the SYSTEM service. The
// sample-style runas elevation is interactive (password prompt on a
// visible console) and has no place in a background monitor. Detection,
// not elevation, is this file's job. Implemented by parsing hidden
// `whoami /groups` output (no unsafe pointer games — the repo gate runs
// vet -unsafeptr=false).
type NMSPriv struct {
	User      string `json:"user"`
	Elevated  bool   `json:"elevated"`
	Integrity string `json:"integrity"`
	IsAdmin   bool   `json:"is_admin"`
	Detail    string `json:"detail,omitempty"`
}

var privCacheMu sync.Mutex
var privCacheAt time.Time
var privCacheVal NMSPriv

// CurrentNMSPriv inspects this process (60s cache: whoami spawns). Never
// fails — unreadable attributes read false/unknown with a Detail note.
func CurrentNMSPriv() NMSPriv {
	privCacheMu.Lock()
	defer privCacheMu.Unlock()
	if !privCacheAt.IsZero() && time.Since(privCacheAt) < time.Minute {
		return privCacheVal
	}
	p := queryNMSPriv()
	privCacheAt = time.Now()
	privCacheVal = p
	return p
}

func queryNMSPriv() NMSPriv {
	p := NMSPriv{Integrity: "unknown"}
	if u, err := user.Current(); err == nil {
		p.User = u.Username
	}
	out, err := runWithTimeout(10*time.Second, "whoami", "/groups", "/fo", "csv")
	if err != nil {
		p.Detail = "whoami unavailable: " + privShortErr(err)
		return p
	}
	p.Elevated, p.Integrity, p.IsAdmin = parseWhoamiGroups(string(out))
	if !p.Elevated {
		p.Detail = appendPrivDetail(p.Detail, "token not elevated (install/task must grant admin)")
	}
	if !p.IsAdmin {
		p.Detail = appendPrivDetail(p.Detail, "no enabled Administrators membership")
	}
	return p
}

func appendPrivDetail(d, s string) string {
	if d == "" {
		return s
	}
	return d + "; " + s
}

func privShortErr(err error) string {
	s := strings.TrimSpace(err.Error())
	if len(s) > 120 {
		s = s[:120] + "..."
	}
	return s
}

// parseWhoamiGroups reads `whoami /groups /fo csv` rows. Integrity comes
// from the S-1-16-* mandatory-label row; admin from S-1-5-32-544 carrying
// Enabled (a non-elevated admin shows it deny-only). Pure, tested.
func parseWhoamiGroups(csvText string) (elevated bool, integrity string, isAdmin bool) {
	integrity = "unknown"
	r := csv.NewReader(strings.NewReader(csvText))
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil || len(rows) < 2 {
		return false, integrity, false
	}
	for _, row := range rows[1:] {
		if len(row) < 4 {
			continue
		}
		name, sid, attrs := strings.TrimSpace(row[0]), strings.TrimSpace(row[2]), row[3]
		_ = name
		switch {
		case strings.HasPrefix(sid, "S-1-16-"):
			integrity = integrityFromLabel(sid)
		case sid == "S-1-5-32-544":
			a := strings.ToLower(attrs)
			if strings.Contains(a, "enabled") && !strings.Contains(a, "deny") {
				isAdmin = true
				elevated = true
			}
		}
	}
	return elevated, integrity, isAdmin
}

// integrityFromLabel maps a mandatory-label SID to its level (pure, tested).
func integrityFromLabel(sid string) string {
	switch sid {
	case "S-1-16-4096":
		return "low"
	case "S-1-16-8192":
		return "medium"
	case "S-1-16-12288":
		return "high"
	case "S-1-16-16384":
		return "system"
	default:
		return "unknown(" + sid + ")"
	}
}
