package ui

import (
	"bytes"
	"encoding/json"
	"image/png"
	"strconv"
	"strings"
	"testing"
)

// PWA gate: the installable shell (manifest, icons, worker, login links)
// must stay valid — browsers silently refuse installation otherwise,
// with zero diagnostic on the tablet.
func TestPWAManifest(t *testing.T) {
	b, err := FS.ReadFile("frontend/manifest.webmanifest")
	if err != nil {
		t.Fatalf("manifest missing from bundle: %v", err)
	}
	var m struct {
		Name            string `json:"name"`
		ShortName       string `json:"short_name"`
		StartURL        string `json:"start_url"`
		Scope           string `json:"scope"`
		Display         string `json:"display"`
		BackgroundColor string `json:"background_color"`
		ThemeColor      string `json:"theme_color"`
		Icons           []struct {
			Src     string `json:"src"`
			Sizes   string `json:"sizes"`
			Type    string `json:"type"`
			Purpose string `json:"purpose"`
		} `json:"icons"`
	}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("manifest invalid JSON: %v", err)
	}
	for _, kv := range [][2]string{
		{"name", m.Name}, {"short_name", m.ShortName},
		{"start_url", m.StartURL}, {"display", m.Display},
	} {
		if kv[1] == "" {
			t.Fatalf("manifest missing %q", kv[0])
		}
	}
	if len(m.Icons) == 0 {
		t.Fatal("manifest has no icons")
	}
	maskable := false
	for _, ic := range m.Icons {
		if !strings.HasPrefix(ic.Src, "/") {
			t.Fatalf("icon src %q must be absolute", ic.Src)
		}
		rel := "frontend" + ic.Src
		ib, err := FS.ReadFile(rel)
		if err != nil {
			t.Fatalf("icon %q missing from bundle: %v", ic.Src, err)
		}
		cfg, err := png.DecodeConfig(bytes.NewReader(ib))
		if err != nil {
			t.Fatalf("icon %q not a valid PNG: %v", ic.Src, err)
		}
		wh := strings.SplitN(ic.Sizes, "x", 2)
		if len(wh) != 2 {
			t.Fatalf("icon %q bad sizes %q", ic.Src, ic.Sizes)
		}
		w, _ := strconv.Atoi(wh[0])
		h, _ := strconv.Atoi(wh[1])
		if cfg.Width != w || cfg.Height != h {
			t.Fatalf("icon %q is %dx%d, manifest says %s", ic.Src, cfg.Width, cfg.Height, ic.Sizes)
		}
		if ic.Purpose == "maskable" {
			maskable = true
		}
	}
	if !maskable {
		t.Fatal("manifest needs a maskable icon (Android adaptive icons)")
	}
}

func TestPWAShell(t *testing.T) {
	// Worker exists and only precaches bundled public files.
	sw, err := FS.ReadFile("frontend/sw.js")
	if err != nil {
		t.Fatalf("sw.js missing: %v", err)
	}
	for _, core := range []string{"/login.html", "/manifest.webmanifest", "/icons/icon-192.png"} {
		if !strings.Contains(string(sw), `"`+core+`"`) {
			t.Fatalf("sw.js does not precache %q", core)
		}
	}
	// The worker must never cache the authed console or streams: API,
	// WS and screens pass through by construction (asserted below).
	if !strings.Contains(string(sw), "/api/") {
		t.Fatal("sw.js must explicitly pass through /api/")
	}
	if !strings.Contains(string(sw), "/screens/") {
		t.Fatal("sw.js must explicitly pass through /screens/")
	}
	// Login page links the shell together (index.html stays frozen).
	login, err := FS.ReadFile("frontend/login.html")
	if err != nil {
		t.Fatalf("login.html missing: %v", err)
	}
	for _, want := range []string{
		`rel="manifest"`, "/manifest.webmanifest",
		"apple-touch-icon", "/icons/icon-192.png",
		`register("/sw.js")`,
	} {
		if !strings.Contains(string(login), want) {
			t.Fatalf("login.html missing %q", want)
		}
	}
}
