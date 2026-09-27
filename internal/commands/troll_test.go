package commands

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPlayTrollUsage(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("non-windows refusal path only")
	}
	if _, err := playTroll(""); err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("err = %v, want not supported", err)
	}
	if _, err := stopTroll(); err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("stop err = %v, want not supported", err)
	}
}

func TestTrollScriptSafetyMarkers(t *testing.T) {
	// Video path must contain every safety rail: hard timeout, BlockInput
	// off on close, no taskbar, topmost, MediaFailed unblock.
	script, err := trollScript(`C:\m\v.mp4`, ".mp4", 300, true, `C:\m\status.txt`)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"BlockInput($false)",
		"BlockInput($true)",
		"ShowInTaskbar = $false",
		"Topmost = $true",
		"WindowStyle = 'None'",
		"MediaFailed",
		"Add_Closed",
		// Lockdown rails (v1.46.1): close-cancel, key hook, re-assert.
		"allowClose",
		"Cancel = $true",
		"SetWindowsHookEx",
		"Uninstall()",
		// Playback proof (v1.46.1): status handshake + no-proof watchdog.
		"MediaOpened",
		"timeout-no-media",
		"failed: ",
		// Multi-monitor (v1.46.6): per-screen windows, modeless pump.
		"AllScreens",
		"InvokeShutdown",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("video script missing safety marker %q", want)
		}
	}
	if strings.Contains(script, `"C:`) {
		t.Fatalf("path double-quoted")
	}

	gscript, err := trollScript(`C:\m\loop.gif`, ".gif", 60, false, `C:\m\status.txt`)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"BlockInput($false)",
		"BlockInput($true)",
		"TopMost = $true",
		"ShowInTaskbar = $false",
		"FormBorderStyle = 'None'",
		"Add_FormClosed",
		// Lockdown rails (v1.46.1).
		"allowClose",
		"Cancel = $true",
		"SetWindowsHookEx",
		"Uninstall()",
		"Add_FormClosing",
		// Playback proof (v1.46.1).
		"'opened'",
		"failed: ",
		// Multi-monitor (v1.46.6): per-screen forms, modeless pump.
		"AllScreens",
		"ExitThread",
	} {
		if !strings.Contains(gscript, want) {
			t.Fatalf("gif script missing safety marker %q", want)
		}
	}
}

func TestTrollSecondsClampLogic(t *testing.T) {
	// playTroll clamps via maxTrollSeconds; assert the constants hold.
	if defaultTrollSeconds <= 0 || defaultTrollSeconds > maxTrollSeconds {
		t.Fatalf("default %d max %d", defaultTrollSeconds, maxTrollSeconds)
	}
	if maxTrollSeconds != 3600 {
		t.Fatalf("maxTrollSeconds = %d, want 3600 (1h hard cap)", maxTrollSeconds)
	}
}

func TestTrollExtKind(t *testing.T) {
	for _, ext := range []string{".mp4", ".mov", ".avi", ".wmv", ".mkv", ".webm", ".m4v", ".mpg", ".mp3", ".wav", ".wma", ".m4a"} {
		if trollExtKind(ext) != "video" {
			t.Fatalf("%s should be video", ext)
		}
	}
	for _, ext := range []string{".gif", ".png", ".jpg", ".jpeg", ".bmp"} {
		if trollExtKind(ext) != "image" {
			t.Fatalf("%s should be image", ext)
		}
	}
	for _, ext := range []string{"", ".dat", ".exe", ".ps1", ".txt"} {
		if trollExtKind(ext) != "" {
			t.Fatalf("%s should be rejected", ext)
		}
	}
}

func TestTrollExtForContentType(t *testing.T) {
	cases := map[string]string{
		"video/mp4": "mp4", "image/gif": "gif", "image/png": "png",
		"video/x-matroska": "mkv", "text/html": "",
		"video/mp4; charset=binary": "mp4",
	}
	for ct, want := range cases {
		got := trollExtForContentType(ct)
		if want == "" && got != "" {
			t.Fatalf("%s should map to nothing, got %s", ct, got)
		}
		if want != "" && got != "."+want {
			t.Fatalf("%s mapped to %s, want .%s", ct, got, want)
		}
	}
}

// Still images must ride the WinForms branch (PictureBox), never WPF
// MediaElement (which never raises MediaOpened for a still — the exact
// failure behind "troll media failed: timeout-no-media" on a .jpg).
func TestTrollStillsUseWinForms(t *testing.T) {
	for _, ext := range []string{".jpg", ".jpeg", ".bmp", ".png", ".gif"} {
		s, err := trollScript(`C:\m\pic`+ext, ext, 60, true, `C:\m\status.txt`)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(s, "PictureBox") {
			t.Fatalf("%s script missing WinForms PictureBox", ext)
		}
		if strings.Contains(s, "MediaElement") {
			t.Fatalf("%s script wrongly uses WPF MediaElement", ext)
		}
	}
	v, err := trollScript(`C:\m\v.mp4`, ".mp4", 60, true, `C:\m\status.txt`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(v, "MediaElement") {
		t.Fatal("mp4 script missing WPF MediaElement")
	}
	a, err := trollScript(`C:\m\s.mp3`, ".mp3", 60, true, `C:\m\status.txt`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(a, "MediaElement") {
		t.Fatal("mp3 script missing WPF MediaElement (audio rides the media pipeline)")
	}
	if !strings.Contains(a, "MediaOpened") {
		t.Fatal("mp3 script missing MediaOpened proof handshake")
	}
}

func TestSniffMP4Codec(t *testing.T) {
	mk := func(payload string) string {
		p := filepath.Join(t.TempDir(), "s.mp4")
		// Minimal ftyp box: size(4) "ftyp" major(4) minor(4) + brands.
		box := []byte{0, 0, 0, 32, 'f', 't', 'y', 'p', 'i', 's', 'o', 'm', 0, 0, 0, 0}
		box = append(box, []byte(payload)...)
		if err := os.WriteFile(p, box, 0644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if got := sniffMP4Codec(mk("avc1....")); got != "h264" {
		t.Fatalf("avc1 = %q, want h264", got)
	}
	if got := sniffMP4Codec(mk("hvc1....")); got != "hevc" {
		t.Fatalf("hvc1 = %q, want hevc", got)
	}
	if got := sniffMP4Codec(mk("vp09....")); got != "vp9" {
		t.Fatalf("vp09 = %q, want vp9", got)
	}
	if got := sniffMP4Codec(filepath.Join(t.TempDir(), "missing.mp4")); got != "" {
		t.Fatalf("missing file = %q, want empty", got)
	}
}

func TestSniffMP4CodecMoovAtEnd(t *testing.T) {
	// Non-faststart layout: ftyp + mdat up front, moov (with codec box)
	// at the END. A head-only scan reports "other"; the tail scan must
	// find it. (jackpot.mp4: 107MB, vp9, moov at EOF.)
	p := filepath.Join(t.TempDir(), "tail.mp4")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	ftyp := []byte{0, 0, 0, 28, 'f', 't', 'y', 'p', 'i', 's', 'o', 'm', 0, 0, 0, 0, 'i', 's', 'o', '2', 0, 0, 0, 0, 0, 0, 0, 0}
	if _, err := f.Write(ftyp); err != nil {
		t.Fatal(err)
	}
	// 200KB of filler so the tail window (256KB from EOF) differs.
	filler := make([]byte, 200<<10)
	if _, err := f.Write(filler); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("....moov....vp09....")); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if got := sniffMP4Codec(p); got != "vp9" {
		t.Fatalf("moov-at-end vp9 = %q, want vp9", got)
	}
	if !mp4HasMoov(p) {
		t.Fatal("moov-at-end file should have moov")
	}
	// Truncated twin: ftyp + filler, no moov anywhere.
	p2 := filepath.Join(t.TempDir(), "trunc.mp4")
	f2, err := os.Create(p2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f2.Write(ftyp); err != nil {
		t.Fatal(err)
	}
	if _, err := f2.Write(filler); err != nil {
		t.Fatal(err)
	}
	f2.Close()
	if got := sniffMP4Codec(p2); got != "other" {
		t.Fatalf("truncated = %q, want other", got)
	}
	if mp4HasMoov(p2) {
		t.Fatal("truncated file must not have moov")
	}
}

func TestTrollProbeScriptMarkers(t *testing.T) {
	s, err := trollProbeScript(`C:\m\v.mp4`)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"SingleBorderWindow",
		"CenterScreen",
		"MediaOpened",
		"MediaFailed",
		"NaturalVideoWidth",
		"PROBE-RESULT: ",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("probe script missing marker %q", want)
		}
	}
	for _, bad := range []string{"BlockInput", "Topmost", "SetWindowsHookEx", "Opacity = 0"} {
		if strings.Contains(s, bad) {
			t.Fatalf("probe script must not lock down or hide (%q present)", bad)
		}
	}
}

// mkIndexMP4 builds a synthetic MP4: ftyp + mdat(size) + moov with a
// proper trak>mdia>minf>stbl>stco nesting holding the given chunks.
func mkIndexMP4(t *testing.T, mdatSize int, chunks []uint32) string {
	t.Helper()
	box := func(typ string, payload []byte) []byte {
		b := make([]byte, 8+len(payload))
		binary.BigEndian.PutUint32(b[0:4], uint32(len(b)))
		copy(b[4:8], []byte(typ))
		copy(b[8:], payload)
		return b
	}
	p := filepath.Join(t.TempDir(), "idx.mp4")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	ftyp := []byte{0, 0, 0, 20, 'f', 't', 'y', 'p', 'i', 's', 'o', 'm', 0, 0, 0, 0, 'i', 's', 'o', '2'}
	if _, err := f.Write(ftyp); err != nil {
		t.Fatal(err)
	}
	mdatHdr := make([]byte, 8)
	binary.BigEndian.PutUint32(mdatHdr[0:4], uint32(8+mdatSize))
	copy(mdatHdr[4:8], []byte("mdat"))
	if _, err := f.Write(mdatHdr); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(make([]byte, mdatSize)); err != nil {
		t.Fatal(err)
	}
	stco := make([]byte, 8+4*len(chunks))
	binary.BigEndian.PutUint32(stco[4:8], uint32(len(chunks)))
	for i, c := range chunks {
		binary.BigEndian.PutUint32(stco[8+i*4:], c)
	}
	stbl := box("stbl", box("stco", stco))
	minf := box("minf", stbl)
	mdia := box("mdia", minf)
	trak := box("trak", mdia)
	moov := box("moov", trak)
	if _, err := f.Write(moov); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestMp4IndexSane(t *testing.T) {
	mdatSize := 8 << 20 // above the 4MB coverage-rule floor
	base := uint32(20 + 8) // ftyp(20) + mdat header(8)
	// 10+ entries per table (smaller tables are skipped as thumbnails).
	var good []uint32
	for i := 0; i < 10; i++ {
		good = append(good, base+100+uint32(i)*(uint32(mdatSize)-1000)/10)
	}
	if ok, reason := mp4IndexSane(mkIndexMP4(t, mdatSize, good)); !ok {
		t.Fatalf("sane index rejected: %s", reason)
	}
	// Clustered: all chunks inside the first KB of an 8MB mdat.
	var bad []uint32
	for i := 0; i < 10; i++ {
		bad = append(bad, base+100+uint32(i)*90)
	}
	if ok, reason := mp4IndexSane(mkIndexMP4(t, mdatSize, bad)); ok {
		t.Fatal("clustered index accepted")
	} else if !strings.Contains(reason, "covers only") {
		t.Fatalf("wrong reason: %s", reason)
	}
	// Escaped: chunk past mdat end.
	esc := append(append([]uint32{}, good[:9]...), base+uint32(mdatSize)+50000)
	if ok, _ := mp4IndexSane(mkIndexMP4(t, mdatSize, esc)); ok {
		t.Fatal("escaping index accepted")
	}
	// Fragmented (no tables): passes through to the player.
	p := filepath.Join(t.TempDir(), "frag.mp4")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte{0, 0, 0, 20, 'f', 't', 'y', 'p', 'i', 's', 'o', 'm', 0, 0, 0, 0, 'i', 's', 'o', '2'})
	f.Write([]byte{0, 0, 0, 8, 'm', 'd', 'a', 't'})
	f.Write([]byte{0, 0, 0, 16, 'm', 'o', 'o', 'v', 0, 0, 0, 8, 'm', 'v', 'e', 'x'})
	f.Close()
	if ok, _ := mp4IndexSane(p); !ok {
		t.Fatal("fragmented file should pass through")
	}
}

func TestTrollEngine(t *testing.T) {
	cases := []struct {
		codec   string
		indexOK bool
		edgeOK  bool
		want    string
		wantErr bool
	}{
		{"h264", true, true, "wpf", false},
		{"h264", true, false, "wpf", false},
		{"h264", false, true, "edge", false},
		{"h264", false, false, "", true},
		{"vp9", true, true, "edge", false},
		{"vp9", true, false, "", true},
		{"av1", false, true, "edge", false},
		{"", true, false, "wpf", false},
		{"other", true, true, "wpf", false},
	}
	for _, c := range cases {
		got, err := trollEngine(c.codec, c.indexOK, c.edgeOK)
		if c.wantErr && err == nil {
			t.Fatalf("engine(%q,%v,%v) should error", c.codec, c.indexOK, c.edgeOK)
		}
		if !c.wantErr && (err != nil || got != c.want) {
			t.Fatalf("engine(%q,%v,%v) = %q,%v want %q", c.codec, c.indexOK, c.edgeOK, got, err, c.want)
		}
	}
}

func TestTrollEdgeScriptMarkers(t *testing.T) {
	s, err := trollEdgeScript(`C:\e\msedge.exe`, `C:\m\v.mp4`, false, 300, true, `C:\m\status.txt`)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"--kiosk",
		"--new-window",
		"--user-data-dir=",
		"--no-first-run",
		"--no-default-browser-check",
		"--disable-search-engine-choice-screen",
		"--autoplay-policy=no-user-gesture-required",
		"First Run",
		"Edge-CleanLocks",
		"SingletonLock",
		"Start-TrollEdge",
		"FindTrollWindow",
		"EnumWindows",
		"FullscreenTroll",
		"GetSystemMetrics",
		"RMM-TROLL-PLAYING",
		"RMM-TROLL-STALLED",
		"RMM-TROLL",
		"SetWindowPos",
		"HWND_TOPMOST",
		"BlockInput($true)",
		"BlockInput($false)",
		"'opened'",
		"failed: ",
		"user-data-dir",
		"stopFlag",
		"troll.stop",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("edge script missing marker %q", want)
		}
	}
}

func TestTrollStopFlag(t *testing.T) {
	dir := t.TempDir()
	if trollStopFlagged(dir) {
		t.Fatal("fresh dir should not be flagged")
	}
	setTrollStopFlag(dir)
	if !trollStopFlagged(dir) {
		t.Fatal("flag should exist after set")
	}
	clearTrollStopFlag(dir)
	if trollStopFlagged(dir) {
		t.Fatal("flag should be gone after clear")
	}
	if trollStopFlagPath(dir) == "" {
		t.Fatal("empty flag path")
	}
}
