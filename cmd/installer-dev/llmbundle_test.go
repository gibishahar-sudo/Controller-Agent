package main

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// validBundleEntry gates the sidecar layout (v1.46.98): bin/* + model.
func TestValidBundleEntry(t *testing.T) {
	for _, ok := range []string{"model.gguf", "bin/llama-server.exe", "bin/x.dll", "./model.gguf"} {
		if !validBundleEntry(ok) {
			t.Fatalf("%q must be allowed", ok)
		}
	}
	for _, no := range []string{"../evil.exe", "evil.exe", "bin", "", "model.gguf.bak", "x/model.gguf"} {
		if validBundleEntry(no) {
			t.Fatalf("%q must be rejected", no)
		}
	}
}

// Backslash layout (v1.46.99 post-mortem): Compress-Archive writes
// bin\file.dll, which failed the bin/ prefix test and skipped all 30
// server files while model.gguf landed — the exact box state.
func TestBackslashBundle(t *testing.T) {
	for _, ok := range []string{`bin\llama-server.exe`, `bin\x.dll`, `.\model.gguf`} {
		if !validBundleEntry(ok) {
			t.Fatalf("%q must be allowed", ok)
		}
	}
	if got := normZipName(`bin\sub\a.dll`); got != "bin/sub/a.dll" {
		t.Fatalf("norm = %q", got)
	}
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, e := range [][2]string{{`bin\srv.exe`, "EXE"}, {`model.gguf`, "MODEL"}, {`bin\..\..\evil.exe`, "evil"}} {
		fw, err := w.Create(e[0])
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write([]byte(e[1])); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if _, err := extractLLMBundle(buf.Bytes(), dir); err == nil {
		t.Fatal("backslash traversal must fail the extract")
	}
	buf.Reset()
	w = zip.NewWriter(&buf)
	for _, e := range [][2]string{{`bin\srv.exe`, "EXE"}, {`model.gguf`, "MODEL"}} {
		fw, err := w.Create(e[0])
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write([]byte(e[1])); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	dir2 := t.TempDir()
	n, err := extractLLMBundle(buf.Bytes(), dir2)
	if err != nil || n != 2 {
		t.Fatalf("backslash extract = %d, %v", n, err)
	}
	if b, err := os.ReadFile(filepath.Join(dir2, "bin", "srv.exe")); err != nil || string(b) != "EXE" {
		t.Fatalf("backslash mapping: %v %q", err, b)
	}
}

// llmReport must name what's present, what's missing, and where —
// never a bare "missing" again.
func TestLlmReport(t *testing.T) {
	got := llmReport(`C:\x\llm`, true, true, 31)
	if !strings.Contains(got, "OK") || strings.Contains(got, "MISSING") {
		t.Fatalf("full: %q", got)
	}
	got = llmReport(`C:\x\llm`, true, false, 1)
	if !strings.Contains(got, "llama-server.exe MISSING") || !strings.Contains(got, `C:\x\llm`) {
		t.Fatalf("partial: %q", got)
	}
}

// bundleEntrySample shows layout evidence (first names verbatim).
func TestBundleEntrySample(t *testing.T) {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, e := range []string{"b/a", "b/c", "m"} {
		if _, err := w.Create(e); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	got := bundleEntrySample(buf.Bytes(), 2)
	if len(got) != 2 || got[0] != "b/a" || got[1] != "b/c" {
		t.Fatalf("sample = %v", got)
	}
	if bundleEntrySample([]byte("junk"), 5) != nil {
		t.Fatal("garbage must yield nil")
	}
}

// extractLLMBundle lands the layout and rejects zip-slip (v1.46.98:
// the ~811MB bundle must unpack exactly, hostile entries never).
func TestExtractLLMBundle(t *testing.T) {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	add := func(name, body string) {
		fw, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	add("bin/llama-server.exe", "EXE")
	add("bin/x.dll", "DLL")
	add("model.gguf", "MODEL")
	add("notes.txt", "junk")
	add("../evil.exe", "evil")
	add("bin/../../evil2.exe", "evil2")
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if _, err := extractLLMBundle(buf.Bytes(), dir); err == nil {
		t.Fatal("zip-slip must fail the whole extract")
	}
	// evil must not exist anywhere near dest.
	for _, p := range []string{filepath.Join(dir, "evil.exe")} {
		if _, err := os.Stat(p); err == nil {
			t.Fatalf("zip-slip wrote %s", p)
		}
	}
	parent := filepath.Dir(dir)
	if _, err := os.Stat(filepath.Join(parent, "evil.exe")); err == nil {
		t.Fatal("zip-slip escaped dest")
	}
	// Clean bundle unpacks exactly.
	buf.Reset()
	w = zip.NewWriter(&buf)
	add("bin/llama-server.exe", "EXE")
	add("model.gguf", "MODEL")
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	dir2 := t.TempDir()
	n, err := extractLLMBundle(buf.Bytes(), dir2)
	if err != nil {
		t.Fatalf("clean extract: %v", err)
	}
	if n != 2 {
		t.Fatalf("entry count = %d, want 2", n)
	}
	if b, err := os.ReadFile(filepath.Join(dir2, "bin", "llama-server.exe")); err != nil || string(b) != "EXE" {
		t.Fatalf("exe: %v %q", err, b)
	}
	if b, err := os.ReadFile(filepath.Join(dir2, "model.gguf")); err != nil || string(b) != "MODEL" {
		t.Fatalf("model: %v %q", err, b)
	}
}
