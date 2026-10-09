package main

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
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
	if err := extractLLMBundle(buf.Bytes(), dir); err == nil {
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
	if err := extractLLMBundle(buf.Bytes(), dir2); err != nil {
		t.Fatalf("clean extract: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(dir2, "bin", "llama-server.exe")); err != nil || string(b) != "EXE" {
		t.Fatalf("exe: %v %q", err, b)
	}
	if b, err := os.ReadFile(filepath.Join(dir2, "model.gguf")); err != nil || string(b) != "MODEL" {
		t.Fatalf("model: %v %q", err, b)
	}
}
