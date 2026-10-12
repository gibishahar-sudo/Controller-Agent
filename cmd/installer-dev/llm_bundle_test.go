package main

import (
	"os"
	"path/filepath"
	"testing"
)

// Already-installed sidecar short-circuits (reinstalls stay fast/quiet).
func TestLlmSidecarReady(t *testing.T) {
	dir := t.TempDir()
	if llmSidecarReady(dir) {
		t.Fatal("empty dir must read not-ready")
	}
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0755); err != nil {
		t.Fatal(err)
	}
	// Wrong-size model: not ready.
	if err := os.WriteFile(filepath.Join(dir, "model.gguf"), []byte("small"), 0644); err != nil {
		t.Fatal(err)
	}
	if llmSidecarReady(dir) {
		t.Fatal("wrong-size model must read not-ready")
	}
	// Exact size + exe: ready (size gate only at install; runtime hashes).
	big := make([]byte, llmModelSizeWant)
	if err := os.WriteFile(filepath.Join(dir, "model.gguf"), big, 0644); err != nil {
		t.Fatal(err)
	}
	if llmSidecarReady(dir) {
		t.Fatal("missing exe must read not-ready")
	}
	if err := os.WriteFile(filepath.Join(bin, "llama-server.exe"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	if !llmSidecarReady(dir) {
		t.Fatal("exact model + exe must read ready")
	}
}

// --llm-bundle flag parsing (both forms + absent).
func TestLlmBundleFlag(t *testing.T) {
	old := os.Args
	defer func() { os.Args = old }()
	os.Args = []string{"setup.exe", "--llm-bundle", `C:\x\b.zip`}
	if got := llmBundleFlag(); got != `C:\x\b.zip` {
		t.Fatalf("space form: %q", got)
	}
	os.Args = []string{"setup.exe", "--llm-bundle=C:\\y\\c.zip"}
	if got := llmBundleFlag(); got != `C:\y\c.zip` {
		t.Fatalf("equals form: %q", got)
	}
	os.Args = []string{"setup.exe"}
	if got := llmBundleFlag(); got != "" {
		t.Fatalf("absent: %q", got)
	}
}
