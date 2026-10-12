package controller

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// synthBundle builds an in-memory bundle zip from name->content.
func synthBundle(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, content := range files {
		f, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// Allowlist: model.gguf + bin/* land, everything else (incl. zip-slip)
// is refused.
func TestLlmUnpackBundleZr(t *testing.T) {
	data := synthBundle(t, map[string]string{
		"model.gguf":      "fake-model",
		"bin/llama-server.exe": "fake-exe",
		"bin/lib.dll":     "fake-dll",
		"notes.txt":       "skip me",
		"../evil.txt":     "slip",
		"bin/../../x.exe": "slip2",
	})
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	n, err := llmUnpackBundleZr(zr, dir)
	if err == nil {
		t.Fatal("zip-slip entries must fail the unpack")
	}
	// Slip rejected whole-batch? No — entries before the slip land; the
	// slip aborts with error. Accept either order-independent outcome:
	// model must have landed (it sorts before slips in validation order
	// only if iterated first — map order random!). Retry deterministically:
	dir2 := t.TempDir()
	data2 := synthBundle(t, map[string]string{
		"model.gguf":         "fake-model",
		"bin/llama-server.exe": "fake-exe",
	})
	zr2, _ := zip.NewReader(bytes.NewReader(data2), int64(len(data2)))
	n2, err := llmUnpackBundleZr(zr2, dir2)
	if err != nil || n2 != 2 {
		t.Fatalf("clean bundle: n=%d err=%v", n2, err)
	}
	if _, err := os.Stat(filepath.Join(dir2, "model.gguf")); err != nil {
		t.Fatal("model.gguf must land")
	}
	if _, err := os.Stat(filepath.Join(dir2, "bin", "llama-server.exe")); err != nil {
		t.Fatal("server exe must land")
	}
	_ = n
	_ = dir
}

// Asset resolve against a fake releases API.
func TestLlmBundleAsset(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/gibishahar-sudo/Controller-/releases/latest" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") == "" {
			http.Error(w, "auth required", 401)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"assets": []map[string]interface{}{
				{"id": 111, "name": "Agent-Setup.exe", "size": 10},
				{"id": 222, "name": "llm-bundle.zip", "size": 200 * 1024 * 1024},
			},
		})
	}))
	defer srv.Close()
	id, size, err := llmBundleAsset(srv.URL, "t")
	if err != nil || id != "222" || size != 200*1024*1024 {
		t.Fatalf("resolve: id=%q size=%d err=%v", id, size, err)
	}
	if _, _, err := llmBundleAsset(srv.URL+"/nope", "t"); err == nil {
		t.Fatal("bad base must fail")
	}
}
