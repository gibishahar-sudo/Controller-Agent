package controller

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Bundle-zip supply path for the LLM sidecar (v1.49.2): the release
// carries llm-bundle.zip (best compression, one download: model.gguf +
// bin/*). llmPullRun tries this FIRST; any failure falls through to the
// direct server-zip + model phases. Verified files always skip everything
// (reinstalls and repeats never re-fetch).

// llmGHToken resolves the release-asset token (env first, token file
// beside the exe second — same sources as install-cmd). "" = no bundle
// phase; the direct-URL phases need no auth.
func llmGHToken() string {
	if t := strings.TrimSpace(os.Getenv("RMM_GH_TOKEN")); t != "" {
		return t
	}
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	b, err := os.ReadFile(filepath.Join(filepath.Dir(exe), "github_token.txt"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(strings.Split(string(b), "\n")[0])
}

// llmBundleAsset resolves the llm-bundle.zip asset id+size from the latest
// suite release. The zip itself needs no pin — its CONTENTS verify (model
// SHA + size, server exe present) after unpack. apiBase is the API root
// (unit-tested against a fake server).
func llmBundleAsset(apiBase, token string) (id string, size int64, err error) {
	req, err := http.NewRequest("GET", strings.TrimSuffix(apiBase, "/")+"/repos/gibishahar-sudo/Controller-/releases/latest", nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	c := &http.Client{Timeout: 60 * time.Second}
	r, err := c.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return "", 0, fmt.Errorf("releases/latest: http %d", r.StatusCode)
	}
	var rel struct {
		Assets []struct {
			ID   int64  `json:"id"`
			Name string `json:"name"`
			Size int64  `json:"size"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&rel); err != nil {
		return "", 0, err
	}
	for _, a := range rel.Assets {
		if a.Name == "llm-bundle.zip" && a.Size > 100*1024*1024 {
			return fmt.Sprintf("%d", a.ID), a.Size, nil
		}
	}
	return "", 0, fmt.Errorf("no llm-bundle.zip in latest release")
}

// llmUnpackBundleZr extracts a bundle zip into dest (model.gguf + bin/*
// allowlist, zip-slip rejected). Returns accepted entries. Pure on the
// reader: unit-tested with synthetic zips; production passes a file-backed
// *zip.Reader (no 800MB RAM spike).
func llmUnpackBundleZr(zr *zip.Reader, dest string) (int, error) {
	base := filepath.Clean(dest) + string(os.PathSeparator)
	entries := 0
	for _, f := range zr.File {
		name := strings.ReplaceAll(strings.TrimPrefix(f.Name, "./"), "\\", "/")
		if f.FileInfo().IsDir() || (name != "model.gguf" && !strings.HasPrefix(name, "bin/")) {
			continue
		}
		out := filepath.Join(dest, filepath.FromSlash(name))
		if !strings.HasPrefix(out, base) {
			return 0, fmt.Errorf("zip-slip entry %q", f.Name)
		}
		if err := os.MkdirAll(filepath.Dir(out), 0700); err != nil {
			return entries, err
		}
		rc, err := f.Open()
		if err != nil {
			return entries, err
		}
		w, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			rc.Close()
			return entries, err
		}
		_, err = io.Copy(w, rc)
		rc.Close()
		w.Close()
		if err != nil {
			return entries, err
		}
		entries++
	}
	return entries, nil
}

// llmFetchBundle downloads the release bundle zip (authed), unpacks it,
// and verifies the result (model SHA+size, server exe present). Any failure
// leaves existing files untouched and returns the error for fallback.
func llmFetchBundle(st *llmState) error {
	fail := func(format string, args ...interface{}) error {
		err := fmt.Errorf(format, args...)
		st.mu.Lock()
		st.lastErr = err.Error()
		st.mu.Unlock()
		log.Printf("[llm] bundle phase: %v", err)
		return err
	}
	token := llmGHToken()
	if token == "" {
		return fail("no release token (RMM_GH_TOKEN or github_token.txt)")
	}
	id, size, err := llmBundleAsset("https://api.github.com", token)
	if err != nil {
		return fail("resolve: %v", err)
	}
	zpath := filepath.Join(llmHome(), "bundle.zip.tmp")
	url := "https://api.github.com/repos/gibishahar-sudo/Controller-/releases/assets/" + id
	if err := llmFetchAuth(url, zpath, size, st, "bundle", map[string]string{"Authorization": "token " + token, "Accept": "application/octet-stream"}); err != nil {
		os.Remove(zpath)
		return fail("download: %v", err)
	}
	f, err := os.Open(zpath)
	if err != nil {
		os.Remove(zpath)
		return fail("open: %v", err)
	}
	fi, _ := f.Stat()
	zr, err := zip.NewReader(f, fi.Size())
	if err != nil {
		f.Close()
		os.Remove(zpath)
		return fail("zip open: %v", err)
	}
	n, err := llmUnpackBundleZr(zr, llmHome())
	f.Close()
	os.Remove(zpath)
	if err != nil {
		return fail("unpack: %v", err)
	}
	if n == 0 {
		return fail("empty bundle")
	}
	if !modelFileVerified(llmModel()) {
		return fail("bundled model failed verification")
	}
	if _, err := os.Stat(llmExe()); err != nil {
		return fail("bundled server missing")
	}
	return nil
}

// llmFetchAuth is llmFetch with request headers (release assets need
// Authorization + octet-stream Accept; direct URLs pass nil).
func llmFetchAuth(url, dst string, wantSize int64, st *llmState, what string, headers map[string]string) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	c := &http.Client{Timeout: 0} // bounded by stopPull + read activity, not wall clock
	r, err := c.Do(req)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return fmt.Errorf("fetch %s: http %d", what, r.StatusCode)
	}
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	total := r.ContentLength
	if total <= 0 {
		total = wantSize
	}
	var got int64
	lastPct := -1
	chunk := make([]byte, 1<<20)
	for {
		st.mu.Lock()
		stop := st.stopPull
		st.mu.Unlock()
		if stop {
			return fmt.Errorf("pull cancelled")
		}
		n, err := r.Body.Read(chunk)
		if n > 0 {
			got += int64(n)
			if _, werr := out.Write(chunk[:n]); werr != nil {
				return werr
			}
			if total > 0 {
				pct := int(100 * got / total)
				if pct != lastPct && pct%5 == 0 {
					lastPct = pct
					st.mu.Lock()
					st.pullPct = pct
					st.mu.Unlock()
				}
			}
		}
		if err != nil {
			break
		}
	}
	if total > 0 && got != total {
		return fmt.Errorf("fetch %s: short (%d/%d)", what, got, total)
	}
	return nil
}
