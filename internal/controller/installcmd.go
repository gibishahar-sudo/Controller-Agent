package controller

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"rmm/internal/version"
)

// Install-command fallback (v1.45.2): when push-update is impossible (no
// bundle, stale bundle, agent offline after failed rounds) the controller
// hands out the same short EncodedCommand install one-liner used by tooling:
// download Agent-Setup.exe for this version's tag and run it silent.
// Token comes from RMM_GH_TOKEN env or gh_token.txt beside the controller.

const (
	ghRepo     = "gibishahar-sudo/Controller-"
	ghAsset    = "Agent-Setup.exe"
	ghAssetURL = "https://api.github.com/repos/gibishahar-sudo/Controller-/releases/assets/%d"
)

var (
	installCmdMu   sync.Mutex
	installCmdCach = map[string]string{} // tag -> powershell -EncodedCommand ...
	ghAssetIDMu    sync.Mutex
	ghAssetIDCach  = map[string]int64{} // tag -> asset id
)

func ghToken() string {
	if t := strings.TrimSpace(os.Getenv("RMM_GH_TOKEN")); t != "" {
		return t
	}
	if exe, err := os.Executable(); err == nil {
		if b, err := os.ReadFile(filepath.Join(filepath.Dir(exe), "gh_token.txt")); err == nil {
			return strings.TrimSpace(string(b))
		}
	}
	if b, err := os.ReadFile("gh_token.txt"); err == nil {
		return strings.TrimSpace(string(b))
	}
	return ""
}

func ghHeaders(tok string) map[string]string {
	h := map[string]string{
		"Accept":               "application/vnd.github+json",
		"User-Agent":           "rmm-controller",
		"X-GitHub-Api-Version": "2022-11-28",
	}
	if tok != "" {
		h["Authorization"] = "Bearer " + tok
	}
	return h
}

// resolveAssetID returns the numeric id of Agent-Setup.exe on tag (cached).
func resolveAssetID(tag string) (int64, error) {
	ghAssetIDMu.Lock()
	if id, ok := ghAssetIDCach[tag]; ok && id > 0 {
		ghAssetIDMu.Unlock()
		return id, nil
	}
	ghAssetIDMu.Unlock()

	tok := ghToken()
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/tags/%s", ghRepo, tag)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	for k, v := range ghHeaders(tok) {
		req.Header.Set(k, v)
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return 0, fmt.Errorf("github tag %s: HTTP %d %s", tag, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var rel struct {
		Assets []struct {
			ID   int64  `json:"id"`
			Name string `json:"name"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return 0, err
	}
	for _, a := range rel.Assets {
		if a.Name == ghAsset {
			ghAssetIDMu.Lock()
			ghAssetIDCach[tag] = a.ID
			ghAssetIDMu.Unlock()
			return a.ID, nil
		}
	}
	return 0, fmt.Errorf("release %s has no %s", tag, ghAsset)
}

// buildInstallPS is the remote one-liner (single quotes only — the old app
// parser and cmd.exe both eat double quotes). Download authenticated asset
// to %TEMP%, detect admin, run Agent-Setup.exe --silent, report a=<admin>
// e=<exit>. Mirrors tool/gen_short.py exactly.
func buildInstallPS(assetID int64) string {
	return "$h=@{Authorization='Bearer " + ghToken() + "'};" +
		"$u='https://api.github.com/repos/" + ghRepo + "/releases/assets/" + fmt.Sprintf("%d", assetID) + "';" +
		"$o=($env:TEMP+'\\A.exe');" +
		"iwr -Headers ($h+@{Accept='application/octet-stream'}) -Uri $u -OutFile $o;" +
		"$a=[bool]((whoami /groups)-match'S-1-16-12288');" +
		"if($a){$c=Start-Process $o '--silent' -Wait -PassThru}" +
		"else{$c=Start-Process $o '--silent' -Verb RunAs -Wait -PassThru};" +
		"'a='+$a+' e='+$c.ExitCode"
}

// installCommand returns the full `powershell -EncodedCommand <b64>` line
// for the current suite version (UTF-16LE, as PowerShell expects).
func installCommand() (string, error) {
	tag := "v" + version.Version
	installCmdMu.Lock()
	defer installCmdMu.Unlock()
	if c, ok := installCmdCach[tag]; ok && c != "" {
		return c, nil
	}
	if ghToken() == "" {
		return "", fmt.Errorf("no GitHub token: set RMM_GH_TOKEN or put gh_token.txt beside the controller")
	}
	aid, err := resolveAssetID(tag)
	if err != nil {
		return "", err
	}
	ps := buildInstallPS(aid)
	if strings.Contains(ps, "\"") {
		return "", fmt.Errorf("double quote leaked into install script")
	}
	// PowerShell -EncodedCommand expects UTF-16LE bytes of the script.
	raw := encodeUTF16LE(ps)
	b64 := base64.StdEncoding.EncodeToString(raw)
	// Round-trip self-check (same guarantee as gen_short.py).
	back, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || decodeUTF16LE(back) != ps {
		return "", fmt.Errorf("install-cmd round-trip mismatch")
	}
	cmd := "powershell -EncodedCommand " + b64
	installCmdCach[tag] = cmd
	return cmd, nil
}

func encodeUTF16LE(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for _, r := range s {
		if r > 0xFFFF {
			r -= 0x10000
			hi := uint16(0xD800 + (r >> 10))
			lo := uint16(0xDC00 + (r & 0x3FF))
			out = append(out, byte(hi), byte(hi>>8), byte(lo), byte(lo>>8))
			continue
		}
		u := uint16(r)
		out = append(out, byte(u), byte(u>>8))
	}
	return out
}

func decodeUTF16LE(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	var runes []rune
	for i := 0; i+1 < len(b); i += 2 {
		u := uint16(b[i]) | uint16(b[i+1])<<8
		if u >= 0xD800 && u < 0xDC00 && i+3 < len(b) {
			u2 := uint16(b[i+2]) | uint16(b[i+3])<<8
			if u2 >= 0xDC00 && u2 < 0xE000 {
				runes = append(runes, rune(((uint32(u)-0xD800)<<10)|(uint32(u2)-0xDC00)+0x10000))
				i += 2
				continue
			}
		}
		runes = append(runes, rune(u))
	}
	return string(runes)
}
