package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Command geninstall mints the agent install CMD for a release tag:
//
//	go run ./tool/geninstall v1.47.3
//
// Token comes from gh_token.txt beside the repo (gitignored, same as the
// ship scripts). Output is the ready-to-paste powershell line.
func main() {
	if len(os.Args) != 2 || !strings.HasPrefix(os.Args[1], "v") {
		fmt.Fprintln(os.Stderr, "usage: go run ./tool/geninstall vX.Y.Z")
		os.Exit(2)
	}
	tag := os.Args[1]
	rawTok, err := os.ReadFile("gh_token.txt")
	if err != nil {
		fmt.Fprintln(os.Stderr, "gh_token.txt missing:", err)
		os.Exit(1)
	}
	token := strings.TrimSpace(strings.Split(string(rawTok), "\n")[0])
	id, size, err := findAgentAsset(token, tag)
	if err != nil {
		fmt.Fprintln(os.Stderr, "asset lookup:", err)
		os.Exit(1)
	}
	line, err := encodeCMD(buildInstallCMD(token, id, size))
	if err != nil {
		fmt.Fprintln(os.Stderr, "encode:", err)
		os.Exit(1)
	}
	fmt.Printf("asset: Agent-Setup.exe id=%s size=%d\n%s\n", id, size, line)
}

func findAgentAsset(token, tag string) (string, int64, error) {
	req, err := http.NewRequest("GET", "https://api.github.com/repos/gibishahar-sudo/Controller-/releases/tags/"+tag, nil)
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
		return "", 0, fmt.Errorf("release %s: http %d", tag, r.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return "", 0, err
	}
	var rel struct {
		Assets []struct {
			ID   int64  `json:"id"`
			Name string `json:"name"`
			Size int64  `json:"size"`
		} `json:"assets"`
	}
	if err := json.Unmarshal(body, &rel); err != nil {
		return "", 0, err
	}
	for _, a := range rel.Assets {
		if a.Name == "Agent-Setup.exe" {
			return fmt.Sprintf("%d", a.ID), a.Size, nil
		}
	}
	return "", 0, fmt.Errorf("Agent-Setup.exe not in %s", tag)
}
