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
//	go run ./tool/geninstall v1.47.3          # Invoke-WebRequest fetcher
//	go run ./tool/geninstall -curl v1.47.3    # curl.exe resume fetcher
//	                                          # (pipes that RST mid-download)
//	go run ./tool/geninstall -ps1 v1.47.3 > install-agent.ps1
//	                                          # file variant: secrets via
//	                                          # $env, code over HTTPS
//
// Token comes from gh_token.txt beside the repo (gitignored, same as the
// ship scripts). Output is the ready-to-paste powershell line — or with
// -ps1, the raw file body on stdout (redirect to install-agent.ps1;
// asset line goes to stderr to keep the redirect clean).
func main() {
	mode := "iwr"
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "-curl" {
		mode = "curl"
		args = args[1:]
	}
	ps1 := false
	if len(args) > 0 && args[0] == "-ps1" {
		ps1 = true
		args = args[1:]
	}
	if len(args) != 1 || !strings.HasPrefix(args[0], "v") {
		fmt.Fprintln(os.Stderr, "usage: go run ./tool/geninstall [-curl] [-ps1] vX.Y.Z")
		os.Exit(2)
	}
	tag := args[0]
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
	line, err := encodeCMD(buildInstallCMDMode(token, id, size, mode))
	if err != nil {
		fmt.Fprintln(os.Stderr, "encode:", err)
		os.Exit(1)
	}
	if ps1 {
		fmt.Fprintf(os.Stderr, "asset: Agent-Setup.exe id=%s size=%d\n", id, size)
		fmt.Print(buildInstallPS1(id, size))
		return
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
