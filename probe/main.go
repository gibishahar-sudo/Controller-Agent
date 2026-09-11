// Command probe sends one command to one agent and prints what comes back
// over WS (output and any audiolist broadcast). Usage:
// probe <httpAddr> <agentID> <command...> [--want substr]
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

func main() {
	if len(os.Args) < 4 {
		fmt.Println("usage: probe <httpAddr> <agentID> <command...>")
		os.Exit(2)
	}
	httpAddr, agentID := os.Args[1], os.Args[2]
	rest := os.Args[3:]
	want := ""
	for i, a := range rest {
		if a == "--want" && i+1 < len(rest) {
			want = rest[i+1]
			rest = append(rest[:i], rest[i+2:]...)
			break
		}
	}
	cmd := strings.Join(rest, " ")

	ws, _, err := websocket.DefaultDialer.Dial("ws://"+httpAddr+"/ws", nil)
	if err != nil {
		fmt.Println("WS-FAIL dial:", err)
		os.Exit(1)
	}
	defer ws.Close()
	// No draining (a timed-out read poisons gorilla conns); the main loop
	// below simply ignores non-output/audiolist traffic.

	body, _ := json.Marshal(map[string]string{"cmd": cmd, "target": agentID})
	resp, err := http.Post("http://"+httpAddr+"/api/cmd", "application/json", bytes.NewReader(body))
	if err != nil {
		fmt.Println("WS-FAIL post:", err)
		os.Exit(1)
	}
	resp.Body.Close()
	fmt.Println("sent, waiting up to 20s for output/audiolist...")

	dumpAll := os.Getenv("PROBE_DUMP") != ""
	deadline := time.Now().Add(25 * time.Second)
	ws.SetReadDeadline(deadline)
	for time.Now().Before(deadline) {
		var m map[string]interface{}
		if err := ws.ReadJSON(&m); err != nil {
			fmt.Println("WS-FAIL read:", err)
			os.Exit(1)
		}
		t, _ := m["type"].(string)
		switch t {
		case "output":
			id, _ := m["id"].(string)
			if id != "" && id != agentID {
				continue
			}
			data, _ := m["data"].(string)
			errStr, _ := m["error"].(string)
			if dumpAll {
				fmt.Printf("--- %s len=%d err=%q\n%s\n", t, len(data), errStr, truncate(data, 300))
				continue
			}
			if want != "" && !strings.Contains(data, want) && !strings.Contains(errStr, want) {
				continue // other traffic (e.g. monitor polls); keep waiting
			}
			fmt.Printf("OUTPUT len=%d err=%q\n%s\n", len(data), errStr, truncate(data, 1500))
			return
		case "audiolist":
			id, _ := m["id"].(string)
			if id != "" && id != agentID {
				continue
			}
			data, _ := m["data"].(string)
			fmt.Printf("AUDIOLIST len=%d\n%s\n", len(data), truncate(data, 1500))
			return
		}
	}
	fmt.Println("TIMEOUT: no output/audiolist in 20s")
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "\n...[truncated]"
	}
	return s
}
