package controller

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"runtime"
	"time"

	"rmm/internal/cmdlist"
	"rmm/internal/protocol"
	"rmm/internal/ui"
	"rmm/internal/version"
)

func (s *Server) startHTTP(addr, dir string) {
	sub, _ := fs.Sub(ui.FS, "frontend")
	mux := http.NewServeMux()
	mux.Handle("/screens/", http.StripPrefix("/screens/", http.FileServer(http.Dir(dir))))
	mux.Handle("/", http.FileServer(http.FS(sub)))
	mux.HandleFunc("/ws", s.handleWS)
	mux.HandleFunc("/api/commands", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cmdlist.Known)
	})
	mux.HandleFunc("/api/files", func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Query().Get("path")
		if p == "" {
			p = `C:\`
			if runtime.GOOS != "windows" {
				p = "/"
			}
		}
		entries, err := os.ReadDir(p)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		type FE struct {
			Name         string `json:"name"`
			Size         int64  `json:"size"`
			IsDirectory  bool   `json:"isDirectory"`
			LastModified string `json:"lastModified"`
		}
		var out []FE
		for _, e := range entries {
			info, _ := e.Info()
			var sz int64
			var mod string
			if info != nil {
				sz = info.Size()
				mod = info.ModTime().Format("2006-01-02T15:04:05Z07:00")
			}
			out = append(out, FE{Name: e.Name(), Size: sz, IsDirectory: e.IsDir(), LastModified: mod})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"path": p, "entries": out})
	})
	mux.HandleFunc("/api/cmd", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Cmd         string `json:"cmd"`
			Type        string `json:"type"`
			Target      string `json:"target"`
			Quality     int    `json:"quality"`
			Monitor     int    `json:"monitor"`
			AllMonitors bool   `json:"allMonitors"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
			http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
			return
		}
		target := r.URL.Query().Get("target")
		if target == "" {
			target = req.Target
		}
		ac := s.getAgentByID(target)
		if ac == nil {
			http.Error(w, "no agent connected", http.StatusServiceUnavailable)
			return
		}
		var msg protocol.Message
		switch {
		case req.Type == protocol.TypeScreenshotRequest || req.Cmd == "screenshot":
			msg = protocol.Message{Type: protocol.TypeScreenshotRequest, Quality: req.Quality, Monitor: req.Monitor, AllMonitors: req.AllMonitors}
		case req.Cmd != "":
			msg = protocol.Message{Type: protocol.TypeCommand, Cmd: req.Cmd}
		case req.Type != "":
			msg = protocol.Message{Type: req.Type}
		default:
			http.Error(w, "missing cmd", http.StatusBadRequest)
			return
		}
		if err := s.sendToAgent(ac, msg); err != nil {
			http.Error(w, "send failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "sent", "type": msg.Type, "cmd": msg.Cmd, "agent": ac.id})
	})
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		ac := s.getAgent()
		if ac == nil {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"connected": false, "count": len(s.Agents())})
			return
		}
		s.latencyMu.RLock()
		lat := s.latency[ac.id]
		s.latencyMu.RUnlock()
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"connected": true, "id": ac.id, "hostname": ac.hostname, "user": ac.user,
			"remote": ac.remote(), "latency": lat, "count": len(s.Agents()),
			"controllerVersion": version.Version,
		})
	})
	mux.HandleFunc("/api/agents", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"agents": s.Agents()})
	})

	s.httpSrv = &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	go func() {
		log.Printf("[http] UI at http://%s/", addr)
		if err := s.httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[http] %v", err)
		}
	}()
}

func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	raw, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("ws upgrade: %v", err)
		return
	}
	c := &wsClient{conn: raw}
	s.wsMu.Lock()
	s.wsClients[c] = true
	s.wsMu.Unlock()
	s.broadcastAgents()
	defer func() {
		s.wsMu.Lock()
		delete(s.wsClients, c)
		s.wsMu.Unlock()
		raw.Close()
	}()
	_ = raw.SetReadDeadline(time.Now().Add(60 * time.Second))
	raw.SetPongHandler(func(string) error {
		_ = raw.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})
	for {
		var msg map[string]interface{}
		if err := raw.ReadJSON(&msg); err != nil {
			break
		}
		_ = raw.SetReadDeadline(time.Now().Add(60 * time.Second))
		t, _ := msg["type"].(string)
		target, _ := msg["target"].(string)
		cmd, _ := msg["cmd"].(string)
		quality := 0
		if q, ok := msg["quality"].(float64); ok {
			quality = int(q)
		}
		monitor := 0
		if m, ok := msg["monitor"].(float64); ok {
			monitor = int(m)
		}
		allMonitors, _ := msg["allMonitors"].(bool)
		switch t {
		case "command":
			ac := s.getAgentByID(target)
			if ac == nil {
				_ = c.writeJSON(map[string]interface{}{"type": "output", "data": "No agent connected", "success": false})
				continue
			}
			_ = s.sendToAgent(ac, protocol.Message{Type: protocol.TypeCommand, Cmd: cmd})
		case "screenshot_request":
			ac := s.getAgentByID(target)
			if ac == nil {
				continue
			}
			_ = s.sendToAgent(ac, protocol.Message{Type: protocol.TypeScreenshotRequest, Quality: quality, Monitor: monitor, AllMonitors: allMonitors})
		case "ping":
			ac := s.getAgentByID(target)
			if ac != nil {
				ac.pingSentMu.Lock()
				ac.pingSent = time.Now()
				ac.pingSentMu.Unlock()
				_ = s.sendToAgent(ac, protocol.Message{Type: protocol.TypePing})
			}
			_ = c.writeJSON(map[string]interface{}{"type": "pong"})
		case "filelist":
			path, _ := msg["path"].(string)
			ac := s.getAgentByID(target)
			if ac != nil {
				_ = s.sendToAgent(ac, protocol.Message{Type: protocol.TypeCommand, Cmd: "list-directory " + path})
			}
		case "disconnect":
			ac := s.getAgentByID(target)
			if ac == nil {
				_ = c.writeJSON(map[string]interface{}{"type": "output", "data": "No agent selected", "success": false})
				continue
			}
			s.disconnectAgent(ac.id)
		default:
			fmt.Printf("[ws] unknown type %q\n", t)
		}
	}
}
