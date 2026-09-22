package controller

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
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
	// /api/file-op manages controller-local files (the Files tab local
	// pane): mkdir, delete, move/rename, write (small content, 1MB cap).
	mux.HandleFunc("/api/file-op", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Op      string `json:"op"`
			Path    string `json:"path"`
			Dst     string `json:"dst"`
			Content string `json:"content"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<20)).Decode(&req); err != nil {
			http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
			return
		}
		fail := func(msg string) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
		}
		if req.Path == "" {
			fail("path required")
			return
		}
		// Refuse drive/filesystem roots for destructive ops.
		isRoot := len(req.Path) <= 3 || req.Path == "/" || req.Path == "\\"
		switch req.Op {
		case "mkdir":
			if err := os.MkdirAll(req.Path, 0755); err != nil {
				fail(err.Error())
				return
			}
		case "delete":
			if isRoot {
				fail("refusing to delete a drive root")
				return
			}
			if err := os.RemoveAll(req.Path); err != nil {
				fail(err.Error())
				return
			}
		case "move", "rename":
			if req.Dst == "" {
				fail("dst required")
				return
			}
			if isRoot {
				fail("refusing to move a drive root")
				return
			}
			_ = os.MkdirAll(filepath.Dir(req.Dst), 0755)
			if err := os.Rename(req.Path, req.Dst); err != nil {
				fail(err.Error())
				return
			}
		case "write":
			if len(req.Content) > 1024*1024 {
				fail("content over 1MB cap (use upload for big files)")
				return
			}
			_ = os.MkdirAll(filepath.Dir(req.Path), 0755)
			if err := os.WriteFile(req.Path, []byte(req.Content), 0644); err != nil {
				fail(err.Error())
				return
			}
		default:
			fail("unknown op (mkdir|delete|move|write)")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "path": req.Path})
	})
	// /api/file-slice reads one slice of a controller-local file as base64
	// (the upload path: the browser pages a local file through the
	// controller to the agent without ever holding it whole server-side).
	mux.HandleFunc("/api/file-slice", func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Query().Get("path")
		if p == "" {
			http.Error(w, "path required", http.StatusBadRequest)
			return
		}
		var offset int64
		var length int64 = 512 * 1024
		if v := r.URL.Query().Get("offset"); v != "" {
			fmt.Sscanf(v, "%d", &offset)
		}
		if v := r.URL.Query().Get("len"); v != "" {
			fmt.Sscanf(v, "%d", &length)
		}
		if length <= 0 || length > 1024*1024 {
			length = 512 * 1024
		}
		if offset < 0 {
			offset = 0
		}
		f, err := os.Open(p)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if st.IsDir() {
			http.Error(w, "not a file", http.StatusBadRequest)
			return
		}
		buf := make([]byte, length)
		n, _ := f.ReadAt(buf, offset)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"path": p, "size": st.Size(), "offset": offset, "len": n,
			"data": base64.StdEncoding.EncodeToString(buf[:n]),
		})
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
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"connected": false, "count": len(s.Agents()), "controllerVersion": version.Version, "certDaysLeft": s.certDaysLeft, "house": s.house, "peers": s.peerCount(), "autoUpdate": s.autoUpdate.Load()})
			return
		}
		s.latencyMu.RLock()
		lat := s.latency[ac.id]
		s.latencyMu.RUnlock()
		online := true
		if strings.HasPrefix(ac.id, "agent-ntfy-") || strings.HasPrefix(ac.id, "agent-mqtt-") {
			online = time.Since(ac.seen()) <= ntfyStaleAfter
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"connected": true, "id": ac.id, "hostname": ac.hostname, "user": ac.user,
			"remote": ac.remote(), "latency": lat, "count": len(s.Agents()),
			"controllerVersion": version.Version,
			"certDaysLeft": s.certDaysLeft,
			"online": online,
			"house": s.house,
			"peers": s.peerCount(),
			"autoUpdate": s.autoUpdate.Load(),
		})
	})
	mux.HandleFunc("/api/agents", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"agents": s.Agents()})
	})
	// Live remote-audio stream health (played/dropped/concealed/gaps) for
	// the Audio tab readout — dropouts are diagnosed, not guessed.
	mux.HandleFunc("/api/audio-stats", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "GET only", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(audioStatsSnapshot())
	})
	// Local playback devices: endpoints on THIS controller PC (the
	// operator's machine), never the remote agent's. The Audio tab's
	// "Local playback" card uses these; remote lists still come from
	// the agent via list-audio-endpoints.
	mux.HandleFunc("/api/local-audio-devices", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "GET only", http.StatusMethodNotAllowed)
			return
		}
		devs, err := ListLocalAudioDevices()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if devs == nil {
			devs = []LocalAudioDevice{}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"devices": devs})
	})
	mux.HandleFunc("/api/local-audio-map", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "GET only", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"map": loadLocalAudioMap()})
	})
	mux.HandleFunc("/api/local-audio-choice", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "GET only", http.StatusMethodNotAllowed)
			return
		}
		m := loadLocalAudioMap()
		id := r.URL.Query().Get("agentId")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"device": choiceForAgent(m, id), "volume": volumeForAgent(m, id), "clarity": clarityForAgent(m, id)})
	})
	mux.HandleFunc("/api/local-audio-select", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			AgentID string `json:"agentId"`
			Device  string `json:"device"`
			Volume  int    `json:"volume"`  // -1/absent = unchanged
			Clarity *bool  `json:"clarity"` // nil = unchanged
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&req); err != nil {
			http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
			return
		}
		// Contract: the UI always sends volume 0-100 explicitly.
		// Out-of-range (e.g. -1) means unchanged.
		vol := req.Volume
		if vol < 0 || vol > 100 {
			vol = -1
		}
		if err := saveLocalAudioChoice(req.AgentID, req.Device, vol, req.Clarity); err != nil {
			http.Error(w, "save failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "saved", "agentId": req.AgentID, "device": req.Device})
	})
	var updateMu sync.Mutex
	var updateCache map[string]interface{}
	var updateAt time.Time
	mux.HandleFunc("/api/update-check", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "GET only", http.StatusMethodNotAllowed)
			return
		}
		updateMu.Lock()
		cached, at := updateCache, updateAt
		updateMu.Unlock()
		if cached != nil && time.Since(at) < time.Hour {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(cached)
			return
		}
		out := map[string]interface{}{"current": version.Version, "latest": "", "update": false}
		client := &http.Client{Timeout: 10 * time.Second}
		// The repo is private, so the API needs a token. Look for one in
		// github_token.txt next to the exe (or CWD); without it the badge
		// simply stays hidden — no error, no leak.
		token := ""
		if exe, err := os.Executable(); err == nil {
			if b, err := os.ReadFile(filepath.Join(filepath.Dir(exe), "github_token.txt")); err == nil {
				token = strings.TrimSpace(string(b))
			}
		}
		if token == "" {
			if b, err := os.ReadFile("github_token.txt"); err == nil {
				token = strings.TrimSpace(string(b))
			}
		}
		if token == "" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(out)
			return
		}
		// NOTE: /releases/latest 404s on this repo; newest-first list is reliable.
		if req, err := http.NewRequest("GET", "https://api.github.com/repos/gibishahar-sudo/Controller-/releases?per_page=1", nil); err != nil {
			log.Printf("[update-check] request: %v", err)
		} else {
			req.Header.Set("User-Agent", "rmm-controller")
			req.Header.Set("Accept", "application/vnd.github.v3+json")
			req.Header.Set("Authorization", "token "+token)
			resp, err := client.Do(req)
			if err != nil {
				log.Printf("[update-check] fetch: %v", err)
			} else if resp.StatusCode != 200 {
				log.Printf("[update-check] http %d", resp.StatusCode)
				resp.Body.Close()
			} else {
			var rels []struct {
				TagName string `json:"tag_name"`
				HTMLURL string `json:"html_url"`
				Draft   bool   `json:"draft"`
			}
			if json.NewDecoder(resp.Body).Decode(&rels) == nil {
				resp.Body.Close()
				if len(rels) > 0 && !rels[0].Draft {
					latest := strings.TrimPrefix(strings.TrimSpace(rels[0].TagName), "v")
					out["latest"] = rels[0].TagName
					out["url"] = rels[0].HTMLURL
					out["update"] = latest != "" && latest != version.Version
				}
		} else {
			resp.Body.Close()
		}
		}
		}
		updateMu.Lock()
		updateCache, updateAt = out, time.Now()
		updateMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("/api/agent-update", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Target string `json:"target"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&req); err != nil {
			http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
			return
		}
		ac := s.getAgentByID(req.Target)
		if ac == nil {
			http.Error(w, "no agent selected", http.StatusServiceUnavailable)
			return
		}
		bin := s.bundledAgentBin()
		if bin == "" {
			http.Error(w, "no bundled agent binary next to controller (reinstall Controller-Setup)", http.StatusInternalServerError)
			return
		}
		go s.pushAgentUpdate(ac, bin)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "pushing", "agent": ac.id})
	})
	mux.HandleFunc("/api/agent-update-all", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		bin := s.bundledAgentBin()
		if bin == "" {
			http.Error(w, "no bundled agent binary next to controller (reinstall Controller-Setup)", http.StatusInternalServerError)
			return
		}
		go s.pushAgentUpdateAll(bin)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "pushing all outdated"})
	})
	mux.HandleFunc("/api/auto-update", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"enabled": s.autoUpdate.Load()})
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "GET or POST only", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Enabled *bool `json:"enabled"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&req); err != nil || req.Enabled == nil {
			http.Error(w, "bad json: need {\"enabled\":true|false}", http.StatusBadRequest)
			return
		}
		s.autoUpdate.Store(*req.Enabled)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"enabled": s.autoUpdate.Load()})
	})
	mux.HandleFunc("/api/agent-auth", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"enforced": s.enforceAuth.Load(), "hasToken": s.agentToken != "", "token": s.agentToken,
			})
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "GET or POST only", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Enforced *bool `json:"enforced"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&req); err != nil || req.Enforced == nil {
			http.Error(w, "bad json: need {\"enforced\":true|false}", http.StatusBadRequest)
			return
		}
		s.enforceAuth.Store(*req.Enforced)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"enforced": s.enforceAuth.Load()})
	})
	mux.HandleFunc("/api/forget-agent", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			ID string `json:"id"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&req); err != nil {
			http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
			return
		}
		s.removeAgent(req.ID)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "forgotten", "id": req.ID})
	})
	mux.HandleFunc("/api/reconnect-relays", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		s.resetMQTTBus()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "redialing"})
	})
	mux.HandleFunc("/api/local-audio-stop", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		stopAudioPlayer()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "stopped"})
	})
	mux.HandleFunc("/api/local-audio-test", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Device string `json:"device"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&req); err != nil {
			http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
			return
		}
		msg, err := TestLocalAudio(req.Device)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "message": msg})
	})

	s.httpSrv = &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	// Bind synchronously so a clash is detected NOW, not silently later.
	// If the configured port is taken by another controller, fall back to
	// an ephemeral port: otherwise the native window / auto-opened browser
	// would show the OTHER controller's (empty) agent list while this
	// process's console reports agents connecting (split-brain UI).
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		host, _, splitErr := net.SplitHostPort(addr)
		if splitErr != nil || host == "" {
			host = "127.0.0.1"
		}
		log.Printf("[http] %s in use, falling back to an ephemeral port", addr)
		ln, err = net.Listen("tcp", net.JoinHostPort(host, "0"))
		if err != nil {
			log.Printf("[http] UI disabled: %v", err)
			s.httpAddr = ""
			return
		}
	}
	s.httpAddr = ln.Addr().String()
	go func() {
		log.Printf("[http] UI at http://%s/", s.httpAddr)
		if err := s.httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
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
			scale := 0.0
			if f, ok := msg["scale"].(float64); ok {
				scale = f
			}
			tiles, _ := msg["tiles"].(bool)
			_ = s.sendToAgent(ac, protocol.Message{Type: protocol.TypeScreenshotRequest, Quality: quality, Monitor: monitor, AllMonitors: allMonitors, Scale: scale, Tiles: tiles})
		case "file-dl", "file-dl-more":
			path, _ := msg["path"].(string)
			ac := s.getAgentByID(target)
			if ac == nil || path == "" {
				continue
			}
			from := 0
			if f, ok := msg["fromSeq"].(float64); ok && f > 0 {
				from = int(f)
			}
			_ = s.sendToAgent(ac, protocol.Message{Type: protocol.TypeFileDlReq, FilePath: path, FileFrom: from, FileChunk: fileChunkRaw(ac)})
		case "file-ul-begin":
			path, _ := msg["path"].(string)
			sha, _ := msg["sha"].(string)
			ac := s.getAgentByID(target)
			if ac == nil || path == "" {
				continue
			}
			var size int64
			if f, ok := msg["size"].(float64); ok {
				size = int64(f)
			}
			total := 0
			if f, ok := msg["total"].(float64); ok {
				total = int(f)
			}
			_ = s.sendToAgent(ac, protocol.Message{Type: protocol.TypeFileUlBegin, FilePath: path, FileSize: size, FileSHA: sha, FileTotal: total, FileChunk: fileChunkRaw(ac)})
		case "file-ul-chunk":
			data, _ := msg["data"].(string)
			ac := s.getAgentByID(target)
			if ac == nil || data == "" {
				continue
			}
			seq := 0
			if f, ok := msg["seq"].(float64); ok {
				seq = int(f)
			}
			_ = s.sendToAgent(ac, protocol.Message{Type: protocol.TypeFileUlChunk, FileSeq: seq, Data: data, FileChunk: fileChunkRaw(ac)})
		case "file-dl-to":
			remote, _ := msg["remotePath"].(string)
			local, _ := msg["localPath"].(string)
			ac := s.getAgentByID(target)
			if ac == nil || remote == "" || local == "" {
				continue
			}
			s.startDlTo(ac, remote, local)
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
