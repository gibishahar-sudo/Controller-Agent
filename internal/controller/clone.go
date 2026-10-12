package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Auto-clone (v1.48+): POST /api/clone {ip, username, password} runs the
// version-pinned Agent-Setup EncodedCommand ON the target LAN PC via remote
// scheduled-task (primary) or WMI Win32_Process.Create (fallback), then polls
// until the new agent dials home. LAN-only on purpose: public IPs are
// rejected so the controller can't be used as an outbound attack relay.

type cloneReq struct {
	IP       string `json:"ip"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func isPrivateV4(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	if ip4.IsLoopback() || ip4.IsLinkLocalUnicast() {
		return true
	}
	switch {
	case ip4[0] == 10:
		return true
	case ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31:
		return true
	case ip4[0] == 192 && ip4[1] == 168:
		return true
	}
	return false
}

func runCmdTimeout(d time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	c := exec.CommandContext(ctx, name, args...)
	out, err := c.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return string(out), fmt.Errorf("timed out after %s", d)
	}
	if err != nil {
		return string(out), fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// remoteLaunch runs installB64 on target via schtasks (primary) then WMI.
// installB64 is the base64 payload from installCommand (no quotes/spaces).
func remoteLaunch(ip, user, pass, installB64 string) (string, error) {
	tr := "powershell -WindowStyle Hidden -EncodedCommand " + installB64
	// --- Primary: remote scheduled task (SMB+RPC only, no WinRM needed) ---
	mk := []string{"/s", ip, "/u", user, "/p", pass,
		"/create", "/tn", "RMMClone", "/tr", tr,
		"/sc", "ONCE", "/st", "00:00", "/f", "/ru", "SYSTEM"}
	if out, err := runCmdTimeout(25*time.Second, "schtasks", mk...); err == nil {
		_, _ = runCmdTimeout(25*time.Second, "schtasks", "/s", ip, "/u", user, "/p", pass, "/run", "/tn", "RMMClone")
		time.Sleep(3 * time.Second)
		_, _ = runCmdTimeout(15*time.Second, "schtasks", "/s", ip, "/u", user, "/p", pass, "/delete", "/tn", "RMMClone", "/f")
		return "schtasks RMMClone created+run on " + ip, nil
	} else {
		lastErr := fmt.Sprintf("schtasks: %v", err)
		_ = out
		// --- Fallback: WMI Win32_Process.Create via powershell ---
		psUser := strings.ReplaceAll(user, "'", "''")
		psPass := strings.ReplaceAll(pass, "'", "''")
		psCmd := strings.ReplaceAll("powershell -WindowStyle Hidden -EncodedCommand "+installB64, `"`, "`\"")
		script := "$ErrorActionPreference='Stop'\n" +
			"$sec=ConvertTo-SecureString '" + psPass + "' -AsPlainText -Force\n" +
			"$cred=New-Object System.Management.Automation.PSCredential('" + psUser + "',$sec)\n" +
			"$r=Invoke-WmiMethod -ComputerName '" + ip + "' -Credential $cred -Class Win32_Process -Name Create -ArgumentList '" + psCmd + "'\n" +
			"'WMI pid='+$r.ProcessId\n"
		dir := os.TempDir()
		fp := filepath.Join(dir, fmt.Sprintf("rmmclone-%d.ps1", time.Now().UnixNano()))
		if err := os.WriteFile(fp, []byte(script), 0600); err != nil {
			return "", fmt.Errorf("%s; wmi stage failed: %v", lastErr, err)
		}
		defer os.Remove(fp)
		out2, err2 := runCmdTimeout(40*time.Second, "powershell.exe",
			"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", fp)
		if err2 != nil {
			return "", fmt.Errorf("%s; wmi: %v %s", lastErr, err2, strings.TrimSpace(out2))
		}
		return "wmi Win32_Process.Create on " + ip + " (" + strings.TrimSpace(out2) + ")", nil
	}
}

func (s *Server) waitAgentIP(ip string, d time.Duration) bool {
	dead := time.Now().Add(d)
	for time.Now().Before(dead) {
		for have := range s.agentIPs() {
			if have == ip {
				return true
			}
		}
		time.Sleep(2 * time.Second)
	}
	return false
}

func (s *Server) handleClone(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req cloneReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&req); err != nil {
		http.Error(w, "bad json: need {\"ip\",\"username\",\"password\"}", http.StatusBadRequest)
		return
	}
	ip := strings.TrimSpace(req.IP)
	user := strings.TrimSpace(req.Username)
	pass := req.Password
	parsed := net.ParseIP(ip)
	if parsed == nil {
		http.Error(w, "bad ip", http.StatusBadRequest)
		return
	}
	if runtime.GOOS != "windows" {
		http.Error(w, "auto-clone needs a Windows controller (schtasks/wmi)", http.StatusBadRequest)
		return
	}
	if !isPrivateV4(parsed) {
		http.Error(w, "clone is LAN-only (RFC1918); refusing public ip", http.StatusForbidden)
		return
	}
	if user == "" || pass == "" {
		http.Error(w, "username + password required (admin on target)", http.StatusBadRequest)
		return
	}
	if s.agentIPs()[parsed.String()] {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "already", "ip": parsed.String(),
			"detail": "agent already dialed in from this ip",
		})
		return
	}
	cmd, err := installCommand()
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	const pfx = "powershell -WindowStyle Hidden -EncodedCommand "
	if !strings.HasPrefix(cmd, pfx) {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "install-cmd shape changed"})
		return
	}
	b64 := strings.TrimSpace(strings.TrimPrefix(cmd, pfx))
	log.Printf("[clone] auto-clone to %s as %s", parsed.String(), user)
	detail, err := remoteLaunch(parsed.String(), user, pass, b64)
	// Never log the password.
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error": fmt.Sprintf("remote launch failed: %v. Check: same subnet, admin user/pass on target, File+Printer Sharing on, allow 445/WMI firewall, no Guest-WiFi isolation.", err),
		})
		return
	}
	if s.waitAgentIP(parsed.String(), 75*time.Second) {
		s.broadcastWS(map[string]interface{}{"type": "output",
			"data": fmt.Sprintf("clone %s: agent online (%s)", parsed.String(), detail), "success": true})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status": "online", "ip": parsed.String(), "detail": detail,
		})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "launched", "ip": parsed.String(),
		"detail": detail + "; installer started but agent not seen yet (60-75s) — watch Connections, then re-Discover",
	})
}
