package commands

import (
	"encoding/json"
	"fmt"
	"runtime"
	"strconv"
	"strings"
)

// Audio controls on Windows without any extra installs.
//
// Master volume uses winmm.dll waveOutGetVolume/waveOutSetVolume (simple
// P/Invoke, verified working). Mic mute uses the Core Audio MMDevice API on
// the default capture endpoint; on systems where COM activation is blocked
// it returns a clear error instead of raw COM spew.

const winmmSnippet = `
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class RmmWinmm {
  [DllImport("winmm.dll")] public static extern int waveOutGetVolume(IntPtr hwo, out uint v);
  [DllImport("winmm.dll")] public static extern int waveOutSetVolume(IntPtr hwo, uint v);
}
'@
`

const coreAudioSnippet = `
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
[ComImport, Guid("BCDE0395-E52F-467C-8E3D-C4579291692E")]
public class RmmMMEnumerator { }
[Guid("A95664D2-9614-4F35-A746-DE8DB63617E6"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
public interface RmmMMEnum {
  int EnumAudioEndpoints(int dataFlow, int dwStateMask, out IntPtr ppDevices);
  int GetDefaultAudioEndpoint(int dataFlow, int role, out IntPtr ppEndpoint);
}
[Guid("D666063F-1587-4E43-81F1-B948E807363F"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
public interface RmmMMDevice {
  int Activate(ref Guid iid, int dwClsCtx, IntPtr pActivationParams, [MarshalAs(UnmanagedType.IUnknown)] out object ppInterface);
}
[Guid("5CDF2C82-841E-4546-9722-0CF74078229A"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
public interface RmmEndpointVolume {
  int RegisterControlChangeNotify(IntPtr pNotify);
  int UnregisterControlChangeNotify(IntPtr pNotify);
  int GetChannelCount(out uint pnChannelCount);
  int SetMasterVolumeLevel(float fLevelDB, ref Guid pguidEventContext);
  int SetMasterVolumeLevelScalar(float fLevel, ref Guid pguidEventContext);
  int GetMasterVolumeLevel(out float pfLevelDB);
  int GetMasterVolumeLevelScalar(out float pfLevel);
  int SetChannelVolumeLevel(uint nChannel, float fLevelDB, ref Guid pguidEventContext);
  int SetChannelVolumeLevelScalar(uint nChannel, float fLevel, ref Guid pguidEventContext);
  int GetChannelVolumeLevel(uint nChannel, out float pfLevelDB);
  int GetChannelVolumeLevelScalar(uint nChannel, out float pfLevel);
  int SetMute([MarshalAs(UnmanagedType.Bool)] bool bMute, ref Guid pguidEventContext);
  int GetMute(out bool pbMute);
  int GetVolumeStepInfo(out uint pnStep, out uint pnStepCount);
  int VolumeStepUp(ref Guid pguidEventContext);
  int VolumeStepDown(ref Guid pguidEventContext);
  int QueryHardwareSupport(out uint pdwHardwareSupportMask);
  int GetVolumeRange(out float pflVolumeMindB, out float pflVolumeMaxdB, out float pflVolumeIncrementdB);
}
public class RmmMic {
  static RmmEndpointVolume CaptureEndpoint() {
    var enumerator = (RmmMMEnum)new RmmMMEnumerator();
    IntPtr ep;
    int hr = enumerator.GetDefaultAudioEndpoint(1, 0, out ep);
    if (hr != 0 || ep == IntPtr.Zero) throw new Exception("no default capture endpoint (0x"+hr.ToString("X8")+")");
    Guid iid = typeof(RmmEndpointVolume).GUID;
    object tmp;
    var dev = (RmmMMDevice)System.Runtime.InteropServices.Marshal.GetObjectForIUnknown(ep);
    hr = dev.Activate(ref iid, 1, IntPtr.Zero, out tmp);
    if (hr != 0 || tmp == null) throw new Exception("endpoint Activate failed (0x"+hr.ToString("X8")+")");
    return (RmmEndpointVolume)tmp;
  }
  public static void SetMicMute(bool mute) {
    Guid ctx = Guid.Empty;
    CaptureEndpoint().SetMute(mute, ref ctx);
  }
}
[Guid("C02216F6-8C67-4B5B-9D00-D008E73E0064"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
public interface RmmMeter {
  int GetPeakValue(out float pfPeak);
  int GetMeteringChannelCount(out uint pnChannelCount);
  int GetChannelsPeakValues(uint u32ChannelCount, [In, Out] float[] afPeakValues);
  int QueryHardwareSupport(out uint pdwHardwareSupportMask);
}
public class RmmLevel {
  static RmmMeter Endpoint(int flow) {
    var enumerator = (RmmMMEnum)new RmmMMEnumerator();
    IntPtr ep;
    int hr = enumerator.GetDefaultAudioEndpoint(flow, 0, out ep);
    if (hr != 0 || ep == IntPtr.Zero) throw new Exception("no default endpoint (0x"+hr.ToString("X8")+")");
    Guid iid = typeof(RmmMeter).GUID;
    object tmp;
    var dev = (RmmMMDevice)System.Runtime.InteropServices.Marshal.GetObjectForIUnknown(ep);
    hr = dev.Activate(ref iid, 1, IntPtr.Zero, out tmp);
    if (hr != 0 || tmp == null) throw new Exception("meter Activate failed (0x"+hr.ToString("X8")+")");
    return (RmmMeter)tmp;
  }
  public static float MasterPeak() {
    float v; Endpoint(0).GetPeakValue(out v); return v;
  }
  public static float MicPeak() {
    float v; Endpoint(1).GetPeakValue(out v); return v;
  }
}
'@
`

func getAudioDevices() (string, error) {
	if runtime.GOOS == "windows" {
		// Endpoints (headphones, speakers, mics) via PnP — this is what
		// actually shows plugged-in headphones, unlike Win32_SoundDevice
		// which only lists sound cards. No COM needed.
		out, err := execPS("Get-PnpDevice -Class AudioEndpoint | Select-Object FriendlyName,Status,InstanceId | Format-Table -AutoSize")
		if err != nil {
			return "", fmt.Errorf("audio devices unavailable (%s)", firstLine(out))
		}
		cards, _ := execPS("Get-CimInstance Win32_SoundDevice | Select-Object Name,Status | Format-Table -AutoSize")
		return "== Endpoints (headphones/speakers/mics) ==\n" + out + "\n== Sound cards ==\n" + cards, nil
	}
	return shellExec("aplay -l 2>/dev/null || pactl list short sinks 2>/dev/null || echo 'no audio tools'")
}

// listAudioEndpoints returns the PnP audio endpoints as JSON for the UI
// dropdowns: [{"name":..,"status":"OK","id":"SWD\\MMDEVAPI\\{0.0.0...}...",
// "kind":"output"}]. kind comes from the MMDEVAPI id: {0.0.0.*} = render
// (speakers/headphones), {0.0.1.*} = capture (mics).
func listAudioEndpoints() (string, error) {
	if runtime.GOOS != "windows" {
		return "", fmt.Errorf("not supported on %s", runtime.GOOS)
	}
	out, err := execPS(`Get-PnpDevice -Class AudioEndpoint | Select-Object FriendlyName,Status,InstanceId | ConvertTo-Json -Compress`)
	if err != nil {
		return "", fmt.Errorf("audio endpoints unavailable (%s)", firstLine(out))
	}
	trimmed := strings.TrimSpace(out)
	if trimmed == "" || trimmed == "null" {
		return "[]", nil
	}
	var raw []struct {
		FriendlyName string `json:"FriendlyName"`
		Status       string `json:"Status"`
		InstanceId   string `json:"InstanceId"`
	}
	if err := json.Unmarshal([]byte(trimmed), &raw); err != nil {
		// Single object instead of array (one endpoint): wrap it.
		var one struct {
			FriendlyName string `json:"FriendlyName"`
			Status       string `json:"Status"`
			InstanceId   string `json:"InstanceId"`
		}
		if err2 := json.Unmarshal([]byte(trimmed), &one); err2 != nil {
			return "", fmt.Errorf("parse audio endpoints: %v", err2)
		}
		raw = []struct {
			FriendlyName string `json:"FriendlyName"`
			Status       string `json:"Status"`
			InstanceId   string `json:"InstanceId"`
		}{one}
	}
	type entry struct {
		Name   string `json:"name"`
		Status string `json:"status"`
		ID     string `json:"id"`
		Kind   string `json:"kind"`
	}
	entries := make([]entry, 0, len(raw))
	for _, r := range raw {
		if r.FriendlyName == "" {
			continue
		}
		kind := "unknown"
		if strings.Contains(r.InstanceId, "{0.0.0.") {
			kind = "output"
		} else if strings.Contains(r.InstanceId, "{0.0.1.") {
			kind = "input"
		}
		entries = append(entries, entry{Name: r.FriendlyName, Status: r.Status, ID: r.InstanceId, Kind: kind})
	}
	b, _ := json.Marshal(entries)
	return string(b), nil
}

func getAudioVolume() (string, error) {
	if runtime.GOOS != "windows" {
		return "", fmt.Errorf("not supported on %s", runtime.GOOS)
	}
	out, err := execPS(winmmSnippet + `$v = [uint32]0; [RmmWinmm]::waveOutGetVolume([IntPtr]::Zero, [ref]$v) | Out-Null; [int](($v -band 0xFFFF) / 655.35)`)
	if err != nil {
		return "", fmt.Errorf("audio volume unavailable (%s)", firstLine(out))
	}
	pct, ferr := strconv.Atoi(strings.TrimSpace(out))
	if ferr != nil {
		return strings.TrimSpace(out), nil
	}
	return fmt.Sprintf("%d%%", pct), nil
}

func setAudioVolume(arg string) (string, error) {
	arg = strings.TrimSpace(strings.TrimSuffix(arg, "%"))
	if arg == "" {
		return getAudioVolume()
	}
	var pct int
	if _, err := fmt.Sscanf(arg, "%d", &pct); err != nil || pct < 0 || pct > 100 {
		return "", fmt.Errorf("usage: set-audio-volume <0-100>")
	}
	if runtime.GOOS != "windows" {
		return "", fmt.Errorf("not supported on %s", runtime.GOOS)
	}
	script := fmt.Sprintf(winmmSnippet+`$n = [uint32](%d * 65535 / 100); [RmmWinmm]::waveOutSetVolume([IntPtr]::Zero, ($n -bor ($n -shl 16))) | Out-Null; "ok"`, pct)
	out, err := execPS(script)
	if err != nil {
		return "", fmt.Errorf("set volume failed (%s)", firstLine(out))
	}
	return fmt.Sprintf("volume %d%%", pct), nil
}

func setMicMute(arg string) (string, error) {
	arg = strings.ToLower(strings.TrimSpace(arg))
	var mute bool
	switch arg {
	case "on", "1", "true", "mute":
		mute = true
	case "off", "0", "false", "unmute":
		mute = false
	default:
		return "", fmt.Errorf("usage: set-mic-mute <on|off>")
	}
	if runtime.GOOS != "windows" {
		return "", fmt.Errorf("not supported on %s", runtime.GOOS)
	}
	muteStr := "$false"
	if mute {
		muteStr = "$true"
	}
	out, err := execPS(coreAudioSnippet + fmt.Sprintf("[RmmMic]::SetMicMute(%s)", muteStr))
	if err != nil {
		return "", fmt.Errorf("mic mute unavailable on this system (%s)", firstLine(out))
	}
	if mute {
		return "mic muted", nil
	}
	return "mic unmuted", nil
}

func setDefaultAudioDevice(arg string) (string, error) {
	if id := strings.TrimSpace(arg); id == "" {
		return "", fmt.Errorf("usage: set-default-audio-device <id|name>")
	} else {
		arg = id
	}
	if runtime.GOOS != "windows" {
		return "", fmt.Errorf("not supported on %s", runtime.GOOS)
	}
	// Error-as-data convention: failures print RMM_ERROR:<short message>
	// and exit 0, so PowerShell's "<script> : <message>" error rendering
	// can never leak the whole script into command output.
	script := fmt.Sprintf(`
$dev = Get-PnpDevice -Class AudioEndpoint | Where-Object { $_.InstanceId -eq %[1]q -or $_.FriendlyName -eq %[1]q } | Select-Object -First 1
if (-not $dev) { Write-Output "RMM_ERROR:device not found: %[1]s"; exit 0 }

# Use SoundVolumeView or nircmd if present, or fallback to registry / MMDevice
$nircmd = Get-Command nircmd -ErrorAction SilentlyContinue
if ($nircmd) {
  & nircmd setdefaultsounddevice $dev.FriendlyName 1
  & nircmd setdefaultsounddevice $dev.FriendlyName 2
  Write-Output "default set to $($dev.FriendlyName) via nircmd"
  exit 0
}

$svv = Get-Command SoundVolumeView -ErrorAction SilentlyContinue
if ($svv) {
  & SoundVolumeView.exe /SetDefault $dev.FriendlyName 1
  & SoundVolumeView.exe /SetDefault $dev.FriendlyName 2
  Write-Output "default set to $($dev.FriendlyName) via SoundVolumeView"
  exit 0
}

# Fallback: update MMDevices registry default endpoints or user preference
try {
  # Write MMDevices default role keys if accessible
  Write-Output "RMM_ERROR:nircmd or SoundVolumeView not found in PATH. To switch audio, install nircmd (https://www.nirsoft.net/utils/nircmd.html) and add it to PATH."
  exit 0
} catch {
  Write-Output ("RMM_ERROR:" + $_.Exception.Message)
  exit 0
}
`, arg)
	out, err := execPS(script)
	if err != nil {
		return "", fmt.Errorf("audio switch failed (%s)", firstLine(out))
	}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if s := strings.TrimSpace(line); strings.HasPrefix(s, "RMM_ERROR:") {
			return "", fmt.Errorf("%s", strings.TrimSpace(strings.TrimPrefix(s, "RMM_ERROR:")))
		}
	}
	return strings.TrimSpace(out), nil
}

// getAudioLevel samples live peak levels (0.0-1.0) for the default render
// (speakers) and capture (mic) endpoints. Returns JSON for the UI meter:
// {"master":0.42,"mic":0.0}. Needs nothing installed; on systems where COM
// activation is blocked it returns a clear error.
func getAudioLevel() (string, error) {
	if runtime.GOOS != "windows" {
		return "", fmt.Errorf("not supported on %s", runtime.GOOS)
	}
	out, err := execPS(coreAudioSnippet + "[RmmLevel]::MasterPeak()\n[RmmLevel]::MicPeak()")
	if err != nil {
		return "", fmt.Errorf("audio level unavailable on this system (%s)", firstLine(out))
	}
	lines := strings.Fields(strings.TrimSpace(out))
	if len(lines) < 2 {
		return "", fmt.Errorf("audio level unavailable on this system (%s)", firstLine(out))
	}
	master, err1 := strconv.ParseFloat(lines[0], 64)
	mic, err2 := strconv.ParseFloat(lines[1], 64)
	if err1 != nil || err2 != nil {
		return "", fmt.Errorf("audio level unavailable on this system (%s)", firstLine(out))
	}
	if master < 0 {
		master = 0
	}
	if master > 1 {
		master = 1
	}
	if mic < 0 {
		mic = 0
	}
	if mic > 1 {
		mic = 1
	}
	return fmt.Sprintf(`{"master":%.3f,"mic":%.3f}`, master, mic), nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "\n"); i != -1 {
		s = s[:i]
	}
	if len(s) > 160 {
		s = s[:160] + "..."
	}
	return s
}
