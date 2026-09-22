package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// LocalAudioDevice describes one playback/capture endpoint on THIS machine
// (the controller PC the operator sits at) — never the remote agent's.
type LocalAudioDevice struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	ID     string `json:"id"`
	Kind   string `json:"kind"` // output | input | unknown
}

// ListLocalAudioDevices enumerates the controller PC's own audio endpoints
// via PnP (same source as the agent's list-audio-endpoints, but executed
// locally). No COM needed.
func ListLocalAudioDevices() ([]LocalAudioDevice, error) {
	if runtime.GOOS != "windows" {
		return nil, fmt.Errorf("local audio devices not supported on %s", runtime.GOOS)
	}
	out, err := runLocalPS(`Get-PnpDevice -Class AudioEndpoint | Select-Object FriendlyName,Status,InstanceId | ConvertTo-Json -Compress`, 20*time.Second)
	if err != nil {
		return nil, err
	}
	trimmed := strings.TrimSpace(out)
	if trimmed == "" || trimmed == "null" {
		return []LocalAudioDevice{}, nil
	}
	var raw []struct {
		FriendlyName string `json:"FriendlyName"`
		Status       string `json:"Status"`
		InstanceId   string `json:"InstanceId"`
	}
	if err := json.Unmarshal([]byte(trimmed), &raw); err != nil {
		var one struct {
			FriendlyName string `json:"FriendlyName"`
			Status       string `json:"Status"`
			InstanceId   string `json:"InstanceId"`
		}
		if err2 := json.Unmarshal([]byte(trimmed), &one); err2 != nil {
			return nil, fmt.Errorf("parse local audio endpoints: %v", err2)
		}
		raw = append(raw, one)
	}
	devs := make([]LocalAudioDevice, 0, len(raw))
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
		devs = append(devs, LocalAudioDevice{Name: r.FriendlyName, Status: r.Status, ID: r.InstanceId, Kind: kind})
	}
	return devs, nil
}

// waveOutToneSnippet renders a sine beep on a chosen waveOut device (by
// fuzzy name match) so the test tone really comes out of the selected
// headphones/speakers — not just the Windows default. winmm waveOut lets us
// open a specific device index, unlike SystemSounds which is default-only.
const waveOutToneSnippet = `
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Threading;
public class RmmTone {
  const int WAVE_MAPPER = -1;
  [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Auto)]
  struct WAVEOUTCAPS {
    public ushort wMid; public ushort wPid; public uint vDriverVersion;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst=32)] public string szPname;
    public uint dwFormats; public ushort wChannels; public ushort wReserved1; public uint dwSupport;
  }
  [StructLayout(LayoutKind.Sequential)]
  struct WAVEFORMATEX {
    public ushort wFormatTag; public ushort nChannels; public uint nSamplesPerSec;
    public uint nAvgBytesPerSec; public ushort nBlockAlign; public ushort wBitsPerSample; public ushort cbSize;
  }
  [StructLayout(LayoutKind.Sequential)]
  struct WAVEHDR {
    public IntPtr lpData; public uint dwBufferLength; public uint dwBytesRecorded;
    public IntPtr dwUser; public uint dwFlags; public uint dwLoops; public IntPtr lpNext; public IntPtr reserved;
  }
  [DllImport("winmm.dll")] static extern int waveOutGetNumDevs();
  [DllImport("winmm.dll", CharSet=CharSet.Auto)] static extern int waveOutGetDevCaps(int uDeviceID, out WAVEOUTCAPS lpCaps, int uSize);
  [DllImport("winmm.dll")] static extern int waveOutOpen(out IntPtr phwo, int uDeviceID, ref WAVEFORMATEX pwfx, IntPtr dwCallback, IntPtr dwInstance, int fdwOpen);
  [DllImport("winmm.dll")] static extern int waveOutPrepareHeader(IntPtr hwo, ref WAVEHDR pwh, int uSize);
  [DllImport("winmm.dll")] static extern int waveOutWrite(IntPtr hwo, ref WAVEHDR pwh, int uSize);
  [DllImport("winmm.dll")] static extern int waveOutUnprepareHeader(IntPtr hwo, ref WAVEHDR pwh, int uSize);
  [DllImport("winmm.dll")] static extern int waveOutClose(IntPtr hwo);
  static string Norm(string s) {
    var sb = new System.Text.StringBuilder();
    foreach (char c in (s ?? "").ToLowerInvariant()) { if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) sb.Append(c); }
    return sb.ToString();
  }
  public static string List() {
    var sb = new System.Text.StringBuilder();
    int n = waveOutGetNumDevs();
    for (int i = 0; i < n; i++) {
      WAVEOUTCAPS c; int sz = Marshal.SizeOf(typeof(WAVEOUTCAPS));
      if (waveOutGetDevCaps(i, out c, sz) == 0) sb.AppendLine(i + "|" + c.szPname);
    }
    return sb.ToString();
  }
  public static string Play(string want, int freq, int ms) {
    int n = waveOutGetNumDevs();
    int dev = WAVE_MAPPER; string devName = "default output";
    string nw = Norm(want);
    if (nw.Length > 0 && n > 0) {
      int best = -1, bestLen = 0; string bestName = "";
      for (int i = 0; i < n; i++) {
        WAVEOUTCAPS c; int sz = Marshal.SizeOf(typeof(WAVEOUTCAPS));
        if (waveOutGetDevCaps(i, out c, sz) != 0) continue;
        string nd = Norm(c.szPname);
        int score = 0;
        if (nw.Contains(nd) && nd.Length > 0) score = nd.Length;
        else if (nd.Contains(nw)) score = nw.Length;
        else {
          int p = 0; while (p < nw.Length && p < nd.Length && nw[p] == nd[p]) p++;
          if (p >= 6) score = p;
        }
        if (score > bestLen) { bestLen = score; best = i; bestName = c.szPname; }
      }
      if (best >= 0) { dev = best; devName = bestName; }
    }
    int rate = 44100, ch = 1, bits = 16;
    int samples = rate * ms / 1000;
    short[] data = new short[samples];
    for (int i = 0; i < samples; i++) {
      double t = (double)i / rate;
      double env = Math.Min(1.0, Math.Min(i / (rate * 0.02), (samples - i) / (rate * 0.05)));
      data[i] = (short)(Math.Sin(2 * Math.PI * freq * t) * 28000 * env);
    }
    WAVEFORMATEX fmt = new WAVEFORMATEX();
    fmt.wFormatTag = 1; fmt.nChannels = (ushort)ch; fmt.nSamplesPerSec = (uint)rate;
    fmt.wBitsPerSample = (ushort)bits; fmt.nBlockAlign = (ushort)(ch * bits / 8);
    fmt.nAvgBytesPerSec = (uint)(rate * ch * bits / 8); fmt.cbSize = 0;
    IntPtr hwo;
    int hr = waveOutOpen(out hwo, dev, ref fmt, IntPtr.Zero, IntPtr.Zero, 0);
    if (hr != 0) throw new Exception("waveOutOpen failed (0x" + hr.ToString("X8") + ")");
    try {
      var handle = GCHandle.Alloc(data, GCHandleType.Pinned);
      try {
        WAVEHDR hdr = new WAVEHDR();
        hdr.lpData = handle.AddrOfPinnedObject();
        hdr.dwBufferLength = (uint)(data.Length * 2);
        int hs = Marshal.SizeOf(typeof(WAVEHDR));
        hr = waveOutPrepareHeader(hwo, ref hdr, hs);
        if (hr != 0) throw new Exception("waveOutPrepareHeader failed (0x" + hr.ToString("X8") + ")");
        hr = waveOutWrite(hwo, ref hdr, hs);
        if (hr != 0) throw new Exception("waveOutWrite failed (0x" + hr.ToString("X8") + ")");
        int waited = 0;
        while ((hdr.dwFlags & 0x1) == 0 && waited < ms + 5000) { Thread.Sleep(50); waited += 50; }
        waveOutUnprepareHeader(hwo, ref hdr, hs);
      } finally { handle.Free(); }
    } finally { waveOutClose(hwo); }
    return "tone " + freq + "Hz " + ms + "ms on [" + devName + "]";
  }
}
'@
`

// TestLocalAudio plays a short tone on THIS controller PC on the selected
// device (fuzzy-matched by name, e.g. your headphones) so the operator can
// verify the local playback path. Falls back to the default output when no
// selection matches.
func TestLocalAudio(selected string) (string, error) {
	if runtime.GOOS != "windows" {
		return "", fmt.Errorf("local audio test not supported on %s", runtime.GOOS)
	}
	script := waveOutToneSnippet + "[RmmTone]::Play('" + psEscape(selected) + "', 440, 700)"
	out, err := runLocalPS(script, 30*time.Second)
	if err != nil {
		return strings.TrimSpace(out), err
	}
	return strings.TrimSpace(out), nil
}

func psEscape(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

// runLocalPS executes one PowerShell script on the controller PC with a
// timeout. One-shot (no persistent shell): local device queries are rare
// (user clicks Refresh), unlike the 2Hz agent meter.
func runLocalPS(script string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-command", script)
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return string(out), fmt.Errorf("timed out after %s", timeout)
	}
	if err != nil {
		t := strings.TrimSpace(string(out))
		if len(t) > 300 {
			t = t[:300] + "..."
		}
		if t == "" {
			t = err.Error()
		}
		return string(out), fmt.Errorf("%s", t)
	}
	return string(out), nil
}

// ---- per-agent persistence: which local device each agent maps to ----

var localAudioMu sync.Mutex

func localAudioFile() string {
	dir := ""
	if localApp := os.Getenv("LOCALAPPDATA"); localApp != "" {
		dir = filepath.Join(localApp, "RMM")
	} else {
		dir = filepath.Join(os.TempDir(), "RMM")
	}
	_ = os.MkdirAll(dir, 0755)
	return filepath.Join(dir, "local_audio.json")
}

// localChoice is the per-agent local playback setup: output device name,
// local volume 0-100 (applied controller-side at play time), and clarity
// speech-continuity profile (default ON).
type localChoice struct {
	Device  string `json:"device"`
	Volume  int    `json:"volume"`
	Clarity *bool  `json:"clarity,omitempty"`
}

func loadLocalAudioMap() map[string]localChoice {
	m := map[string]localChoice{}
	b, err := os.ReadFile(localAudioFile())
	if err != nil {
		return m
	}
	// New shape first.
	if err := json.Unmarshal(b, &m); err == nil && len(m) > 0 {
		return m
	}
	// Backward compat: old shape was map agent->device string.
	var old map[string]string
	if err := json.Unmarshal(b, &old); err == nil {
		for k, v := range old {
			m[k] = localChoice{Device: v, Volume: 100}
		}
	}
	return m
}

func saveLocalAudioChoice(agentID, device string, volume int, clarity *bool) error {
	localAudioMu.Lock()
	defer localAudioMu.Unlock()
	m := loadLocalAudioMap()
	if agentID == "" {
		agentID = "default"
	}
	cur := m[agentID]
	if device != "" {
		cur.Device = device
	}
	if volume >= 0 && volume <= 100 {
		cur.Volume = volume
	} else if cur.Volume == 0 {
		cur.Volume = 100
	}
	if clarity != nil {
		cur.Clarity = clarity
	} else if cur.Clarity == nil {
		on := true // clarity defaults ON for speech intelligibility
		cur.Clarity = &on
	}
	m[agentID] = cur
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(localAudioFile(), b, 0644)
}

// clarityForAgent reports whether the speech-continuity profile is on
// (default true when never set).
func clarityForAgent(m map[string]localChoice, agentID string) bool {
	if agentID != "" {
		if v, ok := m[agentID]; ok && v.Clarity != nil {
			return *v.Clarity
		}
	}
	if d, ok := m["default"]; ok && d.Clarity != nil {
		return *d.Clarity
	}
	return true
}

func choiceForAgent(m map[string]localChoice, agentID string) string {
	if agentID != "" {
		if v, ok := m[agentID]; ok {
			return v.Device
		}
	}
	return m["default"].Device
}

func volumeForAgent(m map[string]localChoice, agentID string) int {
	if agentID != "" {
		if v, ok := m[agentID]; ok {
			return clampVol(v.Volume)
		}
	}
	if d, ok := m["default"]; ok {
		return clampVol(d.Volume)
	}
	return 100
}

func clampVol(v int) int {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}
