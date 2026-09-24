package controller

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Local playback of streamed remote audio. The controller spawns one
// powershell helper that renders raw 22050Hz mono s16 PCM from stdin to the
// operator's chosen waveOut device. Chunks arrive from MQTT binary frames
// (~25ms blocks, batched pairs by default, DTX silence skipped);
// the writer queue absorbs jitter and drops oldest (rather than lagging)
// on overflow.

const audioPlayRate = 22050
const audioPlayChunk = 2204

const waveOutPlayerSnippet = `
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.IO;
using System.Threading;
public class RmmPlay {
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
  public static void Run(string want) {
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
        else { int p = 0; while (p < nw.Length && p < nd.Length && nw[p] == nd[p]) p++; if (p >= 6) score = p; }
        if (score > bestLen) { bestLen = score; best = i; bestName = c.szPname; }
      }
      if (best >= 0) { dev = best; devName = bestName; }
    }
    Console.Error.WriteLine("RmmPlay on [" + devName + "]");
    WAVEFORMATEX fmt = new WAVEFORMATEX();
    fmt.wFormatTag = 1; fmt.nChannels = 1; fmt.nSamplesPerSec = 22050;
    fmt.wBitsPerSample = 16; fmt.nBlockAlign = 2; fmt.nAvgBytesPerSec = 44100; fmt.cbSize = 0;
    IntPtr hwo;
    int hr = waveOutOpen(out hwo, dev, ref fmt, IntPtr.Zero, IntPtr.Zero, 0);
    if (hr != 0) throw new Exception("waveOutOpen failed (0x" + hr.ToString("X8") + ")");
    try {
      var stdin = Console.OpenStandardInput();
      byte[] buf = new byte[2204]; // 50ms @ 22050Hz mono s16
      while (true) {
        int got = 0;
        while (got < buf.Length) {
          int r = stdin.Read(buf, got, buf.Length - got);
          if (r <= 0) return;
          got += r;
        }
        var handle = GCHandle.Alloc(buf, GCHandleType.Pinned);
        try {
          WAVEHDR hdr = new WAVEHDR();
          hdr.lpData = handle.AddrOfPinnedObject();
          hdr.dwBufferLength = (uint)buf.Length;
          int hs = Marshal.SizeOf(typeof(WAVEHDR));
          hr = waveOutPrepareHeader(hwo, ref hdr, hs);
          if (hr != 0) throw new Exception("prepare failed (0x" + hr.ToString("X8") + ")");
          hr = waveOutWrite(hwo, ref hdr, hs);
          if (hr != 0) throw new Exception("write failed (0x" + hr.ToString("X8") + ")");
          int waited = 0;
          while ((hdr.dwFlags & 0x1) == 0 && waited < 8000) { Thread.Sleep(10); waited += 10; }
          waveOutUnprepareHeader(hwo, ref hdr, hs);
        } finally { handle.Free(); }
      }
    } finally { waveOutClose(hwo); }
  }
}
'@
`

// maxPlayQueue bounds the adaptive jitter buffer in blocks (v1.45+ blocks
// are ~25ms: 2..8 = 50ms floor on clean links, 200ms ceiling on jittery
// ones; clarity profile raises both). When the player falls behind, OLDEST
// chunks are dropped so the stream stays live instead of lagging behind
// (dropping newest would freeze audio while staying late).
const maxPlayQueue = 8
const minPlayQueue = 2

// audioBlockMs is the v2 media block duration; the jitter math below is in
// blocks, so halving the block size halves delay with no other change.
const audioBlockMs = 25

type audioPlayerState struct {
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	mu      sync.Mutex
	queue   [][]byte
	notify  chan struct{}
	done    chan struct{}
	host    string
	device  string
	gain    float64 // 0.0-1.0 local volume, applied per sample
	clarity bool    // speech-continuity profile (deeper buffer, more replays)
	qMin    int     // jitter floor in blocks (clarity mode raises it)
	qMax    int     // jitter ceiling in blocks
	maxReplays int  // consecutive concealment replays allowed
	arrivalEMA float64 // EMA of chunk inter-arrival ms; sizes the buffer
	lastArrival  int64 // unixnano of previous chunk
	lastChunk atomic.Int64
	dropped   atomic.Int64
	played    atomic.Int64
	replayed  atomic.Int64
}

// desiredQueue converts arrival jitter into a buffer target: twice the
// smoothed spacing, clamped to the player's [qMin, qMax] blocks.
func (st *audioPlayerState) desiredQueue() int {
	ema := st.arrivalEMA
	if ema <= 0 {
		ema = 2 * audioBlockMs
	}
	q := int((ema*2 + audioBlockMs - 1) / audioBlockMs)
	lo, hi := st.qMin, st.qMax
	if lo <= 0 {
		lo = minPlayQueue
	}
	if hi <= 0 {
		hi = maxPlayQueue
	}
	if q < lo {
		q = lo
	}
	if q > hi {
		q = hi
	}
	return q
}

var audioPlayerMu sync.Mutex
var curAudioPlayer *audioPlayerState
var lastPlayerSpawnFail atomic.Int64

// ensureAudioPlayer (re)starts the local player when the stream source,
// chosen device or clarity profile changes, and refreshes the silence
// watchdog otherwise. Gain-only changes apply live (no restart, no
// dropout): the writer reads st.gain per chunk under the state mutex.
func ensureAudioPlayer(host, device string, gain float64, clarity bool) (string, error) {
	if runtime.GOOS != "windows" {
		return "", nil // no local playback off Windows; chunks drop silently
	}
	if gain < 0 {
		gain = 0
	}
	if gain > 1 {
		gain = 1
	}
	audioPlayerMu.Lock()
	defer audioPlayerMu.Unlock()
	qMin, qMax, maxRep := minPlayQueue, maxPlayQueue, 4
	if clarity {
		qMin, qMax, maxRep = 8, 20, 8 // ~200-500ms buffer, 200ms concealment for speech
	}
	if curAudioPlayer != nil && curAudioPlayer.host == host && curAudioPlayer.device == device && curAudioPlayer.clarity == clarity {
		if curAudioPlayer.gain != gain {
			curAudioPlayer.mu.Lock()
			curAudioPlayer.gain = gain
			curAudioPlayer.mu.Unlock()
		}
		curAudioPlayer.lastChunk.Store(time.Now().UnixNano())
		return "", nil
	}
	if time.Since(time.Unix(0, lastPlayerSpawnFail.Load())) < 5*time.Second {
		return "", nil // spawn recently failed; back off instead of storming powershell
	}
	stopAudioPlayerLocked()
	script := waveOutPlayerSnippet + "[RmmPlay]::Run('" + strings.ReplaceAll(device, "'", "''") + "')"
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-command", script)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return "", err
	}
	// Stream stderr through a pipe so the helper's first line ("RmmPlay on
	// [actual device]") tells us where audio REALLY landed — the fuzzy
	// match can otherwise misroute silently.
	stdErrR, stdErrW := io.Pipe()
	cmd.Stderr = stdErrW
	if err := cmd.Start(); err != nil {
		lastPlayerSpawnFail.Store(time.Now().UnixNano())
		stdErrW.Close()
		log.Printf("[audio] player spawn failed: %v", err)
		return "", err
	}
	st := &audioPlayerState{
		cmd:    cmd,
		stdin:  stdin,
		notify: make(chan struct{}, 1),
		done:   make(chan struct{}),
		host:   host,
		device: device,
		gain:   gain,
		clarity: clarity,
		qMin:   qMin,
		qMax:   qMax,
		maxReplays: maxRep,
	}
	st.lastChunk.Store(time.Now().UnixNano())
	curAudioPlayer = st
	// Fresh player = fresh encoder on the agent side (or a restarted
	// stream): drop any stale predictor so playback starts clean.
	resetAudioDecoder(host)
	// Confirm where audio landed: the helper prints its ACTUAL device on
	// stderr at startup (fuzzy match can misroute). Timeout = hung
	// helper: kill it and report instead of playing into the void.
	lineCh := make(chan string, 1)
	go func() {
		br := bufio.NewReader(stdErrR)
		ln, _ := br.ReadString('\n')
		lineCh <- strings.TrimSpace(ln)
	}()
	go func() {
		<-st.done
		stdErrW.Close()
	}()
	name := device
	if name == "" {
		name = "Default"
	}
	select {
	case ln := <-lineCh:
		if strings.Contains(ln, "RmmPlay on [") {
			name = ln[strings.Index(ln, "RmmPlay on [")+len("RmmPlay on ["):]
			name = strings.TrimSuffix(name, "]")
		}
	case <-time.After(3 * time.Second):
		_ = cmd.Process.Kill()
		lastPlayerSpawnFail.Store(time.Now().UnixNano())
		stopAudioPlayerLocked()
		return "", fmt.Errorf("player helper silent for 3s (no audio device?)")
	}
	log.Printf("[audio] playing remote audio from %s on [%s]", host, name)
	go audioPlayerWriter(st)
	go audioPlayerWatchdog(st)
	return name, nil
}

func audioPlayerWriter(st *audioPlayerState) {
	// Packet-loss concealment: on underrun, replay the last block with a
	// full-block crossfade from the last played sample (no step/click) and
	// compounding decay (0.9^replays), so long dropout tails fade out
	// instead of droning robotically or punching holes of silence.
	var last []byte
	var lastSample int16
	replays := 0
	for {
		st.mu.Lock()
		if len(st.queue) == 0 {
			st.mu.Unlock()
			select {
			case <-st.done:
				return
			case <-st.notify:
				continue
			case <-time.After(15 * time.Millisecond):
			}
			st.mu.Lock()
			if len(st.queue) == 0 {
				if last != nil && replays < st.maxReplays {
					replays++
					st.replayed.Add(1)
				cp := append([]byte(nil), last...)
				n := len(cp)
				decay := 1.0
				for k := 1; k < replays; k++ {
					decay *= 0.9 // compounding: long tails fade, short gaps stay full
				}
					for i := 0; i+1 < n; i += 2 {
						v := int16(cp[i]) | int16(cp[i+1])<<8
						v = int16(float64(v) * decay)
						prev := lastSample
						v = prev + int16(float64(v-prev)*float64(i)/float64(n))
						cp[i] = byte(v)
						cp[i+1] = byte(v >> 8)
					}
					if len(cp) >= 2 {
						lastSample = int16(cp[len(cp)-2]) | int16(cp[len(cp)-1])<<8
					}
					st.mu.Unlock()
					if _, err := st.stdin.Write(cp); err != nil {
						return
					}
				} else {
					st.mu.Unlock()
				}
				continue
			}
		}
		pcm := st.queue[0]
		st.queue[0] = nil
		st.queue = st.queue[1:]
		replays = 0
		last = pcm
		if len(pcm) >= 2 {
			lastSample = int16(pcm[len(pcm)-2]) | int16(pcm[len(pcm)-1])<<8
		}
		st.mu.Unlock()
		if _, err := st.stdin.Write(pcm); err != nil {
			return
		}
	}
}

// audioPlayerWatchdog stops the player after 3s without chunks (stream
// ended or agent died) so a stale helper never lingers.
func audioPlayerWatchdog(st *audioPlayerState) {
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-st.done:
			return
		case <-t.C:
			if time.Since(time.Unix(0, st.lastChunk.Load())) > 3*time.Second {
				audioPlayerMu.Lock()
				if curAudioPlayer == st {
					log.Printf("[audio] stream silent 3s, stopping local playback")
					stopAudioPlayerLocked()
				}
				audioPlayerMu.Unlock()
				return
			}
		}
	}
}

// writeAudioChunk queues one PCM block; when the player falls behind,
// oldest blocks are dropped (counted) so playback stays live.
func writeAudioChunk(pcm []byte) {
	audioPlayerMu.Lock()
	st := curAudioPlayer
	audioPlayerMu.Unlock()
	if st == nil {
		return
	}
	cp := append([]byte(nil), pcm...)
	st.mu.Lock()
	now := time.Now().UnixNano()
	if prev := st.lastArrival; prev > 0 {
		dt := float64(now-prev) / 1e6
		if dt > 0 && dt < 5000 {
			if st.arrivalEMA <= 0 {
				st.arrivalEMA = dt
			} else {
				st.arrivalEMA = 0.9*st.arrivalEMA + 0.1*dt
			}
		}
	}
	st.lastArrival = now
	if g := st.gain; g < 1 {
		for i := 0; i+1 < len(cp); i += 2 {
			v := int16(cp[i]) | int16(cp[i+1])<<8
			v = int16(float64(v) * g)
			cp[i] = byte(v)
			cp[i+1] = byte(v >> 8)
		}
	}
	st.queue = append(st.queue, cp)
	for len(st.queue) > st.desiredQueue() {
		st.queue[0] = nil
		st.queue = st.queue[1:]
		st.dropped.Add(1)
	}
	if n := st.played.Add(1); n%200 == 0 {
		log.Printf("[audio] stream %s: %d played, %d dropped, %d concealed, %d gaps (%.0fms spacing)",
			st.host, n, st.dropped.Load(), st.replayed.Load(), audioGaps(st.host), st.arrivalEMA)
	}
	st.mu.Unlock()
	select {
	case st.notify <- struct{}{}:
	default:
	}
	st.lastChunk.Store(time.Now().UnixNano())
}

// audioStatsSnapshot reports the live player's counters for the UI's
// stream-health readout (dropouts are a network problem; this shows
// whether the link is lossy/jittery/clean instead of guessing).
func audioStatsSnapshot() map[string]interface{} {
	audioPlayerMu.Lock()
	st := curAudioPlayer
	audioPlayerMu.Unlock()
	if st == nil {
		return map[string]interface{}{"active": false}
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	return map[string]interface{}{
		"active": true, "host": st.host, "device": st.device,
		"played": st.played.Load(), "dropped": st.dropped.Load(),
		"concealed": st.replayed.Load(), "gaps": audioGaps(st.host),
		"spacingMs": st.arrivalEMA, "queue": len(st.queue),
		"queueTarget": st.desiredQueue(), "clarity": st.clarity,
	}
}

// stopAudioPlayer kills local playback immediately (UI Stop button).
func stopAudioPlayer() {
	audioPlayerMu.Lock()
	defer audioPlayerMu.Unlock()
	stopAudioPlayerLocked()
}

func stopAudioPlayerLocked() {
	st := curAudioPlayer
	curAudioPlayer = nil
	if st == nil {
		return
	}
	close(st.done)
	if st.cmd != nil && st.cmd.Process != nil {
		_ = st.cmd.Process.Kill()
		go st.cmd.Wait()
	}
	if st.stdin != nil {
		_ = st.stdin.Close()
	}
}
