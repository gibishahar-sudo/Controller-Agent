package commands

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"rmm/internal/mqttrelay"
	"rmm/internal/relay"
)

// Remote audio streaming: the agent captures its own speaker output
// (WASAPI loopback) or microphone, downmixes to 22050Hz mono 16-bit, and
// publishes ~100ms PCM chunks to the MQTT relay. The controller plays them
// on the operator's selected local device. Fixed format both sides, no
// negotiation: 22050 Hz, 1 channel, 16-bit, 4410 bytes per chunk.

const audioStreamRate = 22050

// Wire block: 1 header byte (bit0 = keyframe: predictor reset on both
// ends) + 1102 samples @22050Hz mono = 50ms, IMA-ADPCM packed to 551 bytes
// (4:1 vs s16). Small + compressed = least loss exposure per block.
const audioStreamChunk = 552

type audioChunk struct {
	Seq  int    `json:"seq"`
	Rate int    `json:"rate"`
	Ch   int    `json:"ch"`
	Bits int    `json:"bits"`
	V    int    `json:"v"`    // wire codec: 0 = raw s16 (legacy), 1 = IMA-ADPCM
	K    bool   `json:"k,omitempty"`
	Data string `json:"data"` // base64 block (ADPCM or PCM per V)
}

// publishAudioChunk sends one ADPCM block, sealed when E2E is active.
func publishAudioChunk(bus *mqttrelay.AgentBus, hn, me string, seq int, raw []byte) error {
	key := false
	data := raw
	if len(raw) > 0 {
		key = raw[0]&1 == 1
		data = raw[1:]
	}
	b, _ := json.Marshal(audioChunk{Seq: seq, Rate: audioStreamRate, Ch: 1, Bits: 16, V: 1, K: key, Data: base64.StdEncoding.EncodeToString(data)})
	payload := json.RawMessage(b)
	enc := false
	if E2EActive() {
		if sealed, err := relay.SealPayload(e2eKey, b); err == nil {
			payload, enc = sealed, true
		}
	}
	return bus.Publish("audio/"+hn, relay.Envelope{From: me, To: "controller", Payload: payload, Enc: enc, Time: time.Now().UnixMilli()})
}

var audioStreamMu sync.Mutex
var audioStreamProc *exec.Cmd
var audioStreamBus *mqttrelay.AgentBus
var audioStreamDone chan struct{}

// captureSnippet runs a WASAPI capture loop writing raw 22050Hz mono s16
// PCM to stdout in 4410-byte blocks. flow 0 = loopback of default render
// (desktop/speakers), 1 = default capture (mic). Emits silence blocks when
// idle so the stream cadence (and controller watchdog) stays alive.
const captureSnippet = `
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.IO;
using System.Threading;
public class RmmCap {
  [ComImport, Guid("BCDE0395-E52F-467C-8E3D-C4579291692E")] public class MMEnum { }
  [Guid("A95664D2-9614-4F35-A746-DE8DB63617E6"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
  public interface IMMEnum {
    int EnumAudioEndpoints(int dataFlow, int dwStateMask, out IntPtr ppDevices);
    int GetDefaultAudioEndpoint(int dataFlow, int role, out IntPtr ppEndpoint);
  }
  [Guid("D666063F-1587-4E43-81F1-B948E807363F"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
  public interface IMMDev {
    int Activate(ref Guid iid, int dwClsCtx, IntPtr pActivationParams, [MarshalAs(UnmanagedType.IUnknown)] out object ppInterface);
  }
  [Guid("1CB9AD4C-DBFA-4C32-B178-C2F568A703B2"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
  public interface IAudioClient {
    int Initialize(int ShareMode, int StreamFlags, long hnsBufferDuration, long hnsPeriodicity, IntPtr pFormat, IntPtr AudioSessionGuid);
    int GetBufferSize(out uint pNumBufferFrames);
    int GetStreamLatency(out long phnsLatency);
    int GetCurrentPadding(out uint pNumPaddingFrames);
    int IsFormatSupported(int ShareMode, IntPtr pFormat, out IntPtr ppClosestMatch);
    int GetMixFormat(out IntPtr ppDeviceFormat);
    int GetDevicePeriod(out long phnsDefaultDevicePeriod, out long phnsMinimumDevicePeriod);
    int Start();
    int Stop();
    int Reset();
    int SetEventHandle(IntPtr eventHandle);
    int GetService(ref Guid riid, [MarshalAs(UnmanagedType.IUnknown)] out object ppv);
  }
  [Guid("C8ADBD64-E71E-48a0-A4DE-185C395CD317"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
  public interface IAudioCapture {
    int GetBuffer(out IntPtr ppData, out uint pNumFramesToRead, out uint pdwFlags, out ulong pu64DevicePosition, out ulong pu64QPCPosition);
    int ReleaseBuffer(uint NumFramesRead);
    int GetNextPacketSize(out uint pNumFramesInNextPacket);
  }
  [StructLayout(LayoutKind.Sequential)]
  public struct WAVEFORMATEX {
    public ushort wFormatTag; public ushort nChannels; public uint nSamplesPerSec;
    public uint nAvgBytesPerSec; public ushort nBlockAlign; public ushort wBitsPerSample; public ushort cbSize;
  }
  static int AdpcmNibble(short sample, ref int pred, ref int idx, int[] stepTab, int[] idxTab) {
    int diff = sample - pred;
    int code = 0;
    if (diff < 0) { code = 8; diff = -diff; }
    int step = stepTab[idx];
    if (diff >= step) { code |= 4; diff -= step; }
    step >>= 1;
    if (diff >= step) { code |= 2; diff -= step; }
    step >>= 1;
    if (diff >= step) { code |= 1; }
    int vpdiff = stepTab[idx] >> 3;
    if ((code & 4) != 0) vpdiff += stepTab[idx];
    if ((code & 2) != 0) vpdiff += stepTab[idx] >> 1;
    if ((code & 1) != 0) vpdiff += stepTab[idx] >> 2;
    if ((code & 8) != 0) pred -= vpdiff; else pred += vpdiff;
    if (pred > 32767) pred = 32767; if (pred < -32768) pred = -32768;
    idx += idxTab[code];
    if (idx < 0) idx = 0; if (idx > 88) idx = 88;
    return code;
  }
  public static void Capture(int flow, int loopback) {
    var enumerator = (IMMEnum)new MMEnum();
    IntPtr ep;
    int hr = enumerator.GetDefaultAudioEndpoint(flow, 0, out ep);
    if (hr != 0 || ep == IntPtr.Zero) throw new Exception("no default endpoint (0x" + hr.ToString("X8") + ")");
    Guid iidClient = new Guid("1CB9AD4C-DBFA-4C32-B178-C2F568A703B2");
    object tmp;
    var dev = (IMMDev)Marshal.GetObjectForIUnknown(ep);
    hr = dev.Activate(ref iidClient, 1, IntPtr.Zero, out tmp);
    if (hr != 0 || tmp == null) throw new Exception("client Activate failed (0x" + hr.ToString("X8") + ")");
    var client = (IAudioClient)tmp;
    IntPtr mixPtr;
    hr = client.GetMixFormat(out mixPtr);
    if (hr != 0) throw new Exception("GetMixFormat failed (0x" + hr.ToString("X8") + ")");
    WAVEFORMATEX fmt = (WAVEFORMATEX)Marshal.PtrToStructure(mixPtr, typeof(WAVEFORMATEX));
    int srcRate = (int)fmt.nSamplesPerSec, srcCh = (int)fmt.nChannels;
    // Mix format is usually WAVE_FORMAT_EXTENSIBLE (0xFFFE); resolve the
    // real encoding from the SubFormat GUID (1 = PCM int, 3 = IEEE float).
    bool isFloat = false; int srcBytes = 0; double pcmScale = 32768;
    if (fmt.wFormatTag == 0xFFFE) {
      int sub1 = Marshal.ReadInt32(mixPtr, 24);
      srcBytes = (fmt.wBitsPerSample + 7) / 8;
      if (sub1 == 3 && (srcBytes == 4 || srcBytes == 8)) { isFloat = true; }
      else if (sub1 == 1 && (srcBytes == 2 || srcBytes == 3 || srcBytes == 4)) {
        pcmScale = srcBytes == 2 ? 32768 : (srcBytes == 3 ? 8388608 : 2147483648);
      }
      else throw new Exception("unsupported extensible subformat=" + sub1 + " bytes=" + srcBytes);
    } else if (fmt.wFormatTag == 3 && fmt.wBitsPerSample == 32) { isFloat = true; srcBytes = 4; }
    else if (fmt.wFormatTag == 3 && fmt.wBitsPerSample == 64) { isFloat = true; srcBytes = 8; }
    else if (fmt.wFormatTag == 1 && fmt.wBitsPerSample == 16) { srcBytes = 2; }
    else if (fmt.wFormatTag == 1 && fmt.wBitsPerSample == 24) { srcBytes = 3; pcmScale = 8388608; }
    else if (fmt.wFormatTag == 1 && fmt.wBitsPerSample == 32) { srcBytes = 4; pcmScale = 2147483648; }
    else throw new Exception("unsupported mix format tag=" + fmt.wFormatTag + " bits=" + fmt.wBitsPerSample);
    int flags = loopback != 0 ? 0x20000 : 0;
    hr = client.Initialize(0, flags, 10000000, 0, mixPtr, IntPtr.Zero);
    Marshal.FreeCoTaskMem(mixPtr);
    if (hr != 0) throw new Exception("Initialize failed (0x" + hr.ToString("X8") + ")");
    Guid iidCap = new Guid("C8ADBD64-E71E-48a0-A4DE-185C395CD317");
    object tmpCap;
    hr = client.GetService(ref iidCap, out tmpCap);
    if (hr != 0 || tmpCap == null) throw new Exception("capture service failed (0x" + hr.ToString("X8") + ")");
    var cap = (IAudioCapture)tmpCap;
    hr = client.Start();
    if (hr != 0) throw new Exception("Start failed (0x" + hr.ToString("X8") + ")");
    const int outRate = 22050;
    const int blockFrames = 1102;
    // IMA-ADPCM state (persists across blocks; decoder mirrors it).
    int adPred = 0, adIdx = 0;
    // Keyframe counter: every 20th block (~1s) resets the predictor and
    // sets the header flag, bounding any divergence window. Decoder
    // resyncs on sight with no round trip.
    int blockNo = 0;
    int[] adStep = new int[] {7,8,9,10,11,12,13,14,16,17,19,21,23,25,28,31,34,37,41,45,50,55,60,66,73,80,88,97,107,118,130,143,157,173,190,209,230,253,279,307,337,371,408,449,494,544,598,658,724,796,876,963,1060,1166,1282,1411,1552,1707,1878,2066,2272,2499,2749,3024,3327,3660,4026,4428,4871,5358,5894,6484,7132,7846,8630,9493,10442,11487,12635,13899,15289,16818,18498,20350,22385,24623,27086,29794,32767};
    int[] adIdxTab = new int[] {-1,-1,-1,-1,2,4,6,8,-1,-1,-1,-1,2,4,6,8};
    var bw = new BinaryWriter(Console.OpenStandardOutput());
    var pending = new System.Collections.Generic.List<short>(8192);
    double acc = 0; int accN = 0; double accPos = 0;
    double ratio = (double)srcRate / outRate;
    long lastEmit = DateTime.UtcNow.Ticks;
    while (true) {
      uint pkt;
      cap.GetNextPacketSize(out pkt);
      if (pkt == 0) {
        long now = DateTime.UtcNow.Ticks;
        if (now - lastEmit > 900000) {
          // Silence THROUGH the encoder (not raw zeros) so both predictors
          // march in lockstep and resume artifact-free.
          bool key = (blockNo % 20 == 0);
          if (key) { adPred = 0; adIdx = 0; }
          blockNo++;
          byte[] ad = new byte[1 + blockFrames / 2];
          ad[0] = (byte)(key ? 1 : 0);
          for (int si = 0; si < blockFrames; si += 2) {
            int hi = AdpcmNibble(0, ref adPred, ref adIdx, adStep, adIdxTab);
            int lo = AdpcmNibble(0, ref adPred, ref adIdx, adStep, adIdxTab);
            ad[1 + si / 2] = (byte)((hi << 4) | lo);
          }
          bw.Write(ad);
          bw.Flush();
          lastEmit = now;
        }
        Thread.Sleep(10);
        continue;
      }
      IntPtr data; uint frames; uint dwFlags; ulong devPos, qpcPos;
      hr = cap.GetBuffer(out data, out frames, out dwFlags, out devPos, out qpcPos);
      if (hr != 0) { Thread.Sleep(10); continue; }
      bool silent = (dwFlags & 0x2) != 0;
      for (uint f = 0; f < frames; f++) {
        double s = 0;
        if (!silent) {
          double sum = 0;
          for (int c = 0; c < srcCh; c++) {
            int idx = (int)(f * (uint)srcCh + (uint)c);
            IntPtr p = IntPtr.Add(data, idx * srcBytes);
            double v;
            if (isFloat) {
              if (srcBytes == 8) v = (double)Marshal.PtrToStructure(p, typeof(double));
              else v = (float)Marshal.PtrToStructure(p, typeof(float));
            }
            else if (srcBytes == 2) v = (short)Marshal.ReadInt16(p) / pcmScale;
            else if (srcBytes == 4) v = (int)Marshal.ReadInt32(p) / pcmScale;
            else {
              int b0 = Marshal.ReadByte(p), b1 = Marshal.ReadByte(p, 1), b2 = Marshal.ReadByte(p, 2);
              int sv = b0 | (b1 << 8) | (b2 << 16);
              if ((sv & 0x800000) != 0) sv |= unchecked((int)0xFF000000);
              v = sv / pcmScale;
            }
            sum += v;
          }
          s = sum / srcCh;
        }
        acc += s; accN++; accPos += 1.0;
        while (accPos >= ratio) {
          double avg = accN > 0 ? acc / accN : 0;
          if (avg > 1) avg = 1; if (avg < -1) avg = -1;
          pending.Add((short)(avg * 32767));
          acc = 0; accN = 0; accPos -= ratio;
          if (pending.Count >= blockFrames) {
            short[] frame = pending.GetRange(0, blockFrames).ToArray();
            pending.RemoveRange(0, blockFrames);
            // Keyframe: reset predictor first so the decoder (which resets
            // on the flag) stays in lockstep.
            bool key = (blockNo % 20 == 0);
            if (key) { adPred = 0; adIdx = 0; }
            blockNo++;
            // IMA-ADPCM encode: 2 samples per byte (4:1 vs s16).
            // Wire block = 1 header byte (bit0 = keyframe) + 551 data bytes.
            byte[] ad = new byte[1 + blockFrames / 2];
            ad[0] = (byte)(key ? 1 : 0);
            for (int si = 0; si < blockFrames; si += 2) {
              int hi = AdpcmNibble(frame[si], ref adPred, ref adIdx, adStep, adIdxTab);
              int lo = AdpcmNibble(frame[si + 1], ref adPred, ref adIdx, adStep, adIdxTab);
              ad[1 + si / 2] = (byte)((hi << 4) | lo);
            }
            bw.Write(ad);
            bw.Flush();
            lastEmit = DateTime.UtcNow.Ticks;
          }
        }
      }
      cap.ReleaseBuffer(frames);
    }
  }
}
'@
`

// StartAudioStream begins publishing live PCM chunks. source is
// desktop (speaker loopback), mic, or both (= desktop loopback plus note).
func StartAudioStream(source string) (string, error) {
	if runtime.GOOS != "windows" {
		return "", fmt.Errorf("audio streaming not supported on %s", runtime.GOOS)
	}
	source = strings.ToLower(strings.TrimSpace(source))
	flow := 0
	loopback := 1
	label := "desktop output"
	switch source {
	case "", "desktop", "both":
		if source == "both" {
			label = "desktop output (both = loopback; mic meter still live)"
		}
	case "mic", "microphone":
		flow = 1
		loopback = 0
		label = "microphone"
	default:
		return "", fmt.Errorf("usage: start-audio-stream [desktop|mic]")
	}
	audioStreamMu.Lock()
	defer audioStreamMu.Unlock()
	stopAudioStreamLocked()
	hn, err := os.Hostname()
	if err != nil || hn == "" {
		return "", fmt.Errorf("hostname: %v", err)
	}
	bus, err := mqttrelay.DialAgent(hn)
	if err != nil {
		return "", fmt.Errorf("mqtt for audio: %v", err)
	}
	fmt.Printf("[audio-stream] publishing via %s\n", bus.Broker())
	script := captureSnippet + fmt.Sprintf("[RmmCap]::Capture(%d, %d)", flow, loopback)
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-command", script)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		bus.Close()
		return "", err
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		bus.Close()
		return "", err
	}
	done := make(chan struct{})
	me := "agent:" + hn
	// Verify the capturer actually produces a first frame (PowerShell
	// Add-Type/COM failures would otherwise be silent: the child just
	// exits and no chunks ever arrive). Block up to ~12s for it.
	first := make([]byte, audioStreamChunk)
	type firstRes struct {
		n   int
		err error
	}
	firstCh := make(chan firstRes, 1)
	go func() {
		n, err := io.ReadFull(stdout, first)
		firstCh <- firstRes{n, err}
	}()
	select {
	case r := <-firstCh:
		if r.err != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			bus.Close()
			errText := strings.TrimSpace(stderr.String())
			if len(errText) > 1500 {
				errText = errText[:1500] + "..."
			}
			if errText == "" {
				errText = r.err.Error()
			}
			return "", fmt.Errorf("audio capture produced no data: %s", errText)
		}
		_ = publishAudioChunk(bus, hn, me, 0, first[:r.n])
	case <-time.After(12 * time.Second):
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		bus.Close()
		errText := strings.TrimSpace(stderr.String())
		if len(errText) > 500 {
			errText = errText[:500] + "..."
		}
		if errText == "" {
			errText = "timed out waiting for first audio frame"
		}
		return "", fmt.Errorf("audio capture produced no data: %s", firstLineOf(errText))
	}
	audioStreamProc = cmd
	audioStreamBus = bus
	audioStreamDone = done
	seq := 1
	go func() {
		buf := make([]byte, audioStreamChunk)
		pubErrs := 0
		for {
			select {
			case <-done:
				return
			default:
			}
			if _, err := io.ReadFull(stdout, buf); err != nil {
				return
			}
			if err := publishAudioChunk(bus, hn, me, seq, buf); err != nil {
				pubErrs++
				if pubErrs <= 3 || pubErrs%50 == 0 {
					fmt.Printf("[audio-stream] publish #%d failed: %v\n", seq, err)
				}
			}
			seq++
		}
	}()
	return fmt.Sprintf("streaming %s @ %dHz mono (~1s delay, stop with stop-audio-stream)", label, audioStreamRate), nil
}

func firstLineOf(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "\n"); i != -1 {
		s = s[:i]
	}
	if len(s) > 300 {
		s = s[:300] + "..."
	}
	return s
}

// StopAudioStream kills a running audio stream, if any.
func StopAudioStream() (string, error) {
	audioStreamMu.Lock()
	defer audioStreamMu.Unlock()
	if audioStreamProc == nil {
		return "no audio stream running", nil
	}
	stopAudioStreamLocked()
	return "audio stream stopped", nil
}

func stopAudioStreamLocked() {
	if audioStreamDone != nil {
		close(audioStreamDone)
		audioStreamDone = nil
	}
	if audioStreamProc != nil && audioStreamProc.Process != nil {
		_ = audioStreamProc.Process.Kill()
		_ = audioStreamProc.Wait()
		audioStreamProc = nil
	}
	if audioStreamBus != nil {
		audioStreamBus.Close()
		audioStreamBus = nil
	}
}
