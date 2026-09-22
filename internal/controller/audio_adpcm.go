package controller

import "sync"

// IMA-ADPCM decoder, mirror of the agent capturer's RmmCap encoder.
// Wire format v1: 551 bytes per 50ms block (1102 samples @22050Hz mono).
// v0 (absent) = legacy raw s16, still accepted for transition.

var imaStepTable = [89]int{
	7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 19, 21, 23, 25, 28, 31,
	34, 37, 41, 45, 50, 55, 60, 66, 73, 80, 88, 97, 107, 118, 130, 143,
	157, 173, 190, 209, 230, 253, 279, 307, 337, 371, 408, 449, 494, 544,
	598, 658, 724, 796, 876, 963, 1060, 1166, 1282, 1411, 1552, 1707, 1878,
	2066, 2272, 2499, 2749, 3024, 3327, 3660, 4026, 4428, 4871, 5358, 5894,
	6484, 7132, 7846, 8630, 9493, 10442, 11487, 12635, 13899, 15289, 16818,
	18498, 20350, 22385, 24623, 27086, 29794, 32767,
}

var imaIndexTable = [16]int{-1, -1, -1, -1, 2, 4, 6, 8, -1, -1, -1, -1, 2, 4, 6, 8}

type adpcmDecoder struct {
	pred  int
	index int
}

func (d *adpcmDecoder) decodeBlock(src []byte) []byte {
	out := make([]byte, 0, len(src)*4)
	for _, b := range src {
		for _, nib := range []byte{b >> 4, b & 0x0F} {
			step := imaStepTable[d.index]
			vpdiff := step >> 3
			if nib&4 != 0 {
				vpdiff += step
			}
			if nib&2 != 0 {
				vpdiff += step >> 1
			}
			if nib&1 != 0 {
				vpdiff += step >> 2
			}
			if nib&8 != 0 {
				d.pred -= vpdiff
			} else {
				d.pred += vpdiff
			}
			if d.pred > 32767 {
				d.pred = 32767
			} else if d.pred < -32768 {
				d.pred = -32768
			}
			d.index += imaIndexTable[nib]
			if d.index < 0 {
				d.index = 0
			} else if d.index > 88 {
				d.index = 88
			}
			out = append(out, byte(d.pred), byte(d.pred>>8))
		}
	}
	return out
}

var adpcmMu sync.Mutex
var adpcmDecoders = map[string]*adpcmDecoder{}

var audioSeqMu sync.Mutex
var audioLastSeq = map[string]int{}
var audioGapCount = map[string]int64{}

// noteAudioSeq records a chunk sequence number; it reports whether the
// decoder must reset first: keyframe flag, first sighting, or any gap.
// Gaps are counted per host for the stream telemetry line.
func noteAudioSeq(host string, seq int, keyframe bool) bool {
	audioSeqMu.Lock()
	defer audioSeqMu.Unlock()
	last, ok := audioLastSeq[host]
	audioLastSeq[host] = seq
	if keyframe || !ok || seq != last+1 {
		if ok && !keyframe && seq != last+1 {
			audioGapCount[host]++
		}
		return true
	}
	return false
}

// resetAudioDecoder drops a host's predictor state (fresh decoder starts
// at 0,0, matching a keyframed or restarted encoder).
func resetAudioDecoder(host string) {
	adpcmMu.Lock()
	delete(adpcmDecoders, host)
	adpcmMu.Unlock()
}

func audioGaps(host string) int64 {
	audioSeqMu.Lock()
	defer audioSeqMu.Unlock()
	return audioGapCount[host]
}

// decodeAudioChunk converts a wire chunk to 2204-byte s16 PCM using the
// persistent per-host predictor. Unknown versions pass through as raw.
func decodeAudioChunk(host string, v int, data []byte) []byte {
	if v != 1 {
		return data
	}
	adpcmMu.Lock()
	dec, ok := adpcmDecoders[host]
	if !ok {
		dec = &adpcmDecoder{}
		adpcmDecoders[host] = dec
	}
	out := dec.decodeBlock(data)
	adpcmMu.Unlock()
	return out
}
