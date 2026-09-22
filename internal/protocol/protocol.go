package protocol

// Message is the JSON protocol exchanged over TLS.
// Line-delimited: one JSON object per line terminated by \n.
// Version 1: adds Target for directed delivery (ntfy fan-out fix).
const Version = 1

type Message struct {
	Type     string `json:"type"`
	Hostname string `json:"hostname,omitempty"`
	User     string `json:"user,omitempty"`
	ID       string `json:"id,omitempty"`
	// Instance identifies one agent process (hostname-pid). Relay virtual
	// agent ids derive from it so two processes on one host (stale duplicate
	// after upgrade) show as distinct entries instead of shadowing each other.
	Instance string `json:"instance,omitempty"`
	Version  string `json:"version,omitempty"` // agent's DesktopAgentVersion (in TypeConnect/hello)
	Target   string `json:"target,omitempty"` // directed delivery: agent hostname or agent id; empty = broadcast
	X        int    `json:"x,omitempty"`
	Y        int    `json:"y,omitempty"`
	Buttons  []int  `json:"buttons,omitempty"`
	Width    int    `json:"width,omitempty"`
	Height   int    `json:"height,omitempty"`
	OX       int    `json:"ox,omitempty"` // capture origin: virtual-screen X of frame's top-left
	OY       int    `json:"oy,omitempty"` // capture origin: virtual-screen Y of frame's top-left
	FSeq     uint64 `json:"fseq,omitempty"` // capture completion order; UI drops stale arrivals
	Data     string `json:"data,omitempty"` // base64-encoded PNG/JPEG
	Format   string `json:"format,omitempty"` // image format: "png" (default) or "jpeg"
	Quality  int    `json:"quality,omitempty"`
	Monitor  int    `json:"monitor,omitempty"`    // display index (0 = primary)
	AllMonitors bool `json:"allMonitors,omitempty"` // capture the full virtual screen (dual view)
	Scale    float64 `json:"scale,omitempty"`    // capture downscale (0.5 = half-res, 4x smaller frames); 0/1 = full
	Tiles    bool    `json:"tiles,omitempty"`    // request tile-diff updates (changed 128px tiles + periodic keyframes)
	Cmd      string `json:"cmd,omitempty"`
	CmdID    string `json:"cmdId,omitempty"` // unique per send; agents skip reruns (two-controller dedupe)
	Result   string `json:"result,omitempty"`
	Error    string `json:"error,omitempty"`
	E2E      bool   `json:"e2e,omitempty"` // controller ack flag: this controller decrypts Enc envelopes
	// Self-update envelope (force-update): controller streams its bundled
	// agent binary in chunks; Data carries base64 chunk bytes.
	UpdateVer   string `json:"updateVer,omitempty"`
	UpdateSize  int64  `json:"updateSize,omitempty"`
	UpdateSHA   string `json:"updateSHA,omitempty"`
	UpdateTotal int    `json:"updateTotal,omitempty"`
	UpdateSeq   int    `json:"updateSeq,omitempty"`
	// Crash-rollback report (in TypeConnect/hello): the watchdog restored
	// the previous binary after the new one crash-looped. RollbackBad is
	// the crashed version, RollbackTo the restored one. The controller
	// raises an alarm and holds back re-pushing the bad version.
	RollbackBad string `json:"rollbackBad,omitempty"`
	RollbackTo  string `json:"rollbackTo,omitempty"`
}

// FileEntry mirrors the Files tab JSON shape.
type FileEntry struct {
	Name         string `json:"name"`
	Size         int64  `json:"size"`
	IsDirectory  bool   `json:"isDirectory"`
	LastModified string `json:"lastModified"`
}

// FileList is the structured result of list-directory (replaces fragile string-sniffing).
type FileList struct {
	Path    string      `json:"path"`
	Entries []FileEntry `json:"entries"`
}

// Message types
const (
	TypeConnect           = "connect"
	TypeConnected         = "connected"
	TypeMouse             = "mouse"
	TypeScreen            = "screen"
	TypeTile              = "tile" // one changed 128px tile: Data=JPEG, OX/OY=tile origin, FSeq=frame generation
	TypeCommand           = "command"
	TypeOutput            = "output"
	TypeScreenshotRequest = "screenshot_request"
	TypePing              = "ping"
	TypePong              = "pong"
	TypeDisconnect        = "disconnect"
	TypeFileList          = "filelist" // structured file list (preferred over output-sniffing)
	TypeUpdateBegin       = "update_begin"
	TypeUpdateChunk       = "update_chunk"
	TypeKeyExchange       = "keyxchg" // agent -> controller: RSA-wrapped AES data key (see relay.SealPayload)
)
