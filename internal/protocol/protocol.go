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
	Target   string `json:"target,omitempty"` // directed delivery: agent hostname or agent id; empty = broadcast
	X        int    `json:"x,omitempty"`
	Y        int    `json:"y,omitempty"`
	Buttons  []int  `json:"buttons,omitempty"`
	Width    int    `json:"width,omitempty"`
	Height   int    `json:"height,omitempty"`
	Data     string `json:"data,omitempty"` // base64-encoded PNG/JPEG
	Format   string `json:"format,omitempty"` // image format: "png" (default) or "jpeg"
	Quality  int    `json:"quality,omitempty"`
	Monitor  int    `json:"monitor,omitempty"`    // display index (0 = primary)
	AllMonitors bool `json:"allMonitors,omitempty"` // capture the full virtual screen (dual view)
	Cmd      string `json:"cmd,omitempty"`
	Result   string `json:"result,omitempty"`
	Error    string `json:"error,omitempty"`
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
	TypeCommand           = "command"
	TypeOutput            = "output"
	TypeScreenshotRequest = "screenshot_request"
	TypePing              = "ping"
	TypePong              = "pong"
	TypeDisconnect        = "disconnect"
	TypeFileList          = "filelist" // structured file list (preferred over output-sniffing)
)
