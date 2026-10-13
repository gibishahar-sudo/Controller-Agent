//go:build !windows

package commands

// NMSPriv describes the identity and power of the running process.
// Non-Windows stub: the fleet is Windows-only; fields read zero-value.
type NMSPriv struct {
	User      string `json:"user"`
	Elevated  bool   `json:"elevated"`
	Integrity string `json:"integrity"`
	IsAdmin   bool   `json:"is_admin"`
	Detail    string `json:"detail,omitempty"`
}

// CurrentNMSPriv on non-Windows reports unavailable (never fails).
func CurrentNMSPriv() NMSPriv {
	return NMSPriv{Integrity: "unknown", Detail: "non-windows build"}
}
