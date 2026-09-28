//go:build windows

package commands

import (
	"fmt"
	"os/user"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// agentContextLine names the world the agent inhabits: user, logon
// session, window station, elevation. GUI faults (invisible windows,
// silent engines) almost always live here, and guessing it from the
// controller wastes a release cycle every time. All fields degrade to
// "?" instead of failing — context must never break diagnosis.
func agentContextLine() string {
	who := "?"
	if u, err := user.Current(); err == nil && u.Username != "" {
		who = u.Username
	}
	sess := "?"
	var sid uint32
	if err := windows.ProcessIdToSessionId(uint32(windows.GetCurrentProcessId()), &sid); err == nil {
		sess = fmt.Sprint(sid)
	}
	sta := windowStationName()
	priv := "user"
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE`, registry.WRITE); err == nil {
		k.Close()
		priv = "elevated"
	}
	return fmt.Sprintf("agent ctx: user=%s session=%s station=%s priv=%s", who, sess, sta, priv)
}

// windowStationName asks user32 directly (the vendored x/sys predates
// the wrappers). "WinSta0" = visible interactive world; anything else
// (e.g. "Service-0x0-...") means GUI children are born invisible.
func windowStationName() string {
	user32 := windows.NewLazySystemDLL("user32.dll")
	getSt := user32.NewProc("GetProcessWindowStation")
	getInfo := user32.NewProc("GetUserObjectInformationW")
	h, _, _ := getSt.Call()
	if h == 0 {
		return "?"
	}
	const uoiName = 2
	buf := make([]uint16, 64)
	var need uint32
	ret, _, _ := getInfo.Call(h, uintptr(uoiName), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)*2), uintptr(unsafe.Pointer(&need)))
	if ret == 0 {
		return "?"
	}
	if s := windows.UTF16ToString(buf); s != "" {
		return s
	}
	return "?"
}
