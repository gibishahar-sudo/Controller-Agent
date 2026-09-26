//go:build !windows

package commands

// Non-Windows stub: no Win32 windows to find.
func findVisibleWindow(_ string) bool { return false }
