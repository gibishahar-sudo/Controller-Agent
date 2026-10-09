//go:build !windows

package controller

// ensureWatchdogLauncher is windows-only (Run keys + schtasks).
func ensureWatchdogLauncher() {}
