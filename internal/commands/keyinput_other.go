//go:build !windows

package commands

import "fmt"

// Non-Windows stub: native SendInput is Windows-only; callers fall back to
// their PowerShell/exec paths (which report unsupported themselves).
func sendTextNative(t string) error {
	return fmt.Errorf("native input needs Windows")
}

func keyPressNative(key string) error {
	return fmt.Errorf("native input needs Windows")
}
