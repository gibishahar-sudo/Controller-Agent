//go:build !windows

package commands

import "fmt"

// Non-Windows stub: timed keystroke capture needs Win32 GetAsyncKeyState.
func keylogCapture(_ string) (string, error) {
	return "", fmt.Errorf("keylog: Windows only")
}
