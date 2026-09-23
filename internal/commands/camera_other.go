//go:build !windows

package commands

import (
	"fmt"
	"runtime"
)

// cameraShot is Windows-only (Video-for-Windows).
func cameraShot(args string) (string, error) {
	return "", fmt.Errorf("camera not supported on %s", runtime.GOOS)
}
