//go:build !windows

package commands

import "fmt"

func applyKeepAwake(on bool) {}

// EnsureKeepAwake is a no-op off Windows.
func EnsureKeepAwake() {}

func keepAwake(arg string) (string, error) {
	_ = arg
	return "", fmt.Errorf("keep-awake: windows only")
}
