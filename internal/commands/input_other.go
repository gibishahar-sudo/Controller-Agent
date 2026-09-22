//go:build !windows

package commands

import "fmt"

// Non-Windows mouse stubs. On Android these are replaced in P3 by the
// AccessibilityService bridge; until then they fail with a clear message
// instead of breaking the build.

func getMousePos() (int, int) { return 0, 0 }

func mouseMove(arg string) (string, error) {
	return "", fmt.Errorf("mouse-move: no cursor on this platform (Android taps land in P3)")
}

func mouseClick(_ string) (string, error) {
	return "", fmt.Errorf("mouse-click: no cursor on this platform (Android taps land in P3)")
}

func mouseDoubleClick() (string, error) {
	return "", fmt.Errorf("mouse-doubleclick: no cursor on this platform (Android taps land in P3)")
}

func mouseButton(arg string) (string, error) {
	_ = arg
	return "", fmt.Errorf("mouse-button: no cursor on this platform (Android taps land in P3)")
}

func mouseScroll(arg string) (string, error) {
	_ = arg
	return "", fmt.Errorf("mouse-scroll: no cursor on this platform (Android taps land in P3)")
}

func mouseClickAt(arg string) (string, error) {
	_ = arg
	return "", fmt.Errorf("mouse-click-at: no cursor on this platform (Android taps land in P3)")
}

func mouseDoubleClickAt(arg string) (string, error) {
	_ = arg
	return "", fmt.Errorf("mouse-doubleclick-at: no cursor on this platform (Android taps land in P3)")
}
