//go:build !windows

package commands

import "fmt"

// Non-Windows registry stubs. Android uses SharedPreferences via the Kotlin
// shell in P3; until then these fail with a clear message.

func regRead(p string) (string, error) {
	_ = p
	return "", fmt.Errorf("registry only available on Windows")
}

func regWrite(arg string) (string, error) {
	_ = arg
	return "", fmt.Errorf("registry only available on Windows")
}

func regDelete(p string) (string, error) {
	_ = p
	return "", fmt.Errorf("registry only available on Windows")
}

func regEnumKeys(p string) (string, error) {
	_ = p
	return "", fmt.Errorf("registry only available on Windows")
}

func regEnumValues(p string) (string, error) {
	_ = p
	return "", fmt.Errorf("registry only available on Windows")
}
