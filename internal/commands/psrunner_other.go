//go:build !windows

package commands

// No persistent shell off Windows; one-shot spawn.
func execPSPlatform(script string) (string, error) {
	out, err := runWithTimeout(quickTimeout, "powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-command", script)
	out = truncateOut(out)
	if err != nil {
		return string(out), err
	}
	return string(out), nil
}
