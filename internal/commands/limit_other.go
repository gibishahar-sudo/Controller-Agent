//go:build !windows

package commands

import "fmt"

// Resource caps are Windows Job Objects; the fleet is Windows and the
// tablet runs no agents.
func ApplyAgentLimits() error { return nil }

func AgentLimitsCmd(args string) (string, error) {
	return "", fmt.Errorf("not supported on this platform")
}
