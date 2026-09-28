//go:build !windows

package commands

// agentContextLine is windows-only (session/station have no meaning
// elsewhere); the selftest that prints it is windows-only too.
func agentContextLine() string { return "agent ctx: n/a" }
