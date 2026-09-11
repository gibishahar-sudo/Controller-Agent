//go:build !windows

package main

// ensureSingleInstance is a no-op off Windows (mobile builds run one
// instance under the app sandbox by construction).
func ensureSingleInstance() {}
