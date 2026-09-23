//go:build !windows

package main

// hideOwnConsole is Windows-only.
func hideOwnConsole() {}

// ensureInteractiveConsole is Windows-only.
func ensureInteractiveConsole() {}
