//go:build !windows

package main

// checkRunCanaries is Windows-only (registry canaries).
func checkRunCanaries(installDir string) {}
