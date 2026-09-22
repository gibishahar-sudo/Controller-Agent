//go:build !windows

package main

// ensureWatchPersistence is Windows-only (registry + schtasks).
func ensureWatchPersistence(w *watchCfg) {}

// runWmiHeal is Windows-only.
func runWmiHeal() {}

// writeProtectionScore is Windows-only.
func writeProtectionScore(w *watchCfg) {}
