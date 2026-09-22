//go:build !windows

package main

// ensureWatchPersistence is Windows-only (registry + schtasks).
func ensureWatchPersistence(w *watchCfg) {}
