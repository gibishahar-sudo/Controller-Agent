//go:build !windows

package main

// Non-Windows stubs: permanent self-delete is a Windows-only operation.

func isElevated() bool { return false }

func deletePendingPath() string { return "" }

func claimDeletePending() bool { return false }

func runSelfDelete() {}
