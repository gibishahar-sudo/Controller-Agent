//go:build !windows

package main

// Non-Windows cursor position. On Android the Kotlin shell reports touch
// state via the P3 bridge; until then the ticker reports (0,0) and the
// controller skips duplicates, so this is a quiet no-op.
func getMousePos() (int, int) { return 0, 0 }
