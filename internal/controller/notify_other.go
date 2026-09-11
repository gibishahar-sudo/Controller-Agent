//go:build !windows

package controller

import "log"

// No MessageBox off Windows; log instead. On Android the Kotlin shell
// surfaces these via Snackbar.
func showError(msg string) {
	log.Printf("[controller error] %s", msg)
}
