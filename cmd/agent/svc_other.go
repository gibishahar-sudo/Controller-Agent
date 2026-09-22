//go:build !windows

package main

import (
	"fmt"
)

// runSvcHealing is Windows-only.
func runSvcHealing() error {
	return fmt.Errorf("service mode is Windows-only")
}
