package commands

import (
	"strings"
	"testing"

	"rmm/internal/version"
)

// VersionReport must lead with the running binary's version: the
// controller UI parses the first dotted triple out of `version` output,
// and the binary line is the only one that reflects the live process
// (file/pending/prev lines describe on-disk update state).
func TestVersionReportLeadsWithBinary(t *testing.T) {
	rep := VersionReport()
	lines := strings.Split(strings.TrimSpace(rep), "\n")
	if len(lines) == 0 {
		t.Fatal("empty report")
	}
	if lines[0] != version.Agent() {
		t.Fatalf("first line = %q, want binary %q", lines[0], version.Agent())
	}
	joined := strings.Join(lines, "\n")
	for _, want := range []string{"file=", "prev="} {
		if !strings.Contains(joined, want) {
			t.Fatalf("report missing %q:\n%s", want, rep)
		}
	}
}
