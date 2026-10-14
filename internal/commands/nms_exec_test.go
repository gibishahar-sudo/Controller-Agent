package commands

import (
	"os"
	"strings"
	"testing"
	"time"
)

// nms-exec gates mirror clone: unreachable/managed/unknown/excluded all
// refuse with directions; unknown + force + confirm runs the pipeline.
func TestNMSExecGates(t *testing.T) {
	withNMSRoot(t, t.TempDir())
	oldDial, oldRead := dialTCP, nmsReadUNC
	t.Cleanup(func() { dialTCP, nmsReadUNC = oldDial, oldRead })

	dialTCP = func(string, int, time.Duration) bool { return false }
	if _, err := NMSHandle("nms-exec", "192.0.2.100 -- hostname", nil); err == nil ||
		!strings.Contains(err.Error(), "unreachable") {
		t.Fatalf("dead host must refuse, got %v", err)
	}
	dialTCP = func(string, int, time.Duration) bool { return true }
	nmsReadUNC = func(string) ([]byte, error) { return []byte("1.49.10"), nil }
	if _, err := NMSHandle("nms-exec", "192.0.2.101 -- hostname", nil); err == nil ||
		!strings.Contains(err.Error(), "own agent row") {
		t.Fatalf("managed host must redirect, got %v", err)
	}
	nmsReadUNC = func(string) ([]byte, error) { return nil, os.ErrPermission }
	if _, err := NMSHandle("nms-exec", "192.0.2.102 -- hostname", nil); err == nil ||
		!strings.Contains(err.Error(), "--force") {
		t.Fatalf("unknown host must demand force, got %v", err)
	}
	if _, err := NMSHandle("nms-exec", "192.0.2.102 --force -- hostname", nil); err == nil ||
		!strings.Contains(err.Error(), "--confirm YES") {
		t.Fatalf("force without confirm must refuse, got %v", err)
	}
}

// Full pipeline with fakes: staged uniquely, launched, output collected
// capped, both remote files deleted.
func TestNMSRemoteRunPipeline(t *testing.T) {
	withNMSRoot(t, t.TempDir())
	var written []string
	var launched []string
	var deleted []string
	oldWrite, oldCreate, oldRead, oldDel := nmsSMBWriteFile, nmsRemoteCreate, nmsReadUNC, nmsRemoteDelete
	t.Cleanup(func() {
		nmsSMBWriteFile, nmsRemoteCreate, nmsReadUNC, nmsRemoteDelete = oldWrite, oldCreate, oldRead, oldDel
	})
	nmsSMBWriteFile = func(dest string, data []byte) error { written = append(written, dest); return nil }
	nmsRemoteCreate = func(host, cmd string) error { launched = append(launched, host+"|"+cmd); return nil }
	nmsReadUNC = func(path string) ([]byte, error) { return []byte("HOST-PC\nok"), nil }
	nmsRemoteDelete = func(path string) error { deleted = append(deleted, path); return nil }

	out, err := NMSRemoteRun("192.0.2.103", "hostname", 30*time.Second)
	if err != nil || out != "HOST-PC\nok" {
		t.Fatalf("pipeline: %q %v", out, err)
	}
	if len(written) != 1 || !strings.HasSuffix(written[0], ".bat") {
		t.Fatalf("one bat staged, got %q", written)
	}
	if len(launched) != 1 || !strings.Contains(launched[0], "192.0.2.103") {
		t.Fatalf("one launch, got %q", launched)
	}
	if len(deleted) != 2 {
		t.Fatalf("bat+out must be deleted, got %q", deleted)
	}
	// Second run stages a different name (no collisions across runs).
	written = nil
	if _, err := NMSRemoteRun("192.0.2.103", "hostname", 30*time.Second); err != nil {
		t.Fatal(err)
	}
	if len(written) != 1 {
		t.Fatalf("second run must stage exactly once, got %q", written)
	}
}

// Output caps at 64KB in the verb reply (remote may return up to 1MB).
func TestNMSRemoteRunCaps(t *testing.T) {
	withNMSRoot(t, t.TempDir())
	oldDial, oldRead, oldWrite, oldCreate, oldDel := dialTCP, nmsReadUNC, nmsSMBWriteFile, nmsRemoteCreate, nmsRemoteDelete
	t.Cleanup(func() {
		dialTCP, nmsReadUNC, nmsSMBWriteFile, nmsRemoteCreate, nmsRemoteDelete = oldDial, oldRead, oldWrite, oldCreate, oldDel
	})
	dialTCP = func(string, int, time.Duration) bool { return true }
	big := make([]byte, 2*1024*1024)
	for i := range big {
		big[i] = 'x'
	}
	nmsReadUNC = func(path string) ([]byte, error) {
		if strings.HasSuffix(path, "version.txt") {
			return nil, os.ErrNotExist // unmanaged
		}
		return big, nil // the .out file: 2MB
	}
	nmsSMBWriteFile = func(string, []byte) error { return nil }
	nmsRemoteCreate = func(string, string) error { return nil }
	nmsRemoteDelete = func(string) error { return nil }
	res, err := NMSHandle("nms-exec", "192.0.2.104 -- bigdump", nil)
	if err != nil {
		t.Fatalf("capped run must succeed, got %v", err)
	}
	if len(res) > 64*1024+100 || !strings.HasSuffix(res, "[truncated at 64KB]") {
		t.Fatalf("reply must cap at 64KB with marker, got %d bytes tail %q", len(res), res[max(0, len(res)-40):])
	}
}

// Timeout path: out file never appears, error names the timeout, staging
// still cleaned.
func TestNMSRemoteRunTimeout(t *testing.T) {
	withNMSRoot(t, t.TempDir())
	oldWrite, oldCreate, oldRead, oldDel := nmsSMBWriteFile, nmsRemoteCreate, nmsReadUNC, nmsRemoteDelete
	var deleted int
	t.Cleanup(func() {
		nmsSMBWriteFile, nmsRemoteCreate, nmsReadUNC, nmsRemoteDelete = oldWrite, oldCreate, oldRead, oldDel
	})
	nmsSMBWriteFile = func(string, []byte) error { return nil }
	nmsRemoteCreate = func(string, string) error { return nil }
	nmsReadUNC = func(string) ([]byte, error) { return nil, os.ErrNotExist }
	nmsRemoteDelete = func(string) error { deleted++; return nil }
	_, err := NMSRemoteRun("192.0.2.105", "sleep 999", 6*time.Second)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("must time out, got %v", err)
	}
	if deleted != 2 {
		t.Fatalf("timeout must still clean bat+out, got %d", deleted)
	}
}

// Verb parsing: -- separator, timeout validation, missing command.
func TestNMSExecParsing(t *testing.T) {
	withNMSRoot(t, t.TempDir())
	if _, err := NMSHandle("nms-exec", "192.0.2.106", nil); err == nil ||
		!strings.Contains(err.Error(), "usage") {
		t.Fatalf("bare host must show usage, got %v", err)
	}
	oldDial, oldRead := dialTCP, nmsReadUNC
	t.Cleanup(func() { dialTCP, nmsReadUNC = oldDial, oldRead })
	dialTCP = func(string, int, time.Duration) bool { return true }
	nmsReadUNC = func(string) ([]byte, error) { return nil, os.ErrNotExist }
	if _, err := NMSHandle("nms-exec", "192.0.2.107 --timeout 3 -- hostname", nil); err == nil ||
		!strings.Contains(err.Error(), "--timeout") {
		t.Fatalf("bad timeout must fail, got %v", err)
	}
}
