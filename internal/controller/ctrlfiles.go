package controller

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
)

// Controller-local filesystem sandbox for the Files tab.
//
// The tab speaks Windows paths (C:\Users default, backslash joins)
// because the classic controller is a Windows PC. An on-device
// controller (tablet) has no C:\ — without mapping, the whole local
// pane errors. Mapping rules (non-Windows only; Windows is identity):
//   - backslashes become slashes, a drive-letter prefix is stripped,
//     and the result is jailed under <tmp>/RMM/files;
//   - paths that are already native (no backslash, no drive letter)
//     pass through untouched (operator's own device, same trust);
//   - ".." escapes are refused; empty is refused.
// Fresh tablets therefore browse an app-private home instead of
// errors, and every Windows-style join the UI builds re-maps
// statelessly on each call.

func ctrlFilesRoot() string {
	if runtime.GOOS == "windows" {
		return ""
	}
	return filepath.Join(os.TempDir(), "RMM", "files")
}

// mapSandboxPath maps p into root. Pure for unit tests.
func mapSandboxPath(root, p string) (string, error) {
	if p == "" {
		return "", fmt.Errorf("path required")
	}
	if !strings.Contains(p, "\\") && !(len(p) >= 2 && p[1] == ':') {
		return p, nil
	}
	q := strings.ReplaceAll(p, "\\", "/")
	if len(q) >= 2 && q[1] == ':' && ((q[0] >= 'A' && q[0] <= 'Z') || (q[0] >= 'a' && q[0] <= 'z')) {
		q = q[2:]
	}
	c := path.Clean("/" + strings.TrimPrefix(q, "/"))
	rel := strings.TrimPrefix(c, "/")
	if rel == ".." || strings.HasPrefix(rel, "../") || strings.Contains(rel, "/../") {
		return "", fmt.Errorf("path escapes the files home")
	}
	if rel == "" || rel == "." {
		return root, nil
	}
	return filepath.Join(root, filepath.FromSlash(rel)), nil
}

// ctrlLocalPath maps a UI-supplied controller-local path for this
// platform, creating the sandbox home on first use.
func ctrlLocalPath(p string) (string, error) {
	root := ctrlFilesRoot()
	if root == "" {
		if p == "" {
			return "", fmt.Errorf("path required")
		}
		return p, nil
	}
	if err := os.MkdirAll(root, 0755); err != nil {
		return "", err
	}
	return mapSandboxPath(root, p)
}
