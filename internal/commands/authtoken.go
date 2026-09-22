package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Agent registration token (Track B). The file lives next to the exe so it
// travels with installs/backups; empty = untokened install (accepted unless
// the controller enforces auth, flagged untrusted in the UI).

func agentTokenPath() string {
	if exe, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exe), "token.txt")
	}
	return filepath.Join(os.TempDir(), "token.txt")
}

// AgentToken returns the stored registration token ("" when absent).
func AgentToken() string {
	b, err := os.ReadFile(agentTokenPath())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// SetAgentToken stores the registration token. Tokens are operator secrets:
// 8-128 chars of letters, digits, dash, underscore, dot.
func SetAgentToken(tok string) (string, error) {
	tok = strings.TrimSpace(tok)
	if len(tok) < 8 || len(tok) > 128 {
		return "", fmt.Errorf("token must be 8-128 characters")
	}
	for _, c := range tok {
		if !(c == '-' || c == '_' || c == '.' ||
			(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return "", fmt.Errorf("token may only contain letters, digits, dash, underscore, dot")
		}
	}
	if err := os.WriteFile(agentTokenPath(), []byte(tok+"\n"), 0600); err != nil {
		return "", err
	}
	return "agent token stored", nil
}
