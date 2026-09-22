// Package version is the single source of truth for versions.
// The suite shares one Version for coordinated releases, but each of the 4
// deliverables (desktop controller, desktop agent, phone controller, phone
// agent) also has its own constant so they can be bumped independently
// when only one side changes.
package version

const (
	// Version is the suite release (all 4 apps in one GitHub tag).
	Version = "1.40.18"
	Name    = "RMM"

	// Per-app versions (all equal for 1.4.0; bump individually as needed).
	DesktopControllerVersion = Version
	DesktopAgentVersion      = Version
	PhoneControllerVersion   = "1.0.0"
	PhoneAgentVersion        = "1.0.0"
)

func Agent() string      { return "rmm-agent " + DesktopAgentVersion }
func Controller() string { return "rmm-controller " + DesktopControllerVersion }
func PhoneAgent() string { return "rmm-phone-agent " + PhoneAgentVersion }
func PhoneController() string {
	return "rmm-phone-controller " + PhoneControllerVersion
}
