package mobile

import (
	"rmm/internal/controller"
	"rmm/internal/version"
)

// ControllerVersion returns the phone controller version (for UI).
func ControllerVersion() string { return version.PhoneControllerVersion }

// AgentVersion returns the phone agent version.
func AgentVersion() string { return version.PhoneAgentVersion }

// StartController starts the controller service in the background.
// It is called from Kotlin on app launch. The controller runs on
// localhost:8080 (WebView) and 0.0.0.0:4444 (TLS).
func StartController(certFile, keyFile, httpAddr, screensDir string) string {
	opts := controller.Options{
		Addr:           ":4444",
		ExtraAddrs:     []string{":443", ":22", ":53", ":80", ":4445"},
		CertFile:       certFile,
		KeyFile:        keyFile,
		HTTPAddr:       httpAddr,
		ScreensDir:     screensDir,
		EnableNtfy:     false, // ntfy removed in v1.45 (direct + MQTT only)
		EnableTCPRelay: false, // mobile: no local relay
	}
	if httpAddr == "" {
		httpAddr = "127.0.0.1:8080"
	}
	opts.HTTPAddr = httpAddr
	srv, err := controller.StartBackground(opts)
	if err != nil {
		return "error: " + err.Error()
	}
	_ = srv
	return "controller started on " + httpAddr + " version " + version.PhoneControllerVersion
}

// StartAgent starts the agent service.
func StartAgent(controllerAddr, caFile string) string {
	// This is a stub for gomobile bind - the real agent is started via
	// a foreground service that runs the Go binary. For now, just return
	// the version to prove the bind works.
	return "agent " + version.PhoneAgentVersion + " ready for " + controllerAddr
}
