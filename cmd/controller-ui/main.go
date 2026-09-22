// Command controller-ui is the RMM controller with auto-open browser UI.
// All logic lives in internal/controller; this is a thin flag wrapper.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"rmm/internal/controller"
)

func main() {
	opts := controller.Options{
		EnableNtfy:     true,
		EnableTCPRelay: true,
		AutoOpen:       true,
	}
	flag.StringVar(&opts.Addr, "addr", ":4444", "TLS listen address")
	flag.StringVar(&opts.CertFile, "cert", "certs/server.crt", "TLS certificate file")
	flag.StringVar(&opts.KeyFile, "key", "certs/server.key", "TLS key file")
	flag.StringVar(&opts.HTTPAddr, "http", "127.0.0.1:8080", "HTTP UI listen address (empty to disable)")
	flag.StringVar(&opts.ScreensDir, "screens", "screenshots", "directory to save screenshots")
	flag.StringVar(&opts.NtfyTopic, "ntfy", "", "ntfy relay topic (empty = default)")
	flag.StringVar(&opts.NtfyServer, "ntfy-server", "", "ntfy relay host (empty = default)")
	flag.StringVar(&opts.House, "house", "", "house label shown in UI (e.g. Home)")
	flag.BoolVar(&opts.AutoOpen, "open", true, "auto-open browser")
	noNtfy := flag.Bool("no-ntfy", false, "disable ntfy relay")
	noRelay := flag.Bool("no-relay", false, "disable TCP relay dial-out")
	flag.Parse()
	if *noNtfy {
		opts.EnableNtfy = false
	}
	if *noRelay {
		opts.EnableTCPRelay = false
	}

	srv, err := controller.StartBackground(opts)
	if err != nil {
		log.Fatalf("start: %v", err)
	}
	defer srv.Close()

	go controller.RunStdinLoop(srv)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh
	fmt.Println("\n[*] Signal received, shutting down...")
}
