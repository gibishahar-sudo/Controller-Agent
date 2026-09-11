// Command controller-native is the RMM controller with a native WebView2
// window (no browser needed). All server logic lives in internal/controller;
// this wrapper only adds the WebView2 frontend.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/jchv/go-webview2"
	"rmm/internal/controller"
)

func main() {
	opts := controller.Options{
		EnableNtfy:     true,
		EnableTCPRelay: true,
	}
	var native bool
	flag.StringVar(&opts.Addr, "addr", ":4444", "TLS listen address")
	flag.StringVar(&opts.CertFile, "cert", "certs/server.crt", "TLS certificate file")
	flag.StringVar(&opts.KeyFile, "key", "certs/server.key", "TLS key file")
	flag.StringVar(&opts.HTTPAddr, "http", "127.0.0.1:8080", "HTTP UI listen address (empty to disable)")
	flag.StringVar(&opts.ScreensDir, "screens", "screenshots", "directory to save screenshots")
	flag.StringVar(&opts.NtfyTopic, "ntfy", "", "ntfy relay topic (empty = default)")
	flag.StringVar(&opts.NtfyServer, "ntfy-server", "", "ntfy relay host (empty = default)")
	flag.BoolVar(&native, "native", true, "run as native WebView2 window (not browser)")
	flag.BoolVar(&opts.AutoOpen, "open", false, "auto-open browser (ignored when --native)")
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

	if !native || opts.HTTPAddr == "" {
		fmt.Println("[*] Native window disabled, running headless (Ctrl+C to stop)")
		go controller.RunStdinLoop(srv)
		select {}
	}

	time.Sleep(300 * time.Millisecond)
	dataPath := ""
	if localApp := os.Getenv("LOCALAPPDATA"); localApp != "" {
		dataPath = filepath.Join(localApp, "RMM", "EBWebView")
		_ = os.MkdirAll(dataPath, 0755)
	}
	url := "http://" + opts.HTTPAddr + "/"
	fmt.Printf("[*] Starting native window -> %s\n", url)
	w := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug: false, AutoFocus: true, DataPath: dataPath,
		WindowOptions: webview2.WindowOptions{Title: "Controller Client", Width: 1000, Height: 700, Center: true},
	})
	if w == nil {
		log.Printf("[!] WebView2 failed, falling back to browser")
		go controller.RunStdinLoop(srv)
		controller.OpenBrowser(url)
		select {}
	}
	defer w.Destroy()
	w.SetSize(1000, 700, webview2.HintNone)
	w.Navigate(url)
	w.Run()
	fmt.Println("[*] Window closed, shutting down...")
}
