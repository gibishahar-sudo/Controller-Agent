// Command controller-native is the RMM controller with a native WebView2
// window (no browser needed). All server logic lives in internal/controller;
// this wrapper only adds the WebView2 frontend.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jchv/go-webview2"
	"rmm/internal/controller"
	"rmm/internal/version"
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
	flag.StringVar(&opts.NtfyTopic, "ntfy", "", "REMOVED in v1.45; accepted and ignored")
	flag.StringVar(&opts.NtfyServer, "ntfy-server", "", "REMOVED in v1.45; accepted and ignored")
	flag.StringVar(&opts.House, "house", "", "house label shown in UI (e.g. Home)")
	flag.BoolVar(&native, "native", true, "run as native WebView2 window (not browser)")
	flag.BoolVar(&opts.AutoOpen, "open", false, "auto-open browser (ignored when --native)")
	noNtfy := flag.Bool("no-ntfy", false, "REMOVED in v1.45; accepted and ignored")
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
	// Navigate to THIS process's UI address: if the configured HTTP port
	// was taken by another controller, the server fell back to an ephemeral
	// port — opening the configured URL would show the other instance.
	uiAddr := srv.HTTPAddr()
	if uiAddr == "" {
		uiAddr = opts.HTTPAddr
	}
	url := "http://" + uiAddr + "/"
	fmt.Printf("[*] Starting native window -> %s\n", url)
	title := "RMM Controller " + version.Version
	if opts.House != "" {
		title += " - " + opts.House
		fmt.Printf("[*] House: %s\n", opts.House)
	}
	w := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug: false, AutoFocus: true, DataPath: dataPath,
		WindowOptions: webview2.WindowOptions{Title: title, Width: 1000, Height: 700, Center: true},
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
	// Native mic bridge: this embedded frame has no web speech service, so
	// the page's mic buttons call window.nativeMicListen() (bound below)
	// instead of webkitSpeechRecognition. Recognition runs here via in-box
	// Windows Speech Recognition; the transcript returns through Eval,
	// filling the command box and auto-sending exactly like the web path.
	// A busy flag in the page stops double-taps; results are JSON-encoded
	// so quotes in speech can't break the snippet. micReset() clears both
	// tab buttons (Commands + Jarvis); the transcript still lands in the
	// shared command box either way.
	if err := w.Bind("nativeMicListen", func() string {
		go func() {
			text := windowsSpeechOnce(45 * time.Second)
			w.Dispatch(func() {
				if strings.TrimSpace(text) == "" {
					w.Eval(`(function(){micReset();addTerm("🎙 heard nothing — try again","out");})()`)
					return
				}
				full, _ := json.Marshal("voice-cmd " + text)
				bare, _ := json.Marshal(text)
				w.Eval(`(function(){var box=document.getElementById("cmdInput");micReset();if(!box){toast("No command box","err");return;}box.value=` + string(full) + `;box.focus();addTerm("🎙 heard: "+` + string(bare) + `,"out");sendCmd();})()`)
			})
		}()
		return ""
	}); err != nil {
		log.Printf("[!] native mic bind failed: %v (page mic falls back to web speech)", err)
	}
	w.Run()
	fmt.Println("[*] Window closed, shutting down...")
}
