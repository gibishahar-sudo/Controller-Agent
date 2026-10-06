package controller

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"rmm/internal/protocol"
	"rmm/internal/version"
)

// RunStdinLoop provides the headless interactive console:
// <shell> | screenshot | ping | status | version | exit.
func RunStdinLoop(s *Server) {
	fmt.Printf("RMM controller %s — type 'help' for commands\n", version.Version)
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Print("> ")
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			fmt.Print("> ")
			continue
		}
		switch line {
		case "exit", "quit":
			fmt.Println("Shutting down...")
			s.Close()
			os.Exit(0)
		case "help":
			fmt.Println("Commands: <shell> | screenshot | ping | status | version | voice-cmd ... | memory ... | llm-say ... | llm-status | exit")
			fmt.Print("> ")
			continue
		case "version":
			fmt.Printf("%s (agents: %d)\n", version.Controller(), len(s.Agents()))
			fmt.Print("> ")
			continue
		case "status":
			agents := s.Agents()
			if len(agents) == 0 {
				fmt.Println("No agents connected")
			} else {
				for _, a := range agents {
					fmt.Printf("Agent %s: %s (%s) remote=%s latency=%vms\n",
						a["id"], a["hostname"], a["user"], a["remote"], a["latency"])
				}
			}
			fmt.Print("> ")
			continue
		}
		// Controller-side llm pseudo-commands first (need no agent).
		if h, rep := s.tryLLMCmd(line); h {
			if rep != "" {
				fmt.Println(rep)
			}
			fmt.Print("> ")
			continue
		}
		ac := s.getAgent()
		if ac == nil {
			ac = s.voiceTarget(nil, line)
		}
		if ac == nil {
			fmt.Println("No agent connected")
			fmt.Print("> ")
			continue
		}
		var msg protocol.Message
		// Jarvis: rewrite voice-cmd locally (replies broadcast + printed).
		if h, tac, run, rep, eid := s.tryVoiceCmd(ac, line, ""); h {
			if rep != "" {
				fmt.Println(rep)
			}
			if run == "" {
				fmt.Print("> ")
				continue
			}
			line = run
			if tac != nil {
				ac = tac
			}
			msg = protocol.Message{Type: protocol.TypeCommand, Cmd: line, CmdID: eid}
			if err := s.sendToAgent(ac, msg); err != nil {
				fmt.Printf("Send error: %v\n", err)
			} else {
				fmt.Printf("Sent command to %s via %s: %s\n", ac.id, ac.transport(), line)
			}
			fmt.Print("> ")
			continue
		}
		switch line {
		case "screenshot":
			msg = protocol.Message{Type: protocol.TypeScreenshotRequest}
			fmt.Printf("Requesting screenshot from %s...\n", ac.id)
		case "ping":
			ac.pingSentMu.Lock()
			ac.pingSent = time.Now()
			ac.pingSentMu.Unlock()
			msg = protocol.Message{Type: protocol.TypePing}
		default:
			msg = protocol.Message{Type: protocol.TypeCommand, Cmd: line}
		}
		if err := s.sendToAgent(ac, msg); err != nil {
			fmt.Printf("Send error: %v\n", err)
		} else if msg.Type == protocol.TypeCommand {
			fmt.Printf("Sent command to %s via %s: %s\n", ac.id, ac.transport(), line)
		}
		fmt.Print("> ")
	}
	if err := scanner.Err(); err != nil {
		log.Printf("stdin: %v", err)
	}
	fmt.Println("[*] stdin closed, controller continues serving (Ctrl+C to stop)")
}
