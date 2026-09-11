//go:build android

package main

import (
	"log"
	"golang.org/x/mobile/app"
	"golang.org/x/mobile/event/lifecycle"
	"golang.org/x/mobile/event/paint"
)

func main() {
	app.Main(func(a app.App) {
		for e := range a.Events() {
			switch e := a.Filter(e).(type) {
			case lifecycle.Event:
				if e.Crosses(lifecycle.StageVisible) == lifecycle.CrossOn {
					log.Println("Phone Agent visible")
				}
			case paint.Event:
				a.Publish()
			}
		}
	})
}
