package main

import (
	"context"
	"encoding/json"
	"time"
)

/*
	Optional daily update check (Update page > "Check for updates once a day", off by default).

	When the setting is on, one request to the GitHub releases API is made about every 24 hours (first one a few minutes
	after start, so a restart loop never hammers GitHub). The result refreshes the release list cached on disk, which is
	what the top bar badge reads (/api/updater/badge, no network), and an "update available" notification is sent once
	per tag. Nothing is downloaded or installed: updating stays a button an administrator presses.
*/

const (
	updateAutoFirstDelay = 5 * time.Minute
	updateAutoInterval   = 24 * time.Hour
	updateAutoPoll       = 10 * time.Minute // how often the loop looks whether it is due (cheap, no network)
)

// startUpdateAutoCheck runs until the process ends. It re-reads the setting each time, so toggling it needs no restart.
func startUpdateAutoCheck() {
	go func() {
		due := time.Now().Add(updateAutoFirstDelay)
		for {
			time.Sleep(updateAutoPoll)
			if updateManager == nil || !updateManager.AutoCheckEnabled() {
				due = time.Now().Add(updateAutoFirstDelay) // turned off or on later: the next check is a few minutes after it is on
				continue
			}
			if time.Now().Before(due) || updateManager.Busy() {
				continue
			}
			runUpdateAutoCheck()
			due = time.Now().Add(updateAutoInterval)
		}
	}()
}

func runUpdateAutoCheck() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := updateManager.Check(ctx, true)
	if err != nil {
		if SystemWideLogger != nil {
			SystemWideLogger.PrintAndLog("updater", "Daily update check failed", err)
		}
		return
	}
	if b, err := json.Marshal(map[string]any{"result": res}); err == nil {
		announceUpdate(b)
	}
}
