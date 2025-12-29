//go:build !windows
// +build !windows

package main

import "fmt"

// Windows-only commands return helpful error messages on other platforms

// cmdPTT - Windows only
func cmdPTT(args []string) error {
	return fmt.Errorf("ptt requires Windows")
}

// cmdDump - Windows only
func cmdDump(args []string) error {
	return fmt.Errorf("dump requires Windows")
}

// cmdTGTDeleg - Windows only
func cmdTGTDeleg(args []string) error {
	return fmt.Errorf("tgtdeleg requires Windows")
}

// cmdTriage - Windows only
func cmdTriage(args []string) error {
	return fmt.Errorf("triage requires Windows")
}

// cmdKlist - Windows only
func cmdKlist(args []string) error {
	return fmt.Errorf("klist requires Windows")
}

// cmdPurge - Windows only
func cmdPurge(args []string) error {
	return fmt.Errorf("purge requires Windows")
}

// cmdMonitor - Windows only
func cmdMonitor(args []string) error {
	return fmt.Errorf("monitor requires Windows")
}

// cmdHarvest - Windows only
func cmdHarvest(args []string) error {
	return fmt.Errorf("harvest requires Windows")
}

// cmdCurrentLUID - Windows only
func cmdCurrentLUID(args []string) error {
	return fmt.Errorf("currentluid requires Windows")
}

// cmdCreateNetOnly - Windows only
func cmdCreateNetOnly(args []string) error {
	return fmt.Errorf("createnetonly requires Windows")
}
