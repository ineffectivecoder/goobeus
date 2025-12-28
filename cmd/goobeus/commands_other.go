//go:build !windows
// +build !windows

package main

import "fmt"

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
