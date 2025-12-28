//go:build !windows
// +build !windows

package main

import "fmt"

// getSessionDomain returns an error on non-Windows.
func getSessionDomain() (string, error) {
	return "", fmt.Errorf("session domain detection requires Windows")
}
