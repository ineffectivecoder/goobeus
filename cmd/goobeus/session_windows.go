//go:build windows
// +build windows

package main

import (
	"github.com/goobeus/goobeus/pkg/windows"
)

// getSessionDomain returns the domain from the Windows ticket cache.
func getSessionDomain() (string, error) {
	return windows.GetCurrentDomain()
}
