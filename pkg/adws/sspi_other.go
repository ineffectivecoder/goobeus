//go:build !windows
// +build !windows

package adws

import (
	"fmt"
	"net/http"
	"time"
)

// createSSPIClient is not available on non-Windows platforms.
// Returns an error indicating SSPI is Windows-only.
func createSSPIClient(base http.RoundTripper, timeout time.Duration) (*http.Client, error) {
	return nil, fmt.Errorf("SSPI authentication is only available on Windows")
}
