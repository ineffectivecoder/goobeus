//go:build windows
// +build windows

package adws

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/alexbrainman/sspi"
	"github.com/alexbrainman/sspi/negotiate"
)

// EDUCATIONAL: Windows SSPI (Security Support Provider Interface)
//
// SSPI is Windows' native authentication API. It handles:
//   - Kerberos (if domain-joined and TGT available)
//   - NTLM (fallback)
//   - Negotiate (picks best option automatically)
//
// This allows goobeus to use the current user's cached Kerberos TGT
// for ADWS authentication without requiring explicit credentials!

// sspiTransport wraps http.RoundTripper with SSPI Negotiate auth.
type sspiTransport struct {
	Transport http.RoundTripper
	cred      *sspi.Credentials
}

// newSSPITransport creates a transport that uses Windows SSPI for auth.
func newSSPITransport(base http.RoundTripper) (*sspiTransport, error) {
	// Acquire credentials for the current user
	cred, err := negotiate.AcquireCurrentUserCredentials()
	if err != nil {
		return nil, fmt.Errorf("failed to acquire SSPI credentials: %w", err)
	}

	return &sspiTransport{
		Transport: base,
		cred:      cred,
	}, nil
}

// RoundTrip implements http.RoundTripper with SSPI Negotiate authentication.
func (t *sspiTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Step 1: Send initial request without auth
	resp, err := t.Transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	// Step 2: Check if server requires auth (401 with WWW-Authenticate: Negotiate)
	if resp.StatusCode != http.StatusUnauthorized {
		return resp, nil
	}

	authHeader := resp.Header.Get("WWW-Authenticate")
	if authHeader == "" || (authHeader != "Negotiate" && !strings.HasPrefix(authHeader, "Negotiate ")) {
		// Not a Negotiate challenge, return as-is
		return resp, nil
	}
	resp.Body.Close()

	// Step 3: Create security context and get initial token
	secCtx, token, err := negotiate.NewClientContext(t.cred, extractHost(req.Host))
	if err != nil {
		return nil, fmt.Errorf("failed to create SSPI context: %w", err)
	}
	defer secCtx.Release()

	// Step 4: Send request with Negotiate token
	req2 := req.Clone(req.Context())
	req2.Header.Set("Authorization", "Negotiate "+base64.StdEncoding.EncodeToString(token))

	resp, err = t.Transport.RoundTrip(req2)
	if err != nil {
		return nil, err
	}

	// Step 5: Handle multi-leg authentication if needed
	if resp.StatusCode == http.StatusUnauthorized {
		authHeader = resp.Header.Get("WWW-Authenticate")
		if strings.HasPrefix(authHeader, "Negotiate ") {
			// Server sent continuation challenge
			serverToken, err := base64.StdEncoding.DecodeString(authHeader[10:])
			if err == nil && len(serverToken) > 0 {
				done, responseToken, err := secCtx.Update(serverToken)
				if err != nil {
					resp.Body.Close()
					return nil, fmt.Errorf("SSPI update failed: %w", err)
				}

				if !done && len(responseToken) > 0 {
					resp.Body.Close()
					req3 := req.Clone(req.Context())
					req3.Header.Set("Authorization", "Negotiate "+base64.StdEncoding.EncodeToString(responseToken))
					return t.Transport.RoundTrip(req3)
				}
			}
		}
	}

	return resp, nil
}

// extractHost removes port from host:port if present
func extractHost(hostPort string) string {
	if idx := strings.LastIndex(hostPort, ":"); idx != -1 {
		// Check if this looks like a port (numbers only after colon)
		port := hostPort[idx+1:]
		isPort := true
		for _, c := range port {
			if c < '0' || c > '9' {
				isPort = false
				break
			}
		}
		if isPort {
			return hostPort[:idx]
		}
	}
	return hostPort
}

// Close releases SSPI resources.
func (t *sspiTransport) Close() error {
	if t.cred != nil {
		return t.cred.Release()
	}
	return nil
}

// createSSPIClient creates an HTTP client with SSPI auth for Windows.
func createSSPIClient(base http.RoundTripper, timeout time.Duration) (*http.Client, error) {
	transport, err := newSSPITransport(base)
	if err != nil {
		return nil, err
	}

	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}, nil
}
