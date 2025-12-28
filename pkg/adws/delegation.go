package adws

import (
	"context"
	"fmt"
)

// EDUCATIONAL: Delegation Enumeration via ADWS
//
// Kerberos delegation allows services to impersonate users. Finding delegation
// configurations is critical for attack path discovery:
//
// 1. Unconstrained Delegation (TRUSTED_FOR_DELEGATION)
//    - Most dangerous - TGTs are forwarded to the service
//    - Compromise = capture TGTs of any user who connects
//    - Find: (userAccountControl:1.2.840.113556.1.4.803:=524288)
//
// 2. Constrained Delegation (msDS-AllowedToDelegateTo)
//    - Can delegate to specific SPNs only
//    - Compromise = impersonate any user to those SPNs
//    - Find: (msDS-AllowedToDelegateTo=*)
//
// 3. Protocol Transition (TRUSTED_TO_AUTH_FOR_DELEGATION)
//    - Can use S4U2Self without existing ticket
//    - Combined with constrained delegation = powerful
//    - Find: (userAccountControl:1.2.840.113556.1.4.803:=16777216)
//
// 4. RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity)
//    - Target controls who can delegate TO it
//    - Writeable = we can add ourselves = compromise
//    - Find: (msDS-AllowedToActOnBehalfOfOtherIdentity=*)

// DelegationType represents the type of delegation configured.
type DelegationType int

const (
	DelegationNone DelegationType = iota
	DelegationUnconstrained
	DelegationConstrained
	DelegationRBCD
)

func (d DelegationType) String() string {
	switch d {
	case DelegationUnconstrained:
		return "Unconstrained"
	case DelegationConstrained:
		return "Constrained"
	case DelegationRBCD:
		return "Resource-Based Constrained (RBCD)"
	default:
		return "None"
	}
}

// DelegationEntry represents an account with delegation configured.
type DelegationEntry struct {
	SAMAccountName     string
	DistinguishedName  string
	Type               DelegationType
	AllowedToDelegate  []string // SPNs for constrained delegation
	ProtocolTransition bool     // Has TRUSTED_TO_AUTH_FOR_DELEGATION
	ObjectType         string   // "user" or "computer"
}

// FindUnconstrainedDelegation finds systems with unconstrained delegation.
//
// EDUCATIONAL: Unconstrained Delegation Attack
//
// Systems with TRUSTED_FOR_DELEGATION (524288) cache the TGTs of
// any user who authenticates to them. If we compromise such a system:
// 1. Wait for high-value user (admin) to connect
// 2. Extract their TGT from memory
// 3. Use TGT to impersonate them anywhere!
//
// Attack vectors:
// - PrinterBug: Force DC to auth to our compromised system
// - PetitPotam: Force DC to auth via EfsRpcOpenFileRaw
func (c *Client) FindUnconstrainedDelegation(ctx context.Context) ([]DelegationEntry, error) {
	// 524288 = TRUSTED_FOR_DELEGATION
	filter := `(userAccountControl:1.2.840.113556.1.4.803:=524288)`

	body := fmt.Sprintf(`<wsen:Enumerate>
      <ad:filter>%s</ad:filter>
      <ad:selection>
        <ad:Path>sAMAccountName</ad:Path>
        <ad:Path>distinguishedName</ad:Path>
        <ad:Path>objectClass</ad:Path>
        <ad:Path>userAccountControl</ad:Path>
      </ad:selection>
    </wsen:Enumerate>`, filter)

	resp, err := c.sendSOAP(ctx, c.enumerateURL(),
		"http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate", body)
	if err != nil {
		return nil, fmt.Errorf("enumerate failed: %w", err)
	}

	objects, err := parseEnumerateResponse(resp)
	if err != nil {
		return nil, fmt.Errorf("parse failed: %w", err)
	}

	var entries []DelegationEntry
	for _, obj := range objects {
		entry := DelegationEntry{
			SAMAccountName:    obj.SAMAccountName,
			DistinguishedName: obj.DN,
			Type:              DelegationUnconstrained,
		}

		// Determine object type
		for _, class := range obj.ObjectClass {
			if class == "computer" {
				entry.ObjectType = "computer"
				break
			} else if class == "user" {
				entry.ObjectType = "user"
			}
		}

		entries = append(entries, entry)
	}

	return entries, nil
}

// FindConstrainedDelegation finds accounts with constrained delegation.
//
// EDUCATIONAL: Constrained Delegation Attack
//
// Accounts with msDS-AllowedToDelegateTo can impersonate users to
// those specific SPNs. The attack:
// 1. Compromise account with constrained delegation
// 2. Use S4U2Self to get ticket "for" any user to ourselves
// 3. Use S4U2Proxy to exchange for ticket to allowed SPN
// 4. Access target service as impersonated user!
//
// SPN substitution trick: If allowed to cifs/server, you might be
// able to access ldap/server or http/server (same machine).
func (c *Client) FindConstrainedDelegation(ctx context.Context) ([]DelegationEntry, error) {
	filter := `(msDS-AllowedToDelegateTo=*)`

	body := fmt.Sprintf(`<wsen:Enumerate>
      <ad:filter>%s</ad:filter>
      <ad:selection>
        <ad:Path>sAMAccountName</ad:Path>
        <ad:Path>distinguishedName</ad:Path>
        <ad:Path>objectClass</ad:Path>
        <ad:Path>msDS-AllowedToDelegateTo</ad:Path>
        <ad:Path>userAccountControl</ad:Path>
      </ad:selection>
    </wsen:Enumerate>`, filter)

	resp, err := c.sendSOAP(ctx, c.enumerateURL(),
		"http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate", body)
	if err != nil {
		return nil, fmt.Errorf("enumerate failed: %w", err)
	}

	objects, err := parseEnumerateResponse(resp)
	if err != nil {
		return nil, fmt.Errorf("parse failed: %w", err)
	}

	var entries []DelegationEntry
	for _, obj := range objects {
		entry := DelegationEntry{
			SAMAccountName:    obj.SAMAccountName,
			DistinguishedName: obj.DN,
			Type:              DelegationConstrained,
		}

		// Get allowed SPNs
		if spns, ok := obj.RawAttributes["msDS-AllowedToDelegateTo"]; ok {
			entry.AllowedToDelegate = spns
		}

		// Check for protocol transition
		// 16777216 = TRUSTED_TO_AUTH_FOR_DELEGATION
		if uac := obj.UserAccountControl; uac&16777216 != 0 {
			entry.ProtocolTransition = true
		}

		for _, class := range obj.ObjectClass {
			if class == "computer" {
				entry.ObjectType = "computer"
				break
			} else if class == "user" {
				entry.ObjectType = "user"
			}
		}

		entries = append(entries, entry)
	}

	return entries, nil
}

// FindRBCDTargets finds objects with RBCD configured.
//
// EDUCATIONAL: RBCD (Resource-Based Constrained Delegation)
//
// Unlike classic delegation where the SOURCE specifies targets,
// RBCD lets the TARGET specify who can delegate to it via
// msDS-AllowedToActOnBehalfOfOtherIdentity.
//
// If we can WRITE this attribute on a computer:
// 1. Create a machine account (MAQ allows ~10)
// 2. Add our machine account's SID to target's RBCD attribute
// 3. Use S4U2Self+S4U2Proxy from our machine to target
// 4. Get ticket as admin to target!
func (c *Client) FindRBCDTargets(ctx context.Context) ([]DelegationEntry, error) {
	filter := `(msDS-AllowedToActOnBehalfOfOtherIdentity=*)`

	body := fmt.Sprintf(`<wsen:Enumerate>
      <ad:filter>%s</ad:filter>
      <ad:selection>
        <ad:Path>sAMAccountName</ad:Path>
        <ad:Path>distinguishedName</ad:Path>
        <ad:Path>objectClass</ad:Path>
        <ad:Path>msDS-AllowedToActOnBehalfOfOtherIdentity</ad:Path>
      </ad:selection>
    </wsen:Enumerate>`, filter)

	resp, err := c.sendSOAP(ctx, c.enumerateURL(),
		"http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate", body)
	if err != nil {
		return nil, fmt.Errorf("enumerate failed: %w", err)
	}

	objects, err := parseEnumerateResponse(resp)
	if err != nil {
		return nil, fmt.Errorf("parse failed: %w", err)
	}

	var entries []DelegationEntry
	for _, obj := range objects {
		entry := DelegationEntry{
			SAMAccountName:    obj.SAMAccountName,
			DistinguishedName: obj.DN,
			Type:              DelegationRBCD,
		}

		for _, class := range obj.ObjectClass {
			if class == "computer" {
				entry.ObjectType = "computer"
				break
			}
		}

		entries = append(entries, entry)
	}

	return entries, nil
}

// DelegationResults contains all delegation findings.
type DelegationResults struct {
	Unconstrained []DelegationEntry
	Constrained   []DelegationEntry
	RBCD          []DelegationEntry
}

// FindAllDelegation finds all delegation configurations in the domain.
func (c *Client) FindAllDelegation(ctx context.Context) (*DelegationResults, error) {
	results := &DelegationResults{}
	var err error

	results.Unconstrained, err = c.FindUnconstrainedDelegation(ctx)
	if err != nil {
		return nil, fmt.Errorf("unconstrained delegation query failed: %w", err)
	}

	results.Constrained, err = c.FindConstrainedDelegation(ctx)
	if err != nil {
		return nil, fmt.Errorf("constrained delegation query failed: %w", err)
	}

	results.RBCD, err = c.FindRBCDTargets(ctx)
	if err != nil {
		return nil, fmt.Errorf("RBCD query failed: %w", err)
	}

	return results, nil
}
