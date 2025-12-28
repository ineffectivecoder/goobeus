package adws

import (
	"context"
	"fmt"
)

// EDUCATIONAL: SPN Enumeration via ADWS
//
// Service Principal Names (SPNs) identify services in Active Directory.
// Accounts with SPNs set are targets for Kerberoasting because:
// 1. Any authenticated user can request a TGS for any SPN
// 2. The TGS is encrypted with the service account's password hash
// 3. We can extract and crack this hash offline
//
// Common kerberoastable SPNs:
// - MSSQLSvc/server:1433 (SQL Server)
// - HTTP/webserver (IIS sites)
// - exchangeMDB/server (Exchange)
// - WSMAN/server (WinRM)
//
// We skip computer accounts (they have random 120-char passwords).

// SPNEntry represents a Kerberoastable account.
type SPNEntry struct {
	SAMAccountName    string
	DistinguishedName string
	UserPrincipalName string
	SPNs              []string
	Description       string
}

// FindKerberoastable returns all user accounts with SPNs set.
//
// EDUCATIONAL: Kerberoast Target Discovery
//
// This queries AD for accounts where:
// - servicePrincipalName is set
// - objectClass is NOT computer (computers have random passwords)
// - Account is enabled (optionally)
//
// The ADWS query is equivalent to LDAP filter:
// (&(servicePrincipalName=*)(!(objectClass=computer)))
func (c *Client) FindKerberoastable(ctx context.Context) ([]SPNEntry, error) {
	return c.FindKerberoastableInOU(ctx, "")
}

// FindKerberoastableInOU finds kerberoastable accounts in a specific OU.
func (c *Client) FindKerberoastableInOU(ctx context.Context, baseOU string) ([]SPNEntry, error) {
	// Build WS-Enumeration request for SPN query
	filter := `(&amp;(servicePrincipalName=*)(!(objectClass=computer))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))`

	body := fmt.Sprintf(`<wsen:Enumerate>
      <ad:filter>%s</ad:filter>
      <ad:selection>
        <ad:Path>sAMAccountName</ad:Path>
        <ad:Path>distinguishedName</ad:Path>
        <ad:Path>userPrincipalName</ad:Path>
        <ad:Path>servicePrincipalName</ad:Path>
        <ad:Path>description</ad:Path>
      </ad:selection>
    </wsen:Enumerate>`, filter)

	resp, err := c.sendSOAP(ctx, c.enumerateURL(),
		"http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate", body)
	if err != nil {
		return nil, fmt.Errorf("enumerate failed: %w", err)
	}

	// Parse response
	objects, err := parseEnumerateResponse(resp)
	if err != nil {
		return nil, fmt.Errorf("parse failed: %w", err)
	}

	// Convert to SPNEntry
	var entries []SPNEntry
	for _, obj := range objects {
		if len(obj.SPNs) > 0 {
			entries = append(entries, SPNEntry{
				SAMAccountName:    obj.SAMAccountName,
				DistinguishedName: obj.DN,
				UserPrincipalName: obj.UserPrincipalName,
				SPNs:              obj.SPNs,
				Description:       obj.Description,
			})
		}
	}

	return entries, nil
}

// UserEntry represents a user account for AS-REP roasting.
type UserEntry struct {
	SAMAccountName    string
	DistinguishedName string
	UserPrincipalName string
	Description       string
}

// FindASREPRoastable returns accounts without pre-authentication required.
//
// EDUCATIONAL: AS-REP Roast Target Discovery
//
// AS-REP Roasting targets accounts with "Do not require Kerberos preauthentication".
// These accounts return encrypted data in AS-REP without validating password first.
//
// The userAccountControl flag for DONT_REQ_PREAUTH is 0x400000 (4194304).
// LDAP filter: (userAccountControl:1.2.840.113556.1.4.803:=4194304)
func (c *Client) FindASREPRoastable(ctx context.Context) ([]UserEntry, error) {
	// 4194304 = DONT_REQ_PREAUTH flag
	filter := `(userAccountControl:1.2.840.113556.1.4.803:=4194304)`

	body := fmt.Sprintf(`<wsen:Enumerate>
      <ad:filter>%s</ad:filter>
      <ad:selection>
        <ad:Path>sAMAccountName</ad:Path>
        <ad:Path>distinguishedName</ad:Path>
        <ad:Path>userPrincipalName</ad:Path>
        <ad:Path>description</ad:Path>
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

	var entries []UserEntry
	for _, obj := range objects {
		entries = append(entries, UserEntry{
			SAMAccountName:    obj.SAMAccountName,
			DistinguishedName: obj.DN,
			UserPrincipalName: obj.UserPrincipalName,
			Description:       obj.Description,
		})
	}

	return entries, nil
}
