package adws

import (
	"context"
	"fmt"
)

// EDUCATIONAL: gMSA (Group Managed Service Accounts)
//
// gMSAs are special AD accounts with automatically rotated 240-character
// passwords. The password is stored in AD and can be retrieved by
// authorized principals listed in msDS-GroupMSAMembership.
//
// Attack relevance:
// 1. Find gMSA accounts
// 2. Check if we're in the allowed principals list
// 3. If allowed, retrieve the password blob
// 4. Use the password for Kerberos ticket requests
//
// Key attributes:
// - objectClass: msDS-GroupManagedServiceAccount
// - msDS-GroupMSAMembership: Who can retrieve the password
// - msDS-ManagedPassword: The actual password (if readable)

// GMSAEntry represents a Group Managed Service Account.
type GMSAEntry struct {
	SAMAccountName        string
	DistinguishedName     string
	Description           string
	ServicePrincipalNames []string
	AllowedPrincipals     []string // DNs that can retrieve password
	PasswordReadable      bool     // True if we can read the password
	// Note: Actual password retrieval requires special handling
}

// FindGMSA finds all Group Managed Service Accounts.
//
// EDUCATIONAL: gMSA Discovery
//
// gMSAs are identified by objectClass=msDS-GroupManagedServiceAccount.
// We enumerate them to find potential targets and check permissions.
func (c *Client) FindGMSA(ctx context.Context) ([]GMSAEntry, error) {
	filter := `(objectClass=msDS-GroupManagedServiceAccount)`

	body := fmt.Sprintf(`<wsen:Enumerate>
      <ad:filter>%s</ad:filter>
      <ad:selection>
        <ad:Path>sAMAccountName</ad:Path>
        <ad:Path>distinguishedName</ad:Path>
        <ad:Path>description</ad:Path>
        <ad:Path>servicePrincipalName</ad:Path>
        <ad:Path>msDS-GroupMSAMembership</ad:Path>
        <ad:Path>msDS-ManagedPassword</ad:Path>
      </ad:selection>
    </wsen:Enumerate>`, filter)

	resp, err := c.sendSOAP(ctx, c.enumerateURL(),
		"http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate", body)
	if err != nil {
		return nil, fmt.Errorf("gMSA enumerate failed: %w", err)
	}

	objects, err := parseEnumerateResponse(resp)
	if err != nil {
		return nil, fmt.Errorf("parse failed: %w", err)
	}

	var entries []GMSAEntry
	for _, obj := range objects {
		entry := GMSAEntry{
			SAMAccountName:        obj.SAMAccountName,
			DistinguishedName:     obj.DN,
			Description:           obj.Description,
			ServicePrincipalNames: obj.SPNs,
		}

		// Check for allowed principals
		if principals, ok := obj.RawAttributes["msDS-GroupMSAMembership"]; ok {
			entry.AllowedPrincipals = principals
		}

		// Check if password is readable (msDS-ManagedPassword will be present)
		if pwd, ok := obj.RawAttributes["msDS-ManagedPassword"]; ok && len(pwd) > 0 {
			entry.PasswordReadable = true
		}

		entries = append(entries, entry)
	}

	return entries, nil
}

// FindReadableGMSA finds gMSAs where we can potentially read the password.
//
// EDUCATIONAL: gMSA Password Access
//
// The msDS-ManagedPassword attribute is only readable if:
// 1. We're in the msDS-GroupMSAMembership list
// 2. We have special permissions (Domain Admins, etc.)
//
// The password blob structure (MSDS-MANAGEDPASSWORD_BLOB):
// - Version (USHORT)
// - Reserved (USHORT)
// - Length (ULONG)
// - CurrentPasswordOffset (USHORT)
// - PreviousPasswordOffset (USHORT)
// - QueryPasswordIntervalOffset (USHORT)
// - UnchangedPasswordIntervalOffset (USHORT)
// - CurrentPassword (variable)
// - PreviousPassword (variable, optional)
func (c *Client) FindReadableGMSA(ctx context.Context) ([]GMSAEntry, error) {
	entries, err := c.FindGMSA(ctx)
	if err != nil {
		return nil, err
	}

	var readable []GMSAEntry
	for _, entry := range entries {
		if entry.PasswordReadable {
			readable = append(readable, entry)
		}
	}

	return readable, nil
}

// GMSAStats provides summary statistics for gMSA accounts.
type GMSAStats struct {
	TotalGMSA         int
	PasswordsReadable int
	WithSPNs          int
}

// GetGMSAStats returns statistics about gMSA accounts.
func (c *Client) GetGMSAStats(ctx context.Context) (*GMSAStats, error) {
	entries, err := c.FindGMSA(ctx)
	if err != nil {
		return nil, err
	}

	stats := &GMSAStats{
		TotalGMSA: len(entries),
	}

	for _, entry := range entries {
		if entry.PasswordReadable {
			stats.PasswordsReadable++
		}
		if len(entry.ServicePrincipalNames) > 0 {
			stats.WithSPNs++
		}
	}

	return stats, nil
}
