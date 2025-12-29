package adws

import (
	"context"
	"fmt"
	"strings"
)

// EDUCATIONAL: Computer Enumeration
//
// Enumerating computers helps identify:
// 1. Domain Controllers - High-value targets
// 2. Servers - Often have sensitive data/services
// 3. Workstations - Potential pivot points
// 4. Operating systems - Find vulnerable versions
//
// Key attributes:
// - operatingSystem, operatingSystemVersion
// - userAccountControl (flags indicate DC, etc.)
// - servicePrincipalName (indicates roles)

// ComputerEntry represents an AD computer object.
type ComputerEntry struct {
	SAMAccountName    string
	DistinguishedName string
	DNSHostName       string
	OperatingSystem   string
	OSVersion         string
	Description       string
	IsDC              bool     // Is a Domain Controller
	IsServer          bool     // Is a server OS
	SPNs              []string // Service Principal Names
	LastLogon         string
}

// FindComputers returns all computers in the domain.
func (c *Client) FindComputers(ctx context.Context) ([]ComputerEntry, error) {
	filter := `(objectClass=computer)`

	body := fmt.Sprintf(`<wsen:Enumerate>
      <ad:filter>%s</ad:filter>
      <ad:selection>
        <ad:Path>sAMAccountName</ad:Path>
        <ad:Path>distinguishedName</ad:Path>
        <ad:Path>dNSHostName</ad:Path>
        <ad:Path>operatingSystem</ad:Path>
        <ad:Path>operatingSystemVersion</ad:Path>
        <ad:Path>description</ad:Path>
        <ad:Path>servicePrincipalName</ad:Path>
        <ad:Path>userAccountControl</ad:Path>
        <ad:Path>lastLogonTimestamp</ad:Path>
      </ad:selection>
    </wsen:Enumerate>`, filter)

	resp, err := c.sendSOAP(ctx, c.enumerateURL(),
		"http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate", body)
	if err != nil {
		return nil, fmt.Errorf("computer enumerate failed: %w", err)
	}

	objects, err := parseEnumerateResponse(resp)
	if err != nil {
		return nil, fmt.Errorf("parse failed: %w", err)
	}

	var entries []ComputerEntry
	for _, obj := range objects {
		entry := ComputerEntry{
			SAMAccountName:    obj.SAMAccountName,
			DistinguishedName: obj.DN,
			Description:       obj.Description,
			SPNs:              obj.SPNs,
		}

		// Get DNS hostname
		if dns, ok := obj.RawAttributes["dNSHostName"]; ok && len(dns) > 0 {
			entry.DNSHostName = dns[0]
		}

		// Get OS info
		if os, ok := obj.RawAttributes["operatingSystem"]; ok && len(os) > 0 {
			entry.OperatingSystem = os[0]
		}
		if osv, ok := obj.RawAttributes["operatingSystemVersion"]; ok && len(osv) > 0 {
			entry.OSVersion = osv[0]
		}

		// Check if server OS
		if strings.Contains(strings.ToLower(entry.OperatingSystem), "server") {
			entry.IsServer = true
		}

		// Check if DC (UAC flag 0x2000 = SERVER_TRUST_ACCOUNT)
		if obj.UserAccountControl&0x2000 != 0 {
			entry.IsDC = true
			entry.IsServer = true
		}

		// Get last logon
		if ll, ok := obj.RawAttributes["lastLogonTimestamp"]; ok && len(ll) > 0 {
			entry.LastLogon = ll[0]
		}

		entries = append(entries, entry)
	}

	return entries, nil
}

// FindDomainControllers returns all Domain Controllers.
//
// EDUCATIONAL: Domain Controller Identification
//
// DCs are identified by:
// - userAccountControl flag SERVER_TRUST_ACCOUNT (0x2000)
// - Primary group = Domain Controllers
// - Distinguished name contains "OU=Domain Controllers"
func (c *Client) FindDomainControllers(ctx context.Context) ([]ComputerEntry, error) {
	// Filter by SERVER_TRUST_ACCOUNT flag
	filter := `(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))`

	body := fmt.Sprintf(`<wsen:Enumerate>
      <ad:filter>%s</ad:filter>
      <ad:selection>
        <ad:Path>sAMAccountName</ad:Path>
        <ad:Path>distinguishedName</ad:Path>
        <ad:Path>dNSHostName</ad:Path>
        <ad:Path>operatingSystem</ad:Path>
        <ad:Path>operatingSystemVersion</ad:Path>
        <ad:Path>servicePrincipalName</ad:Path>
      </ad:selection>
    </wsen:Enumerate>`, filter)

	resp, err := c.sendSOAP(ctx, c.enumerateURL(),
		"http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate", body)
	if err != nil {
		return nil, fmt.Errorf("DC enumerate failed: %w", err)
	}

	objects, err := parseEnumerateResponse(resp)
	if err != nil {
		return nil, fmt.Errorf("parse failed: %w", err)
	}

	var entries []ComputerEntry
	for _, obj := range objects {
		entry := ComputerEntry{
			SAMAccountName:    obj.SAMAccountName,
			DistinguishedName: obj.DN,
			SPNs:              obj.SPNs,
			IsDC:              true,
			IsServer:          true,
		}

		if dns, ok := obj.RawAttributes["dNSHostName"]; ok && len(dns) > 0 {
			entry.DNSHostName = dns[0]
		}
		if os, ok := obj.RawAttributes["operatingSystem"]; ok && len(os) > 0 {
			entry.OperatingSystem = os[0]
		}
		if osv, ok := obj.RawAttributes["operatingSystemVersion"]; ok && len(osv) > 0 {
			entry.OSVersion = osv[0]
		}

		entries = append(entries, entry)
	}

	return entries, nil
}

// FindServers returns all server computers (non-DC).
func (c *Client) FindServers(ctx context.Context) ([]ComputerEntry, error) {
	all, err := c.FindComputers(ctx)
	if err != nil {
		return nil, err
	}

	var servers []ComputerEntry
	for _, comp := range all {
		if comp.IsServer && !comp.IsDC {
			servers = append(servers, comp)
		}
	}

	return servers, nil
}

// FindWorkstations returns all workstation computers.
func (c *Client) FindWorkstations(ctx context.Context) ([]ComputerEntry, error) {
	all, err := c.FindComputers(ctx)
	if err != nil {
		return nil, err
	}

	var workstations []ComputerEntry
	for _, comp := range all {
		if !comp.IsServer {
			workstations = append(workstations, comp)
		}
	}

	return workstations, nil
}

// ComputerStats provides summary statistics.
type ComputerStats struct {
	Total        int
	DCs          int
	Servers      int
	Workstations int
	OSBreakdown  map[string]int
}

// GetComputerStats returns statistics about computers in the domain.
func (c *Client) GetComputerStats(ctx context.Context) (*ComputerStats, error) {
	all, err := c.FindComputers(ctx)
	if err != nil {
		return nil, err
	}

	stats := &ComputerStats{
		Total:       len(all),
		OSBreakdown: make(map[string]int),
	}

	for _, comp := range all {
		if comp.IsDC {
			stats.DCs++
		} else if comp.IsServer {
			stats.Servers++
		} else {
			stats.Workstations++
		}

		// Track OS versions
		if comp.OperatingSystem != "" {
			stats.OSBreakdown[comp.OperatingSystem]++
		}
	}

	return stats, nil
}
