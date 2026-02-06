package pac

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// DecodedPAC contains human-readable PAC information.
type DecodedPAC struct {
	// User info
	EffectiveName string
	FullName      string
	UserRID       uint32
	PrimaryGroup  uint32
	DomainSID     string
	UserSID       string

	// Groups (full SIDs)
	Groups    []string
	ExtraSIDs []string

	// Well-known group analysis
	IsDomainAdmin     bool
	IsEnterpriseAdmin bool
	IsSchemaAdmin     bool
	IsBuiltinAdmin    bool

	// Raw data for debugging
	LogonInfoSize int
}

// DecodePAC parses a PAC and returns human-readable information.
// This is primarily used to see what groups are in a ticket.
func DecodePAC(pacData []byte) (*DecodedPAC, error) {
	pac, err := ParsePACForSigning(pacData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PAC: %w", err)
	}

	result := &DecodedPAC{}

	// Find LOGON_INFO buffer
	logonBuf := pac.GetBuffer(LogonInfoType)
	if logonBuf == nil {
		return nil, fmt.Errorf("PAC has no LOGON_INFO buffer")
	}

	result.LogonInfoSize = int(logonBuf.Size)
	data := logonBuf.Data
	if len(data) < 100 {
		return nil, fmt.Errorf("LOGON_INFO too short: %d bytes", len(data))
	}

	// Parse the KERB_VALIDATION_INFO structure (NDR encoded)
	// This is complex because it's NDR (Network Data Representation)
	// We'll do a best-effort parse focusing on the key fields

	// First, find the domain SID (4 sub-authorities)
	var domainSID *SID
	for i := 0; i < len(data)-24; i++ {
		if data[i] == 0x01 && data[i+1] == 0x04 { // 4 sub-authorities
			if data[i+2] == 0 && data[i+3] == 0 && data[i+4] == 0 && data[i+5] == 0 && data[i+6] == 0 && data[i+7] == 5 {
				sub0 := binary.LittleEndian.Uint32(data[i+8:])
				if sub0 == 21 {
					domainSID = &SID{
						Revision:          data[i],
						NumSubAuthorities: data[i+1],
					}
					copy(domainSID.Authority[:], data[i+2:i+8])
					domainSID.SubAuthorities = make([]uint32, 4)
					for j := 0; j < 4; j++ {
						domainSID.SubAuthorities[j] = binary.LittleEndian.Uint32(data[i+8+j*4:])
					}
					break
				}
			}
		}
	}

	if domainSID != nil {
		result.DomainSID = domainSID.String()
	}

	// Search for user RID and primary group
	// These are typically near each other in the structure
	for i := 0; i < len(data)-8; i++ {
		primaryGroup := binary.LittleEndian.Uint32(data[i:])
		if primaryGroup == 513 { // Domain Users
			if i >= 4 {
				userRID := binary.LittleEndian.Uint32(data[i-4:])
				if userRID >= 500 && userRID < 100000 {
					result.UserRID = userRID
					result.PrimaryGroup = primaryGroup
					if domainSID != nil {
						result.UserSID = fmt.Sprintf("%s-%d", domainSID.String(), userRID)
					}
					break
				}
			}
		}
	}

	// Find group count and group RIDs
	// GroupCount is a DWORD followed by pointer, then an array of GROUP_MEMBERSHIP
	// GROUP_MEMBERSHIP is { ULONG RelativeId, ULONG Attributes }
	groups := findGroupRIDs(data)
	for _, gm := range groups {
		if domainSID != nil {
			fullSID := fmt.Sprintf("%s-%d", domainSID.String(), gm.RelativeID)
			result.Groups = append(result.Groups, fullSID)

			// Check for well-known groups
			switch gm.RelativeID {
			case 512:
				result.IsDomainAdmin = true
			case 519:
				result.IsEnterpriseAdmin = true
			case 518:
				result.IsSchemaAdmin = true
			}
		}
	}

	// Find extra SIDs (full SIDs, not RIDs)
	extraSIDs := findExtraSIDs(data)
	for _, sid := range extraSIDs {
		result.ExtraSIDs = append(result.ExtraSIDs, sid.String())
		// Check for builtin Administrators S-1-5-32-544
		if sid.NumSubAuthorities == 2 && len(sid.SubAuthorities) >= 2 {
			if sid.SubAuthorities[0] == 32 && sid.SubAuthorities[1] == 544 {
				result.IsBuiltinAdmin = true
			}
		}
	}

	// Try to extract username from UPN_DNS_INFO if present
	upnBuf := pac.GetBuffer(UPNDNSInfoType)
	if upnBuf != nil && len(upnBuf.Data) > 16 {
		// UPN_DNS_INFO has offsets to UPN and DNS strings
		upnLen := binary.LittleEndian.Uint16(upnBuf.Data[0:2])
		upnOffset := binary.LittleEndian.Uint16(upnBuf.Data[2:4])
		if upnOffset > 0 && int(upnOffset)+int(upnLen) <= len(upnBuf.Data) {
			// UPN is UTF-16LE
			upnBytes := upnBuf.Data[upnOffset : upnOffset+upnLen]
			result.EffectiveName = decodeUTF16LE(upnBytes)
		}
	}

	return result, nil
}

// findGroupRIDs extracts group relative IDs from LOGON_INFO
func findGroupRIDs(data []byte) []GroupMembership {
	var groups []GroupMembership

	// Look for patterns of valid group RIDs followed by attributes
	// Group attributes are typically 0x07 (SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED)
	for i := 0; i < len(data)-8; i++ {
		rid := binary.LittleEndian.Uint32(data[i:])
		attrs := binary.LittleEndian.Uint32(data[i+4:])

		// Valid group RIDs are typically 500-65535 for well-known groups
		// Attributes 0x07 is the most common
		if rid >= 500 && rid <= 65535 && (attrs == 0x07 || attrs == 0x00000007 || attrs == 0x20000007) {
			// Check if this looks like a group entry
			groups = append(groups, GroupMembership{
				RelativeID: rid,
				Attributes: attrs,
			})
		}
	}

	// Deduplicate
	seen := make(map[uint32]bool)
	var unique []GroupMembership
	for _, g := range groups {
		if !seen[g.RelativeID] {
			seen[g.RelativeID] = true
			unique = append(unique, g)
		}
	}

	return unique
}

// findExtraSIDs extracts full SIDs from LOGON_INFO
func findExtraSIDs(data []byte) []*SID {
	var sids []*SID

	// Search for SID patterns that are NOT 4-subauthority domain SIDs
	for i := 0; i < len(data)-16; i++ {
		// Look for revision=1, numSubAuth=2-10, authority=5
		if data[i] == 0x01 && data[i+1] >= 2 && data[i+1] <= 10 {
			if data[i+2] == 0 && data[i+3] == 0 && data[i+4] == 0 && data[i+5] == 0 && data[i+6] == 0 && data[i+7] == 5 {
				numSub := int(data[i+1])
				sidLen := 8 + numSub*4
				if i+sidLen <= len(data) {
					// Skip domain SIDs (4 sub-authorities starting with 21)
					sub0 := binary.LittleEndian.Uint32(data[i+8:])
					if numSub == 4 && sub0 == 21 {
						continue // Skip domain SID
					}

					sid := &SID{
						Revision:          data[i],
						NumSubAuthorities: data[i+1],
					}
					copy(sid.Authority[:], data[i+2:i+8])
					sid.SubAuthorities = make([]uint32, numSub)
					for j := 0; j < numSub; j++ {
						sid.SubAuthorities[j] = binary.LittleEndian.Uint32(data[i+8+j*4:])
					}
					sids = append(sids, sid)
				}
			}
		}
	}

	// Deduplicate
	seen := make(map[string]bool)
	var unique []*SID
	for _, s := range sids {
		str := s.String()
		if !seen[str] && str != "" {
			seen[str] = true
			unique = append(unique, s)
		}
	}

	return unique
}

// decodeUTF16LE decodes UTF-16LE to string
func decodeUTF16LE(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	var chars []rune
	for i := 0; i+1 < len(data); i += 2 {
		c := rune(data[i]) | rune(data[i+1])<<8
		if c == 0 {
			break
		}
		chars = append(chars, c)
	}
	return string(chars)
}

// String returns a human-readable representation of the decoded PAC.
func (d *DecodedPAC) String() string {
	var sb strings.Builder

	sb.WriteString("╔═══════════════════════════════════════════════════════════════════════════╗\n")
	sb.WriteString("║ PAC AUTHORIZATION DATA                                                    ║\n")
	sb.WriteString("╠═══════════════════════════════════════════════════════════════════════════╣\n")

	if d.EffectiveName != "" {
		sb.WriteString(fmt.Sprintf("  User:        %s\n", d.EffectiveName))
	}
	if d.UserSID != "" {
		sb.WriteString(fmt.Sprintf("  User SID:    %s\n", d.UserSID))
	}
	if d.DomainSID != "" {
		sb.WriteString(fmt.Sprintf("  Domain SID:  %s\n", d.DomainSID))
	}
	sb.WriteString("\n")

	// Privilege analysis
	sb.WriteString("  ───────────────────────────────────────────────────────────────────────────\n")
	sb.WriteString("  PRIVILEGE ANALYSIS:\n")
	if d.IsDomainAdmin {
		sb.WriteString("  ✓ Domain Admins (RID 512) - HIGHLY PRIVILEGED\n")
	}
	if d.IsEnterpriseAdmin {
		sb.WriteString("  ✓ Enterprise Admins (RID 519) - HIGHLY PRIVILEGED\n")
	}
	if d.IsSchemaAdmin {
		sb.WriteString("  ✓ Schema Admins (RID 518) - HIGHLY PRIVILEGED\n")
	}
	if d.IsBuiltinAdmin {
		sb.WriteString("  ✓ BUILTIN\\Administrators - LOCAL ADMIN\n")
	}
	if !d.IsDomainAdmin && !d.IsEnterpriseAdmin && !d.IsSchemaAdmin && !d.IsBuiltinAdmin {
		sb.WriteString("  ✗ No privileged groups detected\n")
		sb.WriteString("    (User may not have admin access to domain resources)\n")
	}
	sb.WriteString("\n")

	// Group SIDs
	if len(d.Groups) > 0 {
		sb.WriteString("  ───────────────────────────────────────────────────────────────────────────\n")
		sb.WriteString("  GROUP SIDS:\n")
		for _, g := range d.Groups {
			label := ""
			// Add labels for well-known RIDs
			if strings.HasSuffix(g, "-512") {
				label = " (Domain Admins)"
			} else if strings.HasSuffix(g, "-513") {
				label = " (Domain Users)"
			} else if strings.HasSuffix(g, "-519") {
				label = " (Enterprise Admins)"
			} else if strings.HasSuffix(g, "-518") {
				label = " (Schema Admins)"
			} else if strings.HasSuffix(g, "-520") {
				label = " (Group Policy Creator Owners)"
			}
			sb.WriteString(fmt.Sprintf("    %s%s\n", g, label))
		}
		sb.WriteString("\n")
	}

	// Extra SIDs
	if len(d.ExtraSIDs) > 0 {
		sb.WriteString("  ───────────────────────────────────────────────────────────────────────────\n")
		sb.WriteString("  EXTRA SIDS:\n")
		for _, s := range d.ExtraSIDs {
			label := ""
			if s == "S-1-5-32-544" {
				label = " (BUILTIN\\Administrators)"
			} else if s == "S-1-18-1" {
				label = " (Authentication Authority Asserted Identity)"
			} else if s == "S-1-18-2" {
				label = " (Service Asserted Identity)"
			}
			sb.WriteString(fmt.Sprintf("    %s%s\n", s, label))
		}
	}

	sb.WriteString("╚═══════════════════════════════════════════════════════════════════════════╝\n")

	return sb.String()
}
