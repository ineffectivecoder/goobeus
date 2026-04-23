package pac

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// BufferSummary describes a single PAC buffer for inventory display.
type BufferSummary struct {
	Type   uint32
	Size   uint32
	Offset uint64
	Name   string
}

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

	// S4U2Self detection fields
	UserFlags          uint32 // LOGON_EXTRA_SIDS=32, LOGON_RESOURCE_GROUPS=512
	ResourceGroupCount int
	ResourceGroupIDs   []uint32
	ResourceDomainSID  string

	// PAC_ATTRIBUTES_INFO flags (MS-PAC 2.14)
	//   0x1 = PAC_WAS_REQUESTED (normal AS-REQ with pA-PAC-REQUEST)
	//   0x2 = PAC_WAS_GIVEN_IMPLICITLY (S4U2Self)
	HasPACAttributes  bool
	PACAttributeFlags uint32

	// Raw buffer inventory (type, size, offset) in PAC-header order.
	BufferInventory []BufferSummary

	// Well-known group analysis
	IsDomainAdmin     bool
	IsEnterpriseAdmin bool
	IsSchemaAdmin     bool
	IsBuiltinAdmin    bool

	// S4U2Self indicators
	HasServiceAssertedIdentity bool // S-1-18-2 present
	HasAuthAssertedIdentity    bool // S-1-18-1 present

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

	// Populate buffer inventory (in PAC-header order) for display
	for i := range pac.Buffers {
		b := &pac.Buffers[i]
		result.BufferInventory = append(result.BufferInventory, BufferSummary{
			Type:   b.Type,
			Size:   b.Size,
			Offset: b.Offset,
			Name:   GetBufferTypeName(b.Type),
		})
	}

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

	// Parse UserFlags from KERB_VALIDATION_INFO
	// UserFlags is at offset 24 in the NDR body (after referent header)
	// Look for characteristic values: 32 (LOGON_EXTRA_SIDS) or 544 (32+512 = EXTRA_SIDS + RESOURCE_GROUPS)
	for i := 8; i < len(data)-4; i++ {
		flags := binary.LittleEndian.Uint32(data[i:])
		// Common UserFlags values
		if flags == 32 || flags == 544 || flags == 0x20 || flags == 0x220 {
			result.UserFlags = flags
			break
		}
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
		sidStr := sid.String()
		result.ExtraSIDs = append(result.ExtraSIDs, sidStr)

		// Check for S4U2Self indicators
		if sidStr == "S-1-18-1" {
			result.HasAuthAssertedIdentity = true // Normal AS-REQ
		} else if sidStr == "S-1-18-2" {
			result.HasServiceAssertedIdentity = true // S4U2Self!
		}

		// Check for builtin Administrators S-1-5-32-544
		if sid.NumSubAuthorities == 2 && len(sid.SubAuthorities) >= 2 {
			if sid.SubAuthorities[0] == 32 && sid.SubAuthorities[1] == 544 {
				result.IsBuiltinAdmin = true
			}
		}
	}

	// Extract PAC_ATTRIBUTES_INFO flags (buffer type 17) if present.
	// Layout: uint32 FlagsLength (bit count) + uint32 Flags
	if attrBuf := pac.GetBuffer(AttributesType); attrBuf != nil && len(attrBuf.Data) >= 8 {
		result.HasPACAttributes = true
		result.PACAttributeFlags = binary.LittleEndian.Uint32(attrBuf.Data[4:8])
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

	// Search for SID patterns
	// - Authority 5 (NT Authority): S-1-5-x-x-x-x (most SIDs)
	// - Authority 18 (Authentication Authority): S-1-18-1 and S-1-18-2
	for i := 0; i < len(data)-16; i++ {
		// Look for revision=1, numSubAuth=1-10
		if data[i] != 0x01 || data[i+1] < 1 || data[i+1] > 10 {
			continue
		}

		// Check for valid authority (5 or 18 in big-endian 6-byte format)
		// Authority 5: 00 00 00 00 00 05
		// Authority 18: 00 00 00 00 00 12
		isAuth5 := data[i+2] == 0 && data[i+3] == 0 && data[i+4] == 0 && data[i+5] == 0 && data[i+6] == 0 && data[i+7] == 5
		isAuth18 := data[i+2] == 0 && data[i+3] == 0 && data[i+4] == 0 && data[i+5] == 0 && data[i+6] == 0 && data[i+7] == 18

		if !isAuth5 && !isAuth18 {
			continue
		}

		numSub := int(data[i+1])
		sidLen := 8 + numSub*4
		if i+sidLen > len(data) {
			continue
		}

		// For authority 5: skip domain SIDs (4 sub-authorities starting with 21)
		if isAuth5 {
			sub0 := binary.LittleEndian.Uint32(data[i+8:])
			if numSub == 4 && sub0 == 21 {
				continue // Skip domain SID
			}
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

	// UserFlags (KERB_VALIDATION_INFO.UserFlags)
	sb.WriteString("\n")
	sb.WriteString("  ───────────────────────────────────────────────────────────────────────────\n")
	sb.WriteString(fmt.Sprintf("  USER FLAGS: 0x%X (%d)\n", d.UserFlags, d.UserFlags))
	if d.UserFlags&0x20 != 0 {
		sb.WriteString("    ✓ LOGON_EXTRA_SIDS (0x20) - ExtraSids array populated\n")
	}
	if d.UserFlags&0x200 != 0 {
		sb.WriteString("    ⚠ LOGON_RESOURCE_GROUPS (0x200) - S4U2Self watermark!\n")
	}
	if d.UserFlags == 0 {
		sb.WriteString("    (none set)\n")
	}

	// PAC_ATTRIBUTES_INFO
	//
	// Flags interpretation is AMBIGUOUS:
	//   0x1 (PAC_WAS_REQUESTED): client sent pA-PAC-REQUEST on AS-REQ. Normal
	//       for Windows domain-joined clients on fresh logon.
	//   0x2 (PAC_WAS_GIVEN_IMPLICITLY): KDC emitted the PAC without an explicit
	//       client request. Normal for:
	//         - MIT kinit / non-Windows clients (they don't send pA-PAC-REQUEST)
	//         - S4U2Self service tickets (issued on behalf of impersonator)
	//   So 0x2 alone does NOT definitively indicate S4U2Self — it's a signal
	//   that must be interpreted in context. Empirically confirmed that MIT
	//   kinit AS-REQ TGTs on a patched Windows Server KDC carry Flags=0x2.
	if d.HasPACAttributes {
		sb.WriteString("\n")
		sb.WriteString("  ───────────────────────────────────────────────────────────────────────────\n")
		sb.WriteString(fmt.Sprintf("  PAC_ATTRIBUTES_INFO Flags: 0x%X\n", d.PACAttributeFlags))
		if d.PACAttributeFlags&0x1 != 0 {
			sb.WriteString("    ✓ PAC_WAS_REQUESTED (0x1) - client sent pA-PAC-REQUEST (Windows-style AS-REQ)\n")
		}
		if d.PACAttributeFlags&0x2 != 0 {
			sb.WriteString("    • PAC_WAS_GIVEN_IMPLICITLY (0x2) - KDC issued PAC without explicit request\n")
			sb.WriteString("      Ambiguous: normal for MIT kinit AND for S4U2Self service tickets\n")
		}
	}

	// Buffer inventory (shows buffer count + types + sizes + offsets).
	// Useful for comparing against KDC-native PAC layouts (e.g. detecting
	// presence/absence of PAC_FULL_CHECKSUM across DC patch levels).
	if len(d.BufferInventory) > 0 {
		sb.WriteString("\n")
		sb.WriteString("  ───────────────────────────────────────────────────────────────────────────\n")
		sb.WriteString(fmt.Sprintf("  PAC BUFFER INVENTORY (%d buffers):\n", len(d.BufferInventory)))
		sb.WriteString("    Idx  Type  Name              Size  Offset\n")
		for i, b := range d.BufferInventory {
			sb.WriteString(fmt.Sprintf("    [%d]  %3d   %-17s %4d  %d\n",
				i, b.Type, b.Name, b.Size, b.Offset))
		}
	}

	// Sapphire / S4U2Self watermark verdict.
	//
	// Only indicators that are *unambiguous* markers of S4U2Self origin are
	// treated as watermarks here. PAC_ATTRIBUTES_INFO Flags=0x2 is NOT one of
	// them: it's also the normal value for MIT kinit AS-REQ TGTs, so flagging
	// it as an S4U2Self watermark produces false positives against legit
	// non-Windows clients.
	sb.WriteString("\n")
	sb.WriteString("  ───────────────────────────────────────────────────────────────────────────\n")
	sb.WriteString("  S4U2Self WATERMARK STATUS:\n")
	watermarks := 0
	if d.HasServiceAssertedIdentity {
		sb.WriteString("    ⚠ S-1-18-2 in ExtraSids (SERVICE_ASSERTED_IDENTITY) — only appears in S4U2Self tickets\n")
		watermarks++
	}
	if d.UserFlags&0x200 != 0 {
		sb.WriteString("    ⚠ LOGON_RESOURCE_GROUPS bit set in UserFlags — only set by KDC on S4U2Self responses\n")
		watermarks++
	}
	if watermarks == 0 {
		sb.WriteString("    ✓ Clean — no unambiguous S4U2Self watermarks present\n")
		if d.HasPACAttributes && d.PACAttributeFlags&0x2 != 0 {
			sb.WriteString("    (note: PAC_ATTRIBUTES_INFO Flags=0x2 present but ambiguous — also normal for kinit-issued AS-REQ TGTs)\n")
		}
	}

	sb.WriteString("╚═══════════════════════════════════════════════════════════════════════════╝\n")

	return sb.String()
}
