package pac

import (
	"encoding/binary"
	"fmt"
)

// EDUCATIONAL: PAC (Privilege Attribute Certificate) Structure
//
// The PAC is a binary blob inside Kerberos tickets containing Windows
// authorization data. It's encoded using NDR (Network Data Representation).
//
// Top-level structure:
//   PACTYPE {
//       cBuffers: count of PAC_INFO_BUFFER entries
//       Version: always 0
//       Buffers[]: array of PAC_INFO_BUFFER
//   }
//
// Each buffer contains a type and pointer to its data:
//   PAC_INFO_BUFFER {
//       ulType: buffer type (1=LOGON_INFO, 6=SERVER_CKSUM, etc.)
//       cbBufferSize: size of the buffer data
//       Offset: offset to the data
//   }

// PAC buffer type constants
const (
	LogonInfoType         = 1  // KERB_VALIDATION_INFO
	CredentialsType       = 2  // PAC_CREDENTIAL_INFO
	ServerChecksumType    = 6  // PAC_SERVER_CHECKSUM
	KDCChecksumType       = 7  // PAC_PRIVSVR_CHECKSUM
	ClientInfoType        = 10 // PAC_CLIENT_INFO
	S4UDelegationInfoType = 11 // S4U_DELEGATION_INFO
	UPNDNSInfoType        = 12 // UPN_DNS_INFO
	ClientClaimsType      = 13 // PAC_CLIENT_CLAIMS_INFO
	DeviceInfoType        = 14 // PAC_DEVICE_INFO
	DeviceClaimsType      = 15 // PAC_DEVICE_CLAIMS_INFO
	TicketChecksumType    = 16 // PAC_TICKET_CHECKSUM
	AttributesType        = 17 // PAC_ATTRIBUTES_INFO
	RequestorType         = 18 // PAC_REQUESTOR
)

// PAC represents a complete Privilege Attribute Certificate.
type PAC struct {
	Version uint32
	Buffers []PACBuffer
	RawData []byte // Original raw data
}

// PACBuffer represents a single buffer in the PAC.
type PACBuffer struct {
	Type   uint32
	Size   uint32
	Offset uint64
	Data   []byte
	Parsed interface{} // Parsed structure (LogonInfo, Checksum, etc.)
}

// LogonInfo represents KERB_VALIDATION_INFO.
//
// EDUCATIONAL: The Core of Windows Authorization
//
// This structure contains everything Windows needs to authorize you:
//   - Your user SID
//   - Your primary group SID
//   - All your group SIDs
//   - Extra SIDs (from SID History, etc.)
//   - Logon metadata
//
// In a Golden Ticket, we forge this to claim any group membership!
type LogonInfo struct {
	// User identification
	LogonTime          uint64
	LogoffTime         uint64
	KickOffTime        uint64
	PasswordLastSet    uint64
	PasswordCanChange  uint64
	PasswordMustChange uint64

	// Names (NDR strings)
	EffectiveName      string
	FullName           string
	LogonScript        string
	ProfilePath        string
	HomeDirectory      string
	HomeDirectoryDrive string

	// Counts
	LogonCount       uint16
	BadPasswordCount uint16

	// IDs
	UserID         uint32
	PrimaryGroupID uint32
	GroupCount     uint32
	GroupIDs       []GroupMembership

	// Flags
	UserFlags uint32

	// Session key (usually empty in tickets)
	UserSessionKey [16]byte

	// Domain info
	LogonServer     string
	LogonDomainName string

	// SIDs
	LogonDomainID SID // Domain SID

	// Additional
	UserAccountControl   uint32
	SubAuthStatus        uint32
	LastSuccessfulILogon uint64
	LastFailedILogon     uint64
	FailedILogonCount    uint32
	Reserved3            uint32

	// Extra groups and SIDs
	SIDCount  uint32
	ExtraSIDs []ExtraSID

	// Resource groups (constrained delegation)
	ResourceGroupDomainSID SID
	ResourceGroupCount     uint32
	ResourceGroupIDs       []GroupMembership
}

// GroupMembership represents a relative group ID.
type GroupMembership struct {
	RelativeID uint32
	Attributes uint32 // SE_GROUP_ flags
}

// ExtraSID represents an extra SID in the PAC.
type ExtraSID struct {
	SID        SID
	Attributes uint32
}

// SID represents a Windows Security Identifier.
//
// EDUCATIONAL: Security Identifiers
//
// SIDs identify security principals in Windows. Format:
//
//	S-R-I-S-S-S-S...
//	- R: Revision (always 1)
//	- I: Identifier authority (usually 5 for NT)
//	- S: Sub-authorities (variable number)
//
// Well-known SIDs:
//
//	S-1-5-21-<domain>-500    : Administrator
//	S-1-5-21-<domain>-512    : Domain Admins
//	S-1-5-21-<domain>-519    : Enterprise Admins
//	S-1-18-1                 : Authentication Authority Asserted Identity
//
// In ticket forgery, we construct the domain SID + RID for groups.
type SID struct {
	Revision          uint8
	NumSubAuthorities uint8
	Authority         [6]byte
	SubAuthorities    []uint32
}

// String returns the SID in string format: S-1-5-21-...
func (s *SID) String() string {
	if s == nil || s.Revision == 0 {
		return ""
	}

	// Calculate authority value
	auth := uint64(0)
	for i := 0; i < 6; i++ {
		auth = (auth << 8) | uint64(s.Authority[i])
	}

	result := fmt.Sprintf("S-%d-%d", s.Revision, auth)
	for _, sub := range s.SubAuthorities {
		result += fmt.Sprintf("-%d", sub)
	}
	return result
}

// ParseSID parses a SID string into a SID structure.
func ParseSID(s string) (*SID, error) {
	if len(s) < 4 || s[0] != 'S' || s[1] != '-' {
		return nil, fmt.Errorf("invalid SID format: %s", s)
	}

	var rev, auth uint64
	var subs []uint32

	_, err := fmt.Sscanf(s, "S-%d-%d", &rev, &auth)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SID: %w", err)
	}

	// Parse sub-authorities
	remaining := s
	for i := 0; i < 3; i++ { // Skip S-r-a
		idx := 0
		for idx < len(remaining) && remaining[idx] != '-' {
			idx++
		}
		if idx < len(remaining) {
			remaining = remaining[idx+1:]
		}
	}

	// Now remaining contains sub-authorities
	for len(remaining) > 0 {
		var sub uint32
		consumed := 0
		for consumed < len(remaining) && remaining[consumed] >= '0' && remaining[consumed] <= '9' {
			sub = sub*10 + uint32(remaining[consumed]-'0')
			consumed++
		}
		if consumed > 0 {
			subs = append(subs, sub)
		}
		remaining = remaining[consumed:]
		if len(remaining) > 0 && remaining[0] == '-' {
			remaining = remaining[1:]
		}
	}

	sid := &SID{
		Revision:          uint8(rev),
		NumSubAuthorities: uint8(len(subs)),
		SubAuthorities:    subs,
	}

	// Set authority (big-endian)
	for i := 5; i >= 0; i-- {
		sid.Authority[i] = byte(auth & 0xFF)
		auth >>= 8
	}

	return sid, nil
}

// Bytes returns the binary representation of the SID.
func (s *SID) Bytes() []byte {
	data := make([]byte, 8+4*len(s.SubAuthorities))
	data[0] = s.Revision
	data[1] = s.NumSubAuthorities
	copy(data[2:8], s.Authority[:])
	for i, sub := range s.SubAuthorities {
		binary.LittleEndian.PutUint32(data[8+i*4:], sub)
	}
	return data
}

// ClientInfo represents PAC_CLIENT_INFO.
type ClientInfo struct {
	ClientID   uint64 // FILETIME
	NameLength uint16
	Name       string
}

// Checksum represents PAC signature.
type Checksum struct {
	Type      uint32 // Checksum type
	Signature []byte // The checksum value
	RODCId    uint16 // Optional RODC identifier
}

// UPNDNSInfo represents UPN_DNS_INFO.
type UPNDNSInfo struct {
	UPN       string
	DNSDomain string
	Flags     uint32
	SAMName   string
	SID       *SID
}
