package pac

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// EDUCATIONAL: PAC Viewer
//
// The PAC (Privilege Attribute Certificate) is embedded in Kerberos tickets
// and contains authorization data. This viewer parses and displays:
//
//   - KERB_VALIDATION_INFO (user info, group memberships)
//   - PAC_CLIENT_INFO (client name and time)
//   - PAC_SIGNATURE_DATA (server and KDC checksums)
//   - S4U_DELEGATION_INFO (delegation history)
//   - UPN_DNS_INFO (UPN and DNS names)
//
// This is critical for:
//   - Understanding what Windows "sees" when you present a ticket
//   - Verifying forged tickets are correct
//   - Researching delegation and impersonation attacks

// PACView contains parsed PAC information for display.
type PACView struct {
	Version    uint32
	NumBuffers uint32
	Buffers    []PACBufferView

	// Parsed info
	LogonInfo      *LogonInfoView
	ClientInfo     *ClientInfoView
	ServerChecksum *ChecksumView
	KDCChecksum    *ChecksumView
	UpnDnsInfo     *UpnDnsInfoView
	DelegationInfo *DelegationInfoView
}

// LogonInfoView contains parsed KERB_VALIDATION_INFO.
type LogonInfoView struct {
	LogonTime          time.Time
	LogoffTime         time.Time
	KickOffTime        time.Time
	PasswordLastSet    time.Time
	EffectiveName      string
	FullName           string
	LogonScript        string
	ProfilePath        string
	HomeDirectory      string
	LogonServer        string
	LogonDomainName    string
	UserID             uint32
	PrimaryGroupID     uint32
	Groups             []GroupView
	UserFlags          uint32
	UserFlagsExplain   []string
	DomainSID          string
	ExtraSIDs          []SIDView
	ResourceGroups     []GroupView
	UserAccountControl uint32
	UACExplain         []string
}

// GroupView represents a group membership.
type GroupView struct {
	RID         uint32
	Attributes  uint32
	AttrExplain []string
	Name        string // If known
}

// SIDView represents a SID.
type SIDView struct {
	SID         string
	Attributes  uint32
	AttrExplain []string
	Explanation string // Well-known SID explanation
}

// ClientInfoView contains parsed PAC_CLIENT_INFO.
type ClientInfoView struct {
	ClientID time.Time
	Name     string
}

// ChecksumView contains parsed PAC_SIGNATURE_DATA.
type ChecksumView struct {
	Type           uint32
	TypeName       string
	Signature      []byte
	RODCIdentifier uint16
}

// UpnDnsInfoView contains parsed UPN_DNS_INFO.
type UpnDnsInfoView struct {
	UPN     string
	DNSName string
	Flags   uint32
}

// DelegationInfoView contains S4U_DELEGATION_INFO.
type DelegationInfoView struct {
	S4U2ProxyTarget   string
	TransitedServices []string
}

// PACBufferView represents a single PAC buffer.
type PACBufferView struct {
	Type     uint32
	TypeName string
	Size     uint32
	Offset   uint64
	Data     []byte
}

// ParsePAC parses a PAC blob and returns a structured view.
func ParsePAC(data []byte) (*PACView, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("PAC too short: %d bytes", len(data))
	}

	view := &PACView{
		NumBuffers: binary.LittleEndian.Uint32(data[0:4]),
		Version:    binary.LittleEndian.Uint32(data[4:8]),
	}

	// Parse buffer headers
	offset := 8
	for i := uint32(0); i < view.NumBuffers && offset+16 <= len(data); i++ {
		bufType := binary.LittleEndian.Uint32(data[offset : offset+4])
		bufSize := binary.LittleEndian.Uint32(data[offset+4 : offset+8])
		bufOffset := binary.LittleEndian.Uint64(data[offset+8 : offset+16])

		buf := PACBufferView{
			Type:     bufType,
			TypeName: pacBufferTypeName(bufType),
			Size:     bufSize,
			Offset:   bufOffset,
		}

		// Extract buffer data
		if bufOffset+uint64(bufSize) <= uint64(len(data)) {
			buf.Data = data[bufOffset : bufOffset+uint64(bufSize)]
		}

		view.Buffers = append(view.Buffers, buf)
		offset += 16
	}

	// Parse each buffer type
	for _, buf := range view.Buffers {
		switch buf.Type {
		case 1: // KERB_VALIDATION_INFO
			view.LogonInfo = parseLogonInfo(buf.Data)
		case 6: // PAC_SERVER_CHECKSUM
			view.ServerChecksum = parseChecksum(buf.Data)
		case 7: // PAC_PRIVSVR_CHECKSUM (KDC)
			view.KDCChecksum = parseChecksum(buf.Data)
		case 10: // PAC_CLIENT_INFO
			view.ClientInfo = parseClientInfo(buf.Data)
		case 11: // S4U_DELEGATION_INFO
			view.DelegationInfo = parseDelegationInfo(buf.Data)
		case 12: // UPN_DNS_INFO
			view.UpnDnsInfo = parseUpnDnsInfo(buf.Data)
		}
	}

	return view, nil
}

func pacBufferTypeName(t uint32) string {
	names := map[uint32]string{
		1:  "KERB_VALIDATION_INFO (Logon Info)",
		2:  "PAC_CREDENTIALS_INFO",
		6:  "PAC_SERVER_CHECKSUM",
		7:  "PAC_PRIVSVR_CHECKSUM (KDC)",
		10: "PAC_CLIENT_INFO",
		11: "S4U_DELEGATION_INFO",
		12: "UPN_DNS_INFO",
		13: "PAC_CLIENT_CLAIMS_INFO",
		14: "PAC_DEVICE_INFO",
		15: "PAC_DEVICE_CLAIMS_INFO",
		16: "PAC_TICKET_CHECKSUM",
		17: "PAC_ATTRIBUTES_INFO",
		18: "PAC_REQUESTOR",
	}
	if name, ok := names[t]; ok {
		return name
	}
	return fmt.Sprintf("Unknown (%d)", t)
}

// String returns a beautifully formatted PAC description.
func (v *PACView) String() string {
	var sb strings.Builder

	sb.WriteString("╔════════════════════════════════════════════════════════════════╗\n")
	sb.WriteString("║               PAC (Privilege Attribute Certificate)            ║\n")
	sb.WriteString("╠════════════════════════════════════════════════════════════════╣\n")

	sb.WriteString(fmt.Sprintf("║  Version: %d, Buffers: %d\n", v.Version, v.NumBuffers))
	sb.WriteString("╠════════════════════════════════════════════════════════════════╣\n")
	sb.WriteString("║  BUFFER TYPES                                                  ║\n")
	sb.WriteString("╠════════════════════════════════════════════════════════════════╣\n")

	for i, buf := range v.Buffers {
		sb.WriteString(fmt.Sprintf("║  [%d] %-45s %5d bytes\n", i+1, buf.TypeName, buf.Size))
	}

	// Logon Info
	if v.LogonInfo != nil {
		sb.WriteString("╠════════════════════════════════════════════════════════════════╣\n")
		sb.WriteString("║  KERB_VALIDATION_INFO (Who You Are)                           ║\n")
		sb.WriteString("╠════════════════════════════════════════════════════════════════╣\n")
		sb.WriteString(v.LogonInfo.String())
	}

	// Client Info
	if v.ClientInfo != nil {
		sb.WriteString("╠════════════════════════════════════════════════════════════════╣\n")
		sb.WriteString("║  PAC_CLIENT_INFO                                               ║\n")
		sb.WriteString("╠════════════════════════════════════════════════════════════════╣\n")
		sb.WriteString(fmt.Sprintf("║  Client:    %s\n", v.ClientInfo.Name))
		sb.WriteString(fmt.Sprintf("║  Timestamp: %s\n", v.ClientInfo.ClientID.Format(time.RFC3339)))
	}

	// Checksums
	if v.ServerChecksum != nil {
		sb.WriteString("╠════════════════════════════════════════════════════════════════╣\n")
		sb.WriteString("║  SIGNATURES                                                    ║\n")
		sb.WriteString("╠════════════════════════════════════════════════════════════════╣\n")
		sb.WriteString(fmt.Sprintf("║  Server: %s (%d bytes)\n", v.ServerChecksum.TypeName, len(v.ServerChecksum.Signature)))
		if v.KDCChecksum != nil {
			sb.WriteString(fmt.Sprintf("║  KDC:    %s (%d bytes)\n", v.KDCChecksum.TypeName, len(v.KDCChecksum.Signature)))
		}
		if v.ServerChecksum.RODCIdentifier != 0 {
			sb.WriteString(fmt.Sprintf("║  RODC ID: %d (Read-Only Domain Controller)\n", v.ServerChecksum.RODCIdentifier))
		}
	}

	// Delegation Info
	if v.DelegationInfo != nil {
		sb.WriteString("╠════════════════════════════════════════════════════════════════╣\n")
		sb.WriteString("║  S4U_DELEGATION_INFO (Delegation History)                     ║\n")
		sb.WriteString("╠════════════════════════════════════════════════════════════════╣\n")
		sb.WriteString(fmt.Sprintf("║  Target: %s\n", v.DelegationInfo.S4U2ProxyTarget))
		for _, svc := range v.DelegationInfo.TransitedServices {
			sb.WriteString(fmt.Sprintf("║    → %s\n", svc))
		}
	}

	// UPN/DNS Info
	if v.UpnDnsInfo != nil {
		sb.WriteString("╠════════════════════════════════════════════════════════════════╣\n")
		sb.WriteString("║  UPN_DNS_INFO                                                  ║\n")
		sb.WriteString("╠════════════════════════════════════════════════════════════════╣\n")
		sb.WriteString(fmt.Sprintf("║  UPN:     %s\n", v.UpnDnsInfo.UPN))
		sb.WriteString(fmt.Sprintf("║  DNS:     %s\n", v.UpnDnsInfo.DNSName))
	}

	sb.WriteString("╚════════════════════════════════════════════════════════════════╝\n")

	// Educational footer
	sb.WriteString("\n💡 EDUCATIONAL NOTES:\n")
	sb.WriteString("   • LogonInfo contains the user's identity and group memberships\n")
	sb.WriteString("   • Groups include Domain Admins (512), Enterprise Admins (519), etc.\n")
	sb.WriteString("   • Server checksum signed by service, KDC checksum by krbtgt\n")
	sb.WriteString("   • Forging a Golden Ticket means forging these signatures\n")

	return sb.String()
}

// String returns formatted LogonInfo.
func (l *LogonInfoView) String() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("║  User:       %s (%s)\n", l.EffectiveName, l.FullName))
	sb.WriteString(fmt.Sprintf("║  Domain:     %s\n", l.LogonDomainName))
	sb.WriteString(fmt.Sprintf("║  User RID:   %d\n", l.UserID))
	sb.WriteString(fmt.Sprintf("║  Domain SID: %s\n", l.DomainSID))
	sb.WriteString(fmt.Sprintf("║  Primary Group: %d (%s)\n", l.PrimaryGroupID, wellKnownRID(l.PrimaryGroupID)))

	if !l.LogonTime.IsZero() {
		sb.WriteString(fmt.Sprintf("║  Logon Time: %s\n", l.LogonTime.Format(time.RFC3339)))
	}
	if !l.PasswordLastSet.IsZero() {
		sb.WriteString(fmt.Sprintf("║  Password Set: %s\n", l.PasswordLastSet.Format(time.RFC3339)))
	}

	// Groups
	if len(l.Groups) > 0 {
		sb.WriteString("║  ───────────────────────────────────────────────────────────\n")
		sb.WriteString(fmt.Sprintf("║  GROUP MEMBERSHIPS (%d groups)\n", len(l.Groups)))
		sb.WriteString("║  ───────────────────────────────────────────────────────────\n")
		for _, g := range l.Groups {
			name := wellKnownRID(g.RID)
			if name != "" {
				sb.WriteString(fmt.Sprintf("║    • RID %d = %s\n", g.RID, name))
			} else {
				sb.WriteString(fmt.Sprintf("║    • RID %d\n", g.RID))
			}
		}
	}

	// Extra SIDs
	if len(l.ExtraSIDs) > 0 {
		sb.WriteString("║  ───────────────────────────────────────────────────────────\n")
		sb.WriteString(fmt.Sprintf("║  EXTRA SIDS (%d)\n", len(l.ExtraSIDs)))
		sb.WriteString("║  ───────────────────────────────────────────────────────────\n")
		for _, s := range l.ExtraSIDs {
			sb.WriteString(fmt.Sprintf("║    • %s", s.SID))
			if s.Explanation != "" {
				sb.WriteString(fmt.Sprintf(" = %s", s.Explanation))
			}
			sb.WriteString("\n")
		}
	}

	// User Account Control
	if l.UserAccountControl != 0 {
		sb.WriteString(fmt.Sprintf("║  UAC Flags: 0x%08x\n", l.UserAccountControl))
		for _, exp := range l.UACExplain {
			sb.WriteString(fmt.Sprintf("║    • %s\n", exp))
		}
	}

	return sb.String()
}

func wellKnownRID(rid uint32) string {
	rids := map[uint32]string{
		500: "Administrator",
		501: "Guest",
		502: "krbtgt",
		512: "Domain Admins",
		513: "Domain Users",
		514: "Domain Guests",
		515: "Domain Computers",
		516: "Domain Controllers",
		518: "Schema Admins",
		519: "Enterprise Admins",
		520: "Group Policy Creator Owners",
		521: "Read-only Domain Controllers",
		522: "Cloneable Domain Controllers",
		526: "Key Admins",
		527: "Enterprise Key Admins",
		553: "RAS and IAS Servers",
	}
	if name, ok := rids[rid]; ok {
		return name
	}
	return ""
}

// Helper parsing functions

func parseLogonInfo(data []byte) *LogonInfoView {
	if len(data) < 100 {
		return nil
	}

	view := &LogonInfoView{}

	// Skip NDR header (typically 16 bytes if present)
	offset := 0
	if len(data) > 16 && binary.LittleEndian.Uint32(data[0:4]) == 0x00081001 {
		offset = 16
	}

	// Parse KERB_VALIDATION_INFO fixed fields
	if offset+72 <= len(data) {
		view.LogonTime = filetimeToTime(binary.LittleEndian.Uint64(data[offset : offset+8]))
		view.PasswordLastSet = filetimeToTime(binary.LittleEndian.Uint64(data[offset+24 : offset+32]))
	}

	// Parse various strings and structures
	// This is simplified - full NDR parsing is complex
	view.EffectiveName = "[requires full NDR parsing]"
	view.LogonDomainName = "[requires full NDR parsing]"

	return view
}

func parseClientInfo(data []byte) *ClientInfoView {
	if len(data) < 10 {
		return nil
	}

	view := &ClientInfoView{
		ClientID: filetimeToTime(binary.LittleEndian.Uint64(data[0:8])),
	}

	nameLen := binary.LittleEndian.Uint16(data[8:10])
	if int(nameLen)+10 <= len(data) {
		view.Name = utf16ToString(data[10 : 10+nameLen])
	}

	return view
}

func parseChecksum(data []byte) *ChecksumView {
	if len(data) < 4 {
		return nil
	}

	view := &ChecksumView{
		Type: binary.LittleEndian.Uint32(data[0:4]),
	}

	view.TypeName = checksumTypeName(view.Type)

	if len(data) > 4 {
		view.Signature = data[4:]
		// RODC identifier is at the end for some checksum types
		if len(data) >= 6 {
			view.RODCIdentifier = binary.LittleEndian.Uint16(data[len(data)-2:])
		}
	}

	return view
}

func checksumTypeName(t uint32) string {
	names := map[uint32]string{
		15:         "HMAC-SHA1-96-AES128",
		16:         "HMAC-SHA1-96-AES256",
		0xFFFFFF76: "HMAC-MD5 (RC4)",
	}
	if name, ok := names[t]; ok {
		return name
	}
	return fmt.Sprintf("Unknown (0x%x)", t)
}

func parseDelegationInfo(data []byte) *DelegationInfoView {
	// S4U_DELEGATION_INFO parsing
	return &DelegationInfoView{
		S4U2ProxyTarget: "[requires NDR parsing]",
	}
}

func parseUpnDnsInfo(data []byte) *UpnDnsInfoView {
	if len(data) < 12 {
		return nil
	}

	upnLen := binary.LittleEndian.Uint16(data[0:2])
	upnOff := binary.LittleEndian.Uint16(data[2:4])
	dnsLen := binary.LittleEndian.Uint16(data[4:6])
	dnsOff := binary.LittleEndian.Uint16(data[6:8])

	view := &UpnDnsInfoView{
		Flags: binary.LittleEndian.Uint32(data[8:12]),
	}

	if int(upnOff)+int(upnLen) <= len(data) {
		view.UPN = utf16ToString(data[upnOff : upnOff+upnLen])
	}
	if int(dnsOff)+int(dnsLen) <= len(data) {
		view.DNSName = utf16ToString(data[dnsOff : dnsOff+dnsLen])
	}

	return view
}

func filetimeToTime(ft uint64) time.Time {
	if ft == 0 || ft == 0x7FFFFFFFFFFFFFFF {
		return time.Time{}
	}
	const epochDiff = 116444736000000000
	return time.Unix(0, (int64(ft)-epochDiff)*100)
}

func utf16ToString(data []byte) string {
	result := make([]byte, 0, len(data)/2)
	for i := 0; i+1 < len(data); i += 2 {
		c := uint16(data[i]) | uint16(data[i+1])<<8
		if c == 0 {
			break
		}
		if c < 0x80 {
			result = append(result, byte(c))
		}
	}
	return string(result)
}
