package ticket

import (
	"encoding/asn1"
	"fmt"
	"strings"
	"time"

	"github.com/goobeus/goobeus/pkg/asn1krb5"
	"github.com/goobeus/goobeus/pkg/crypto"
)

// EDUCATIONAL: Ticket Viewer
//
// The ticket viewer provides rich, educational analysis of Kerberos tickets.
// It doesn't just parse - it TEACHES by explaining:
//   - What each field means
//   - Security implications
//   - Attack relevance
//   - Time-sensitive information (expiry, remaining time)

// ViewOptions configures ticket viewing.
type ViewOptions struct {
	ShowPAC    bool   // Decode and display PAC (if key provided)
	ShowRaw    bool   // Show raw hex values
	Verbose    bool   // Include all optional fields
	NoColor    bool   // Disable ANSI colors
	DecryptKey []byte // Key to decrypt ticket contents
}

// TicketView contains parsed and explained ticket information.
type TicketView struct {
	// Identity
	Client  string
	Service string
	Realm   string

	// Type detection
	IsTGT           bool
	IsServiceTicket bool

	// Flags
	Flags []FlagInfo

	// Times
	AuthTime  TimeInfo
	StartTime TimeInfo
	EndTime   TimeInfo
	RenewTill TimeInfo

	// Encryption
	EType ETypeInfo
	Kvno  int32

	// Raw ticket for reference
	Ticket *asn1krb5.Ticket
}

// FlagInfo describes a ticket flag with educational context.
type FlagInfo struct {
	Name        string
	Set         bool
	Description string
	Warning     string // Security implications
}

// TimeInfo describes a time value with context.
type TimeInfo struct {
	Time      time.Time
	Remaining time.Duration // Time until this point (negative if past)
	Label     string
}

// ETypeInfo describes encryption type with educational context.
type ETypeInfo struct {
	EType       int32
	Name        string
	Description string
	Security    string // Security assessment
}

// ViewTicket creates a detailed, educational view of a ticket.
func ViewTicket(kirbi *Kirbi, opts ViewOptions) *TicketView {
	// Handle RawBytes-based kirbi (from tgtdeleg)
	if kirbi != nil && len(kirbi.RawBytes) > 0 && kirbi.Cred == nil {
		return viewRawTicket(kirbi, opts)
	}

	if kirbi == nil || kirbi.Ticket() == nil {
		return nil
	}

	ticket := kirbi.Ticket()
	view := &TicketView{
		Ticket: ticket,
		Realm:  ticket.Realm,
		Kvno:   ticket.EncPart.Kvno,
	}

	// Parse service name
	view.Service = principalToString(ticket.SName) + "@" + ticket.Realm
	view.IsTGT = isTGT(ticket.SName)
	view.IsServiceTicket = !view.IsTGT

	// Get client info from credential info
	if kirbi.CredInfo != nil && len(kirbi.CredInfo.TicketInfo) > 0 {
		info := &kirbi.CredInfo.TicketInfo[0]
		view.Client = principalToString(info.PName) + "@" + info.PRealm

		// Parse times
		now := time.Now()
		view.AuthTime = TimeInfo{
			Time:      info.AuthTime,
			Remaining: info.AuthTime.Sub(now),
			Label:     "Authentication Time",
		}
		view.StartTime = TimeInfo{
			Time:      info.StartTime,
			Remaining: info.StartTime.Sub(now),
			Label:     "Valid From",
		}
		view.EndTime = TimeInfo{
			Time:      info.EndTime,
			Remaining: info.EndTime.Sub(now),
			Label:     "Expires",
		}
		view.RenewTill = TimeInfo{
			Time:      info.RenewTill,
			Remaining: info.RenewTill.Sub(now),
			Label:     "Renewable Until",
		}

		// Parse flags
		view.Flags = parseFlags(info.Flags)
	}

	// Parse encryption type
	view.EType = describeEType(ticket.EncPart.EType)

	return view
}

// viewRawTicket creates a view from raw KRB-CRED bytes
// This handles kirbi files that couldn't be fully parsed but contain valid data
func viewRawTicket(kirbi *Kirbi, opts ViewOptions) *TicketView {
	rawBytes := kirbi.RawBytes
	view := &TicketView{}

	// If we have a decryption key, try to decrypt the ticket's enc-part
	if len(kirbi.DecryptKey) > 0 || len(opts.DecryptKey) > 0 {
		decryptKey := kirbi.DecryptKey
		if len(opts.DecryptKey) > 0 {
			decryptKey = opts.DecryptKey
		}

		// Try to find and decrypt the ticket enc-part
		decryptedView := tryDecryptTicket(rawBytes, decryptKey, kirbi.DecryptKeyType)
		if decryptedView != nil {
			return decryptedView
		}
	}

	// Try to extract info from raw bytes using pattern matching
	rawStr := string(rawBytes)

	// Check for TGT (krbtgt service)
	if strings.Contains(rawStr, "krbtgt") {
		view.IsTGT = true
	}

	// Extract strings from the raw bytes (look for GeneralString tag 0x1b)
	var extractedStrings []string
	for i := 0; i < len(rawBytes)-4; i++ {
		if rawBytes[i] == 0x1b && i+2 < len(rawBytes) {
			strLen := int(rawBytes[i+1])
			if strLen > 0 && strLen < 100 && i+2+strLen <= len(rawBytes) {
				s := string(rawBytes[i+2 : i+2+strLen])
				// Only keep printable strings
				printable := true
				for _, c := range s {
					if c < 32 || c > 126 {
						printable = false
						break
					}
				}
				if printable && len(s) > 0 {
					extractedStrings = append(extractedStrings, s)
				}
			}
		}
	}

	// Parse extracted strings
	for _, s := range extractedStrings {
		// Check for realm (all uppercase with possible dots)
		if len(s) > 3 && s[0] >= 'A' && s[0] <= 'Z' {
			isRealm := true
			for _, c := range s {
				if !((c >= 'A' && c <= 'Z') || c == '.' || (c >= '0' && c <= '9')) {
					isRealm = false
					break
				}
			}
			if isRealm && view.Realm == "" {
				view.Realm = s
			}
		}

		// Check for username (lowercase, may contain numbers)
		if len(s) > 1 && len(s) < 30 && s[0] >= 'a' && s[0] <= 'z' {
			isUsername := true
			for _, c := range s {
				if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-') {
					isUsername = false
					break
				}
			}
			if isUsername && view.Client == "" && s != "krbtgt" {
				view.Client = s
			}
		}
	}

	// Build service name
	if view.IsTGT && view.Realm != "" {
		view.Service = "krbtgt/" + view.Realm + "@" + view.Realm
	}

	// Add client realm
	if view.Client != "" && view.Realm != "" {
		view.Client = view.Client + "@" + view.Realm
	}

	// Try to find encryption type from the ticket's enc-part
	// Look for etype in context tag [0] after APPLICATION 1 (Ticket)
	for i := 0; i < len(rawBytes)-10; i++ {
		// Look for etype pattern: A0 03 02 01 XX (context[0] INT XX)
		if rawBytes[i] == 0xa0 && rawBytes[i+1] == 0x03 && rawBytes[i+2] == 0x02 && rawBytes[i+3] == 0x01 {
			etype := int32(rawBytes[i+4])
			if etype == 17 || etype == 18 || etype == 23 {
				view.EType = describeEType(etype)
				break
			}
		}
	}

	// Default if not found
	if view.EType.EType == 0 {
		view.EType = describeEType(18) // AES-256 default for modern environments
	}

	// Try to extract times from GeneralizedTime (tag 0x18)
	// GeneralizedTime format: YYYYMMDDHHMMSSZ
	now := time.Now()
	var times []time.Time
	for i := 0; i < len(rawBytes)-17; i++ {
		if rawBytes[i] == 0x18 && rawBytes[i+1] == 0x0f { // GeneralizedTime, 15 bytes
			timeStr := string(rawBytes[i+2 : i+17])
			if len(timeStr) == 15 && timeStr[14] == 'Z' {
				t, err := time.Parse("20060102150405Z", timeStr)
				if err == nil && t.Year() > 2000 && t.Year() < 2100 {
					times = append(times, t)
				}
			}
		}
	}

	// Assign times in order (typically: authtime, starttime, endtime, renew_till)
	if len(times) >= 1 {
		view.AuthTime = TimeInfo{Time: times[0], Remaining: times[0].Sub(now), Label: "Auth Time"}
	}
	if len(times) >= 2 {
		view.StartTime = TimeInfo{Time: times[1], Remaining: times[1].Sub(now), Label: "Start Time"}
	}
	if len(times) >= 3 {
		view.EndTime = TimeInfo{Time: times[2], Remaining: times[2].Sub(now), Label: "End Time"}
	}
	if len(times) >= 4 {
		view.RenewTill = TimeInfo{Time: times[3], Remaining: times[3].Sub(now), Label: "Renew Till"}
	}

	// Try to extract flags from BitString (tag 0x03)
	for i := 0; i < len(rawBytes)-6; i++ {
		// Flags pattern: 03 05 00 XX XX XX XX (BitString, 5 bytes, 0 unused bits, 4 flag bytes)
		if rawBytes[i] == 0x03 && rawBytes[i+1] == 0x05 && rawBytes[i+2] == 0x00 {
			flagBytes := rawBytes[i+3 : i+7]
			view.Flags = parseFlagsFromBytes(flagBytes)
			break
		}
	}

	return view
}

// parseFlagsFromBytes parses ticket flags from raw bytes
func parseFlagsFromBytes(flagBytes []byte) []FlagInfo {
	if len(flagBytes) < 4 {
		return nil
	}

	flagDefs := []struct {
		bit         int
		name        string
		description string
		warning     string
	}{
		{1, "FORWARDABLE", "Can be delegated to another service", "Enables delegation attacks"},
		{2, "FORWARDED", "Has been forwarded/delegated", "This ticket was delegated"},
		{3, "PROXIABLE", "Can be used to obtain proxy tickets", ""},
		{4, "PROXY", "Is a proxy ticket", ""},
		{5, "ALLOW-POSTDATE", "Can be postdated", ""},
		{6, "POSTDATED", "Has been postdated", ""},
		{7, "INVALID", "Ticket is invalid until validated", "Not yet valid"},
		{8, "RENEWABLE", "Can extend lifetime via renewal", ""},
		{9, "INITIAL", "Obtained via AS exchange (fresh)", ""},
		{10, "PRE-AUTHENT", "Client proved password knowledge", ""},
		{11, "HW-AUTHENT", "Hardware authentication was used", ""},
		{12, "TRANSITED-CHECKED", "Transit path was checked", ""},
		{13, "OK-AS-DELEGATE", "KDC trusts this service for delegation", "Delegation trusted"},
	}

	var result []FlagInfo
	for _, def := range flagDefs {
		byteIdx := def.bit / 8
		bitIdx := 7 - (def.bit % 8)
		set := byteIdx < len(flagBytes) && (flagBytes[byteIdx]&(1<<bitIdx)) != 0

		result = append(result, FlagInfo{
			Name:        def.name,
			Set:         set,
			Description: def.description,
			Warning:     def.warning,
		})
	}
	return result
}

// tryDecryptTicket attempts to decrypt the ticket's enc-part using the provided key
// Key usage 2 is used for AS-REP/TGS-REP ticket encryption
func tryDecryptTicket(rawBytes []byte, key []byte, keyType int) *TicketView {
	// Determine encryption type from key length if not specified
	etype := keyType
	if etype == 0 {
		switch len(key) {
		case 32:
			etype = 18 // AES256
		case 16:
			etype = 17 // AES128
		default:
			etype = 23 // RC4
		}
	}

	// Find the ticket's enc-part in the raw bytes
	// Look for EncryptedData structure after the ticket
	// Pattern: A3 (context tag 3 for enc-part in Ticket) followed by SEQUENCE
	for i := 0; i < len(rawBytes)-50; i++ {
		// Look for EncryptedData: SEQUENCE { [0] etype, [1] kvno, [2] cipher }
		if rawBytes[i] == 0x30 && i+10 < len(rawBytes) {
			// Check for etype context tag
			if rawBytes[i+2] == 0xa0 && rawBytes[i+5] == 0x02 {
				foundEtype := int(rawBytes[i+7])
				// Check if this etype matches our key
				if foundEtype == etype || foundEtype == 18 || foundEtype == 17 || foundEtype == 23 {
					// Look for cipher data ([2] tag)
					for j := i + 8; j < len(rawBytes)-5 && j < i+50; j++ {
						if rawBytes[j] == 0xa2 { // [2] cipher
							// Parse length
							if j+2 < len(rawBytes) && rawBytes[j+1] == 0x82 && j+4 < len(rawBytes) {
								cipherLen := int(rawBytes[j+2])<<8 | int(rawBytes[j+3])
								if j+4+cipherLen <= len(rawBytes) {
									cipherData := rawBytes[j+4 : j+4+cipherLen]
									// Skip OCTET STRING tag if present
									if len(cipherData) > 2 && cipherData[0] == 0x04 {
										if cipherData[1] == 0x82 {
											cipherData = cipherData[4:]
										} else {
											cipherData = cipherData[2:]
										}
									}

									// Try to decrypt with the key (key usage 2 for ticket)
									plaintext, err := crypto.DecryptAES(key, cipherData, 2, etype)
									if err == nil && len(plaintext) > 20 {
										// Successfully decrypted! Parse EncTicketPart
										return parseEncTicketPart(plaintext, etype)
									}
								}
							}
						}
					}
				}
			}
		}
	}
	return nil
}

// parseEncTicketPart parses the decrypted EncTicketPart to extract client, flags, times
func parseEncTicketPart(plaintext []byte, etype int) *TicketView {
	view := &TicketView{}
	view.EType = describeEType(int32(etype))

	// EncTicketPart ::= [APPLICATION 3] SEQUENCE {
	//   flags [0] TicketFlags,
	//   key [1] EncryptionKey,
	//   crealm [2] Realm,
	//   cname [3] PrincipalName,
	//   ...
	// }

	// Extract strings (client name, realm) from GeneralString tags
	var strings []string
	for i := 0; i < len(plaintext)-4; i++ {
		if plaintext[i] == 0x1b && i+2 < len(plaintext) {
			strLen := int(plaintext[i+1])
			if strLen > 0 && strLen < 100 && i+2+strLen <= len(plaintext) {
				s := string(plaintext[i+2 : i+2+strLen])
				printable := true
				for _, c := range s {
					if c < 32 || c > 126 {
						printable = false
						break
					}
				}
				if printable && len(s) > 0 {
					strings = append(strings, s)
				}
			}
		}
	}

	// Parse extracted strings
	for _, s := range strings {
		// Check for realm
		if len(s) > 3 && s[0] >= 'A' && s[0] <= 'Z' {
			isRealm := true
			for _, c := range s {
				if !((c >= 'A' && c <= 'Z') || c == '.' || (c >= '0' && c <= '9')) {
					isRealm = false
					break
				}
			}
			if isRealm && view.Realm == "" {
				view.Realm = s
			}
		}

		// Check for username
		if len(s) > 1 && len(s) < 30 && view.Client == "" {
			if s != "krbtgt" && s != view.Realm {
				view.Client = s
			}
		}
	}

	// Add realm to client
	if view.Client != "" && view.Realm != "" {
		view.Client = view.Client + "@" + view.Realm
	}

	// Check for krbtgt
	rawStr := string(plaintext)
	if containsString(rawStr, "krbtgt") {
		view.IsTGT = true
		view.Service = "krbtgt/" + view.Realm + "@" + view.Realm
	}

	// Extract flags from BitString
	for i := 0; i < len(plaintext)-6; i++ {
		if plaintext[i] == 0x03 && plaintext[i+1] == 0x05 && plaintext[i+2] == 0x00 {
			flagBytes := plaintext[i+3 : i+7]
			view.Flags = parseFlagsFromBytes(flagBytes)
			break
		}
	}

	// Extract times from GeneralizedTime
	now := time.Now()
	var times []time.Time
	for i := 0; i < len(plaintext)-17; i++ {
		if plaintext[i] == 0x18 && plaintext[i+1] == 0x0f {
			timeStr := string(plaintext[i+2 : i+17])
			if len(timeStr) == 15 && timeStr[14] == 'Z' {
				t, err := time.Parse("20060102150405Z", timeStr)
				if err == nil && t.Year() > 2000 && t.Year() < 2100 {
					times = append(times, t)
				}
			}
		}
	}

	if len(times) >= 1 {
		view.AuthTime = TimeInfo{Time: times[0], Remaining: times[0].Sub(now), Label: "Auth Time"}
	}
	if len(times) >= 2 {
		view.StartTime = TimeInfo{Time: times[1], Remaining: times[1].Sub(now), Label: "Start Time"}
	}
	if len(times) >= 3 {
		view.EndTime = TimeInfo{Time: times[2], Remaining: times[2].Sub(now), Label: "End Time"}
	}
	if len(times) >= 4 {
		view.RenewTill = TimeInfo{Time: times[3], Remaining: times[3].Sub(now), Label: "Renew Till"}
	}

	return view
}

// containsString is a helper to check if a string contains a substring
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || findSubstr(s, substr)))
}

func findSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// String returns a beautifully formatted ticket description.
func (v *TicketView) String() string {
	var sb strings.Builder

	// Header
	sb.WriteString(boxTop("KERBEROS TICKET ANALYSIS", 77))
	sb.WriteString("\n")

	// Identity section
	sb.WriteString(sectionHeader("TICKET IDENTITY", 77))
	if v.Client != "" {
		sb.WriteString(fmt.Sprintf("  Client    : %s\n", v.Client))
	} else if v.IsTGT {
		sb.WriteString("  Client    : (current user - encrypted in ticket)\n")
	}
	sb.WriteString(fmt.Sprintf("  Service   : %s\n", v.Service))
	if v.IsTGT {
		sb.WriteString("            └─ This is a TGT (Ticket Granting Ticket)\n")
		sb.WriteString("               Used to request service tickets without re-authenticating\n")
	} else if v.Service != "" {
		sb.WriteString("            └─ This is a Service Ticket\n")
		sb.WriteString("               Grants access to this specific service\n")
	}
	sb.WriteString(fmt.Sprintf("  Realm     : %s\n", v.Realm))
	sb.WriteString(sectionFooter(77))

	// Flags section
	sb.WriteString(sectionHeader("TICKET FLAGS", 77))
	if len(v.Flags) == 0 && v.IsTGT {
		// For forwarded TGTs, show typical flags
		sb.WriteString("  ✓ FORWARDABLE    - Can be delegated to another service\n")
		sb.WriteString("  ✓ FORWARDED      - This ticket was delegated (via tgtdeleg trick)\n")
		sb.WriteString("  ✓ RENEWABLE      - Can extend lifetime via renewal\n")
		sb.WriteString("  ✓ PRE-AUTHENT    - Client proved password knowledge\n")
		sb.WriteString("  (⚠️ Flags estimated - encrypted in ticket)\n")
	} else {
		for _, flag := range v.Flags {
			if flag.Set {
				sb.WriteString(fmt.Sprintf("  ✓ %-14s - %s\n", flag.Name, flag.Description))
				if flag.Warning != "" {
					sb.WriteString(fmt.Sprintf("                    ⚠️  %s\n", flag.Warning))
				}
			} else {
				sb.WriteString(fmt.Sprintf("  ✗ %-14s - %s\n", flag.Name, flag.Description))
			}
		}
	}
	sb.WriteString(sectionFooter(77))

	// Time section
	sb.WriteString(sectionHeader("VALIDITY TIMES", 77))
	if v.AuthTime.Time.IsZero() && v.IsTGT {
		sb.WriteString("  (Times encrypted in ticket - decryption requires session key)\n")
		sb.WriteString("  Tip: TGT typically valid for 10 hours, renewable for 7 days\n")
	} else {
		sb.WriteString(formatTimeInfo("Auth Time ", v.AuthTime))
		sb.WriteString(formatTimeInfo("Start Time", v.StartTime))
		sb.WriteString(formatTimeInfo("End Time  ", v.EndTime))
		sb.WriteString(formatTimeInfo("Renew Till", v.RenewTill))
	}
	sb.WriteString(sectionFooter(77))

	// Encryption section
	sb.WriteString(sectionHeader("ENCRYPTION", 77))
	sb.WriteString(fmt.Sprintf("  EType     : %d (%s)\n", v.EType.EType, v.EType.Name))
	sb.WriteString(fmt.Sprintf("            └─ %s\n", v.EType.Description))
	sb.WriteString(fmt.Sprintf("               %s\n", v.EType.Security))
	if v.Kvno > 0 {
		sb.WriteString(fmt.Sprintf("  Key Ver   : %d\n", v.Kvno))
	}
	sb.WriteString(sectionFooter(77))

	return sb.String()
}

// Helper functions

func principalToString(p asn1krb5.PrincipalName) string {
	return strings.Join(p.NameString, "/")
}

func isTGT(sname asn1krb5.PrincipalName) bool {
	if len(sname.NameString) > 0 {
		return strings.ToLower(sname.NameString[0]) == "krbtgt"
	}
	return false
}

func parseFlags(flags asn1.BitString) []FlagInfo {
	flagDefs := []struct {
		bit         int
		name        string
		description string
		warning     string
	}{
		{0, "RESERVED", "Reserved for future use", ""},
		{1, "FORWARDABLE", "Can be delegated to another service", "Enables delegation attacks if combined with unconstrained delegation host"},
		{2, "FORWARDED", "Has been forwarded/delegated", "This ticket was delegated from another context"},
		{3, "PROXIABLE", "Can be used to obtain proxy tickets", ""},
		{4, "PROXY", "Is a proxy ticket", ""},
		{5, "ALLOW-POSTDATE", "Can be postdated", ""},
		{6, "POSTDATED", "Has been postdated", ""},
		{7, "INVALID", "Ticket is invalid until validated", "This ticket is not yet valid"},
		{8, "RENEWABLE", "Can extend lifetime via renewal request", ""},
		{9, "INITIAL", "Obtained via AS exchange (fresh from password)", ""},
		{10, "PRE-AUTHENT", "Client proved password knowledge before ticket", ""},
		{11, "HW-AUTHENT", "Hardware authentication was used", ""},
		{12, "TRANSITED-CHECKED", "Transit path was checked by KDC", ""},
		{13, "OK-AS-DELEGATE", "KDC trusts this service for delegation", "Target service is trusted for delegation"},
	}

	result := make([]FlagInfo, 0)
	for _, def := range flagDefs {
		if def.bit < len(flags.Bytes)*8 {
			byteIdx := def.bit / 8
			bitIdx := 7 - (def.bit % 8)
			set := byteIdx < len(flags.Bytes) && (flags.Bytes[byteIdx]&(1<<bitIdx)) != 0

			// Only include commonly relevant flags
			if def.bit >= 1 && def.bit <= 13 {
				result = append(result, FlagInfo{
					Name:        def.name,
					Set:         set,
					Description: def.description,
					Warning:     def.warning,
				})
			}
		}
	}
	return result
}

func describeEType(etype int32) ETypeInfo {
	etypes := map[int32]ETypeInfo{
		0:  {0, "NULL", "No encryption (plaintext)", "⚠️ Data is not encrypted!"},
		1:  {1, "DES-CBC-CRC", "DES with CRC", "⚠️ Weak - DES is broken"},
		3:  {3, "DES-CBC-MD5", "DES with MD5", "⚠️ Weak - DES is broken"},
		17: {17, "AES128-CTS-HMAC-SHA1-96", "AES-128", "Strong encryption, slower to crack"},
		18: {18, "AES256-CTS-HMAC-SHA1-96", "AES-256", "Strongest Kerberos encryption. Very slow to crack."},
		23: {23, "RC4-HMAC", "RC4/NTLM", "⚠️ Key IS the NTLM hash - 1000x faster to crack than AES!"},
		24: {24, "RC4-HMAC-EXP", "RC4 Export", "⚠️ Weak export cipher"},
	}

	if info, ok := etypes[etype]; ok {
		return info
	}
	return ETypeInfo{etype, "UNKNOWN", "Unknown encryption type", ""}
}

func formatTimeInfo(label string, ti TimeInfo) string {
	var remaining string
	if ti.Remaining > 0 {
		if ti.Remaining > 24*time.Hour {
			days := ti.Remaining / (24 * time.Hour)
			remaining = fmt.Sprintf("(%d days)", days)
		} else if ti.Remaining > time.Hour {
			remaining = fmt.Sprintf("(%.1fh remaining)", ti.Remaining.Hours())
		} else {
			remaining = fmt.Sprintf("(%dm remaining)", int(ti.Remaining.Minutes()))
		}
	} else if ti.Remaining < 0 && ti.Remaining > -time.Hour*24*365 {
		remaining = "(EXPIRED)"
	}

	timeStr := ti.Time.Format("2006-01-02 15:04:05 MST")
	if ti.Time.IsZero() {
		timeStr = "(not set)"
	}

	return fmt.Sprintf("  %-11s: %s  %s\n", label, timeStr, remaining)
}

// Box drawing helpers
func boxTop(title string, width int) string {
	padding := (width - len(title) - 2) / 2
	if padding < 0 {
		padding = 0
	}
	return fmt.Sprintf("┌%s┐\n│%s%s%s│\n└%s┘",
		strings.Repeat("─", width),
		strings.Repeat(" ", padding),
		title,
		strings.Repeat(" ", width-padding-len(title)),
		strings.Repeat("─", width))
}

func sectionHeader(title string, width int) string {
	return fmt.Sprintf("\n╔%s╗\n║ %-*s║\n╠%s╣\n",
		strings.Repeat("═", width),
		width-2, title,
		strings.Repeat("═", width))
}

func sectionFooter(width int) string {
	return fmt.Sprintf("╚%s╝\n", strings.Repeat("═", width))
}
