package ticket

import (
	"encoding/asn1"
	"fmt"
	"strings"
	"time"

	"github.com/goobeus/goobeus/pkg/asn1krb5"
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

// String returns a beautifully formatted ticket description.
func (v *TicketView) String() string {
	var sb strings.Builder

	// Header
	sb.WriteString(boxTop("KERBEROS TICKET ANALYSIS", 77))
	sb.WriteString("\n")

	// Identity section
	sb.WriteString(sectionHeader("TICKET IDENTITY", 77))
	sb.WriteString(fmt.Sprintf("  Client    : %s\n", v.Client))
	sb.WriteString(fmt.Sprintf("  Service   : %s\n", v.Service))
	if v.IsTGT {
		sb.WriteString("            └─ This is a TGT (Ticket Granting Ticket)\n")
		sb.WriteString("               Used to request service tickets without re-authenticating\n")
	} else {
		sb.WriteString("            └─ This is a Service Ticket\n")
		sb.WriteString("               Grants access to this specific service\n")
	}
	sb.WriteString(fmt.Sprintf("  Realm     : %s\n", v.Realm))
	sb.WriteString(sectionFooter(77))

	// Flags section
	sb.WriteString(sectionHeader("TICKET FLAGS", 77))
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
	sb.WriteString(sectionFooter(77))

	// Time section
	sb.WriteString(sectionHeader("VALIDITY TIMES", 77))
	sb.WriteString(formatTimeInfo("Auth Time ", v.AuthTime))
	sb.WriteString(formatTimeInfo("Start Time", v.StartTime))
	sb.WriteString(formatTimeInfo("End Time  ", v.EndTime))
	sb.WriteString(formatTimeInfo("Renew Till", v.RenewTill))
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
