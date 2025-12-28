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

// EDUCATIONAL: AS Exchange - Getting Your TGT
//
// The AS (Authentication Service) exchange is step one of Kerberos.
// You send an AS-REQ to the KDC asking for a TGT (Ticket Granting Ticket).
//
// Flow:
//   1. Build AS-REQ with your principal and options
//   2. Add pre-authentication (encrypted timestamp proves you know password)
//   3. Send to KDC
//   4. Receive AS-REP with:
//      - TGT (encrypted with krbtgt's key - you can't read it)
//      - Session key (encrypted with YOUR key - you CAN read it)
//   5. Decrypt your portion to get the session key
//
// Pass-the-Hash / Overpass-the-Hash:
//   - For RC4 (etype 23): The key IS the NTLM hash
//   - If you have the hash, you don't need the password!
//   - This is why NTLM hashes are so valuable

// TGTRequest configures a TGT request.
type TGTRequest struct {
	Domain   string
	Username string

	// Credentials - one of these
	Password string
	NTHash   []byte // 16 bytes - RC4 key
	AES128   []byte // 16 bytes
	AES256   []byte // 32 bytes

	// Options
	Etype     int32 // Preferred etype (0 = auto)
	NoPAC     bool  // Request ticket without PAC
	Renewable bool  // Request renewable ticket

	// Connection
	KDC string // Explicit KDC (auto-discovered if empty)
}

// TGTResult contains the result of a TGT request.
type TGTResult struct {
	*SessionInfo
	Kirbi  *ticket.Kirbi
	Base64 string // Base64-encoded kirbi for PTT
}

// AskTGT requests a TGT from the KDC.
//
// EDUCATIONAL: TGT Request Process
//
// 1. We build an AS-REQ with:
//   - Our principal: username@DOMAIN
//   - Target service: krbtgt/DOMAIN@DOMAIN (always for TGT)
//   - Supported encryption types
//   - Options (forwardable, renewable, etc.)
//
// 2. We add pre-authentication:
//   - Encrypt current timestamp with our password-derived key
//   - This proves we know the password without sending it
//   - If account has "no preauth required", skip this (AS-REP roasting!)
//
// 3. KDC validates and returns AS-REP:
//   - ticket: The actual TGT (encrypted with krbtgt's key)
//   - enc-part: Session key and metadata (encrypted with OUR key)
//
// 4. We decrypt enc-part to get:
//   - Session key for this TGT
//   - Ticket flags
//   - Validity times
func AskTGT(req *TGTRequest) (*TGTResult, error) {
	return AskTGTWithContext(context.Background(), req)
}

// AskTGTWithContext requests a TGT with context support.
func AskTGTWithContext(ctx context.Context, req *TGTRequest) (*TGTResult, error) {
	if req.Domain == "" {
		return nil, fmt.Errorf("domain is required")
	}
	if req.Username == "" {
		return nil, fmt.Errorf("username is required")
	}

	// Build credentials
	creds := &Credentials{
		Username: req.Username,
		Domain:   req.Domain,
		Password: req.Password,
		NTHash:   req.NTHash,
		AES128:   req.AES128,
		AES256:   req.AES256,
	}

	// Determine encryption type
	etype := req.Etype
	if etype == 0 {
		etype = creds.PreferredEtype()
	}

	// Get the key
	key, err := creds.GetKey(etype)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}

	// Create client
	client := NewClient(req.Domain).WithKDC(req.KDC)

	// Build AS-REQ
	asReq, err := buildASREQ(req, etype)
	if err != nil {
		return nil, fmt.Errorf("failed to build AS-REQ: %w", err)
	}

	// Add pre-authentication (encrypted timestamp)
	paData, err := buildPAEncTimestamp(key, etype)
	if err != nil {
		return nil, fmt.Errorf("failed to build pre-auth: %w", err)
	}
	asReq.PAData = append(asReq.PAData, paData)

	// Optionally request PAC
	if req.NoPAC {
		asReq.PAData = append(asReq.PAData, buildPAPACRequest(false))
	}

	// Marshal and send
	asReqBytes, err := asn1.MarshalWithParams(asReq, "application,tag:10")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal AS-REQ: %w", err)
	}

	respBytes, err := client.send(ctx, asReqBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to send AS-REQ: %w", err)
	}

	// Check for error response
	if err := checkKRBError(respBytes); err != nil {
		return nil, err
	}

	// Parse AS-REP
	var asRep asn1krb5.ASREP
	_, err = asn1.UnmarshalWithParams(respBytes, &asRep, "application,tag:11")
	if err != nil {
		return nil, fmt.Errorf("failed to parse AS-REP: %w", err)
	}

	// Decrypt the enc-part to get session key
	decrypted, err := decryptEncPart(asRep.EncPart, key, etype, crypto.KeyUsageASRepEncPart)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt AS-REP enc-part: %w", err)
	}

	// Parse decrypted content
	var encPart asn1krb5.EncASRepPart
	_, err = asn1.UnmarshalWithParams(decrypted, &encPart, "application,tag:25")
	if err != nil {
		// Try tag 26 (EncTGSRepPart - some KDCs return this)
		_, err = asn1.UnmarshalWithParams(decrypted, &encPart, "application,tag:26")
		if err != nil {
			return nil, fmt.Errorf("failed to parse EncASRepPart: %w", err)
		}
	}

	// Build kirbi
	kirbi, err := buildKirbi(&asRep.Ticket, &encPart)
	if err != nil {
		return nil, fmt.Errorf("failed to build kirbi: %w", err)
	}

	// Get base64
	b64, _ := kirbi.ToBase64()

	return &TGTResult{
		SessionInfo: &SessionInfo{
			SessionKey:  encPart.Key,
			Ticket:      &asRep.Ticket,
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

// buildASREQ constructs an AS-REQ message.
func buildASREQ(req *TGTRequest, etype int32) (*asn1krb5.ASREQ, error) {
	now := time.Now().UTC()

	// Client name
	cname := asn1krb5.PrincipalName{
		NameType:   asn1krb5.NTPrincipal,
		NameString: []string{req.Username},
	}

	// Service name (krbtgt/REALM)
	sname := asn1krb5.PrincipalName{
		NameType:   asn1krb5.NTSrvInst,
		NameString: []string{"krbtgt", req.Domain},
	}

	// KDC options
	options := asn1krb5.FlagForwardable | asn1krb5.FlagRenewable | asn1krb5.FlagProxiable
	if req.Renewable {
		options |= asn1krb5.FlagRenewable
	}

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
		CName: cname,
		Realm: req.Domain,
		SName: sname,
		Till:  now.Add(10 * time.Hour), // Request 10 hour ticket
		Nonce: int32(now.UnixNano() & 0x7FFFFFFF),
		EType: []int32{etype},
	}

	if req.Renewable {
		body.RTime = now.Add(7 * 24 * time.Hour) // 7 day renewal
	}

	return &asn1krb5.ASREQ{
		PVNO:    asn1krb5.PVNO,
		MsgType: asn1krb5.MsgTypeASREQ,
		ReqBody: body,
	}, nil
}

// buildPAEncTimestamp builds encrypted timestamp pre-authentication.
func buildPAEncTimestamp(key []byte, etype int32) (asn1krb5.PAData, error) {
	now := time.Now().UTC()

	// Build PA-ENC-TS-ENC
	paTS := asn1krb5.PAEncTSEnc{
		PATimestamp: now,
		PAUsec:      int32(now.Nanosecond() / 1000),
	}

	paTSBytes, err := asn1.Marshal(paTS)
	if err != nil {
		return asn1krb5.PAData{}, err
	}

	// Encrypt based on etype
	var encrypted []byte
	switch etype {
	case crypto.EtypeRC4:
		encrypted, err = crypto.EncryptRC4(key, paTSBytes, crypto.KeyUsagePAEncTimestamp)
	case crypto.EtypeAES128, crypto.EtypeAES256:
		encrypted, err = crypto.EncryptAES(key, paTSBytes, crypto.KeyUsagePAEncTimestamp, int(etype))
	default:
		return asn1krb5.PAData{}, fmt.Errorf("unsupported etype: %d", etype)
	}
	if err != nil {
		return asn1krb5.PAData{}, err
	}

	// Build EncryptedData
	encData := asn1krb5.EncryptedData{
		EType:  etype,
		Cipher: encrypted,
	}

	encDataBytes, err := asn1.Marshal(encData)
	if err != nil {
		return asn1krb5.PAData{}, err
	}

	return asn1krb5.PAData{
		PADataType:  asn1krb5.PADataEncTimestamp,
		PADataValue: encDataBytes,
	}, nil
}

// buildPAPACRequest builds a PA-PAC-REQUEST pre-auth data.
func buildPAPACRequest(includePAC bool) asn1krb5.PAData {
	value := []byte{0x30, 0x05, 0xA0, 0x03, 0x01, 0x01, 0x00}
	if includePAC {
		value[6] = 0x01 // true
	}
	return asn1krb5.PAData{
		PADataType:  asn1krb5.PADataPACRequest,
		PADataValue: value,
	}
}

// decryptEncPart decrypts an EncryptedData structure.
func decryptEncPart(encData asn1krb5.EncryptedData, key []byte, etype int32, usage int) ([]byte, error) {
	switch etype {
	case crypto.EtypeRC4:
		return crypto.DecryptRC4(key, encData.Cipher, usage)
	case crypto.EtypeAES128, crypto.EtypeAES256:
		return crypto.DecryptAES(key, encData.Cipher, usage, int(etype))
	default:
		return nil, fmt.Errorf("unsupported etype: %d", etype)
	}
}

// buildKirbi creates a Kirbi from ticket and enc-part.
func buildKirbi(tkt *asn1krb5.Ticket, encPart *asn1krb5.EncASRepPart) (*ticket.Kirbi, error) {
	// Build credential info
	credInfo := asn1krb5.EncKRBCredPart{
		TicketInfo: []asn1krb5.KRBCredInfo{
			{
				Key:    encPart.Key,
				PRealm: encPart.SRealm,
				PName: asn1krb5.PrincipalName{
					NameType:   asn1krb5.NTPrincipal,
					NameString: []string{}, // Will be populated
				},
				AuthTime:  encPart.AuthTime,
				StartTime: encPart.StartTime,
				EndTime:   encPart.EndTime,
				RenewTill: encPart.RenewTill,
				SRealm:    encPart.SRealm,
				SName:     encPart.SName,
			},
		},
	}

	// Marshal credential info for enc-part
	credInfoBytes, err := asn1.MarshalWithParams(&credInfo, "application,tag:29")
	if err != nil {
		return nil, err
	}

	// Build KRB-CRED
	krbCred := &asn1krb5.KRBCred{
		PVNO:    asn1krb5.PVNO,
		MsgType: asn1krb5.MsgTypeKRBCred,
		Tickets: []asn1krb5.Ticket{*tkt},
		EncPart: asn1krb5.EncryptedData{
			EType:  0, // NULL encryption
			Cipher: credInfoBytes,
		},
	}

	return &ticket.Kirbi{
		Cred:     krbCred,
		CredInfo: &credInfo,
	}, nil
}

// checkKRBError checks if response is a KRB-ERROR and returns appropriate error.
func checkKRBError(data []byte) error {
	// KRB-ERROR has APPLICATION tag 30
	if len(data) > 0 && (data[0] == 0x7e || (len(data) > 1 && data[1] == 0x1e)) {
		var krbErr asn1krb5.KRBError
		_, err := asn1.UnmarshalWithParams(data, &krbErr, "application,tag:30")
		if err == nil {
			return &KerberosError{
				Code:    krbErr.ErrorCode,
				Message: krbErr.EText,
			}
		}
	}
	return nil
}

// KerberosError represents a Kerberos protocol error.
type KerberosError struct {
	Code    int32
	Message string
}

func (e *KerberosError) Error() string {
	name, desc := errorCodeInfo(e.Code)
	if e.Message != "" {
		return fmt.Sprintf("KRB5 error %d (%s): %s - %s", e.Code, name, desc, e.Message)
	}
	return fmt.Sprintf("KRB5 error %d (%s): %s", e.Code, name, desc)
}

// errorCodeInfo returns name and description for an error code.
func errorCodeInfo(code int32) (string, string) {
	codes := map[int32][2]string{
		0:  {"KDC_ERR_NONE", "No error"},
		6:  {"KDC_ERR_C_PRINCIPAL_UNKNOWN", "Client not found in database"},
		7:  {"KDC_ERR_S_PRINCIPAL_UNKNOWN", "Server not found in database"},
		12: {"KDC_ERR_POLICY", "Policy rejects request"},
		18: {"KDC_ERR_CLIENT_REVOKED", "Client credentials revoked"},
		23: {"KDC_ERR_KEY_EXPIRED", "Password has expired"},
		24: {"KDC_ERR_PREAUTH_FAILED", "Pre-authentication failed (wrong password?)"},
		25: {"KDC_ERR_PREAUTH_REQUIRED", "Pre-authentication required"},
		31: {"KDC_ERR_MUST_USE_USER2USER", "Server requires User-to-User authentication"},
		37: {"KRB_AP_ERR_SKEW", "Clock skew too great"},
		68: {"KDC_ERR_WRONG_REALM", "Wrong realm"},
	}

	if info, ok := codes[code]; ok {
		return info[0], info[1]
	}
	return "UNKNOWN", "Unknown error code"
}
