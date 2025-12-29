package client

import (
	"context"
	"encoding/asn1"
	"fmt"
	"strings"
	"time"

	"github.com/goobeus/goobeus/internal/network"
	"github.com/goobeus/goobeus/pkg/asn1krb5"
	"github.com/goobeus/goobeus/pkg/crypto"
	"github.com/goobeus/goobeus/pkg/ticket"

	gokrb5client "github.com/jcmturner/gokrb5/v8/client"
	gokrb5config "github.com/jcmturner/gokrb5/v8/config"
	gokrb5messages "github.com/jcmturner/gokrb5/v8/messages"
	gokrb5types "github.com/jcmturner/gokrb5/v8/types"
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
	UseNative bool  // Use native AS exchange instead of gokrb5

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
// Uses gokrb5 library for reliable AS-REQ encoding.
func AskTGTWithContext(ctx context.Context, req *TGTRequest) (*TGTResult, error) {
	fmt.Println("[*] AskTGT starting...")

	if req.Domain == "" {
		return nil, fmt.Errorf("domain is required")
	}
	if req.Username == "" {
		return nil, fmt.Errorf("username is required")
	}

	// Build krb5.conf content for gokrb5
	// This tells it how to find the KDC
	kdc := req.KDC
	if kdc == "" {
		// Auto-discover
		addr, err := network.ResolveKDC(req.Domain, "")
		if err != nil {
			return nil, fmt.Errorf("failed to resolve KDC: %w", err)
		}
		kdc = addr
	} else if !strings.Contains(kdc, ":") {
		kdc = kdc + ":88"
	}

	// Extract hostname from kdc address
	kdcHost := kdc
	if idx := strings.Index(kdc, ":"); idx > 0 {
		kdcHost = kdc[:idx]
	}

	fmt.Printf("[*] Using KDC: %s\n", kdc)

	krb5ConfTemplate := `[libdefaults]
  default_realm = %s
  dns_lookup_kdc = false
  dns_lookup_realm = false

[realms]
  %s = {
    kdc = %s
    admin_server = %s
  }
`
	krb5Conf := fmt.Sprintf(krb5ConfTemplate,
		strings.ToUpper(req.Domain),
		strings.ToUpper(req.Domain),
		kdcHost,
		kdcHost)

	// Parse the config
	cfg, err := gokrb5config.NewFromString(krb5Conf)
	if err != nil {
		return nil, fmt.Errorf("failed to create krb5 config: %w", err)
	}

	// Create gokrb5 client
	var cl *gokrb5client.Client

	if req.Password != "" {
		cl = gokrb5client.NewWithPassword(req.Username, strings.ToUpper(req.Domain), req.Password, cfg,
			gokrb5client.DisablePAFXFAST(true)) // Disable FAST - many DCs don't support it
	} else if len(req.NTHash) > 0 {
		// gokrb5 doesn't have direct NT hash support, would need custom keytab
		return nil, fmt.Errorf("NT hash not yet supported with gokrb5, use password")
	} else if len(req.AES256) > 0 {
		return nil, fmt.Errorf("AES key not yet supported with gokrb5, use password")
	} else {
		return nil, fmt.Errorf("password required")
	}

	// Perform AS exchange to get TGT directly (not via GetServiceTicket which does TGS exchange!)
	// For S4U2Self+U2U, we need the actual AS-REP TGT, not a service ticket
	fmt.Println("[*] Requesting TGT via gokrb5 ASExchange...")
	realm := strings.ToUpper(req.Domain)

	// Create AS-REQ - but override the sname to use NT_PRINCIPAL like Impacket does
	// gokrb5's NewASReqForTGT uses NT_SRV_INST (2), but Impacket uses NT_PRINCIPAL (1)
	// This affects the TGT's sname type, which matters for S4U2Self+U2U!
	asReq, err := gokrb5messages.NewASReqForTGT(realm, cfg, cl.Credentials.CName())
	if err != nil {
		return nil, fmt.Errorf("failed to create AS-REQ: %w", err)
	}

	// TEMPORARILY DISABLED: Override sname to use NT_PRINCIPAL (1) instead of NT_SRV_INST (2) to match Impacket
	// asReq.ReqBody.SName.NameType = 1 // NT_PRINCIPAL
	fmt.Printf("[DEBUG] AS-REQ sname: type=%d, name=%v\n", asReq.ReqBody.SName.NameType, asReq.ReqBody.SName.NameString)

	// Perform AS exchange - this returns the AS-REP with the actual TGT
	asRep, err := cl.ASExchange(realm, asReq, 0)
	if err != nil {
		return nil, fmt.Errorf("AS exchange failed: %w", err)
	}

	fmt.Println("[+] TGT obtained successfully!")

	// The TGT is in asRep.Ticket (this is the AS-REP ticket, NOT a TGS-REP ticket!)
	tgt := asRep.Ticket
	tgtKey := asRep.DecryptedEncPart.Key

	fmt.Printf("[*] Got TGT for: krbtgt/%s\n", realm)
	fmt.Printf("[DEBUG] Session Key: etype=%d, len=%d, first8=%x\n",
		tgtKey.KeyType, len(tgtKey.KeyValue), tgtKey.KeyValue[:min(8, len(tgtKey.KeyValue))])

	// Get raw ticket bytes using gokrb5's Marshal - verified structurally identical to Impacket
	rawTktBytes, err := tgt.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ticket: %w", err)
	}
	fmt.Printf("[DEBUG] TGT ticket bytes: %d bytes\n", len(rawTktBytes))

	// Build kirbi from the gokrb5 ticket, with raw bytes
	kirbi, err := buildKirbiFromGokrb5WithRaw(&tgt, &tgtKey, req.Username, rawTktBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to build kirbi: %w", err)
	}

	b64, _ := kirbi.ToBase64()

	return &TGTResult{
		SessionInfo: &SessionInfo{
			SessionKey: asn1krb5.EncryptionKey{
				KeyType:  int32(tgtKey.KeyType),
				KeyValue: tgtKey.KeyValue,
			},
			Kirbi:       kirbi,
			ServerRealm: tgt.Realm,
		},
		Kirbi:  kirbi,
		Base64: b64,
	}, nil
}

// buildKirbiFromGokrb5 converts a gokrb5 ticket to our kirbi format.
func buildKirbiFromGokrb5(tgt *gokrb5messages.Ticket, key *gokrb5types.EncryptionKey, username string) (*ticket.Kirbi, error) {
	return buildKirbiFromGokrb5WithRaw(tgt, key, username, nil)
}

// buildKirbiFromGokrb5WithRaw converts a gokrb5 ticket to our kirbi format.
// If rawTktBytes is provided, it will be used as the raw ticket bytes (from KDC).
func buildKirbiFromGokrb5WithRaw(tgt *gokrb5messages.Ticket, key *gokrb5types.EncryptionKey, username string, rawTktBytes []byte) (*ticket.Kirbi, error) {
	// Get ticket bytes - prefer raw if available
	var tktBytes []byte
	var err error
	if len(rawTktBytes) > 0 {
		tktBytes = rawTktBytes
		fmt.Printf("[DEBUG] Using raw ticket bytes from AS-REP: %d bytes\n", len(tktBytes))
	} else {
		// Fall back to gokrb5's Marshal (may differ from KDC encoding)
		tktBytes, err = tgt.Marshal()
		if err != nil {
			return nil, err
		}
		fmt.Printf("[DEBUG] Using gokrb5 marshaled ticket bytes: %d bytes\n", len(tktBytes))
	}

	// Build Ticket struct directly from gokrb5 ticket fields
	// Store RawBytes so Marshal() uses the exact KDC encoding
	parsedTicket := asn1krb5.Ticket{
		TktVno: tgt.TktVNO,
		Realm:  tgt.Realm,
		SName: asn1krb5.PrincipalName{
			NameType:   int32(tgt.SName.NameType),
			NameString: tgt.SName.NameString,
		},
		EncPart: asn1krb5.EncryptedData{
			EType:  int32(tgt.EncPart.EType),
			Kvno:   int32(tgt.EncPart.KVNO),
			Cipher: tgt.EncPart.Cipher,
		},
		RawBytes: tktBytes, // Use exact KDC bytes when marshaling
	}

	// Build credential info with session key (EncKRBCredPart)
	credInfo := asn1krb5.EncKRBCredPart{
		TicketInfo: []asn1krb5.KRBCredInfo{
			{
				Key: asn1krb5.EncryptionKey{
					KeyType:  int32(key.KeyType),
					KeyValue: key.KeyValue,
				},
				PRealm: tgt.Realm,
				PName: asn1krb5.PrincipalName{
					NameType:   asn1krb5.NTPrincipal,
					NameString: []string{username}, // Client principal name
				},
				SRealm: tgt.Realm,
				SName: asn1krb5.PrincipalName{
					NameType:   int32(tgt.SName.NameType),
					NameString: tgt.SName.NameString,
				},
			},
		},
	}

	// Marshal credential info for the enc-part
	credInfoBytes, err := asn1.MarshalWithParams(credInfo, "application,tag:29")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal cred info: %w", err)
	}

	// Build a complete KRB-CRED manually using raw bytes
	// Structure: APPLICATION 22 SEQUENCE { [0] pvno, [1] msg-type, [2] SEQUENCE OF Ticket, [3] EncryptedData }

	// Helper to build length bytes
	buildLen := func(l int) []byte {
		if l < 128 {
			return []byte{byte(l)}
		} else if l < 256 {
			return []byte{0x81, byte(l)}
		} else {
			return []byte{0x82, byte(l >> 8), byte(l & 0xff)}
		}
	}

	wrapContext := func(tag int, data []byte) []byte {
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

	// [0] pvno INTEGER(5)
	pvnoData := wrapContext(0, []byte{0x02, 0x01, 0x05})

	// [1] msg-type INTEGER(22)
	msgTypeData := wrapContext(1, []byte{0x02, 0x01, 0x16})

	// [2] tickets SEQUENCE OF Ticket - wrap the raw ticket bytes in a SEQUENCE
	ticketsSeq := wrapSeq(tktBytes)
	ticketsData := wrapContext(2, ticketsSeq)

	// [3] enc-part EncryptedData { [0] etype INTEGER(0), [1] cipher OCTET STRING }
	// etype = 0 (NULL encryption)
	etypeTagged := wrapContext(0, []byte{0x02, 0x01, 0x00})
	// cipher = credInfoBytes as OCTET STRING
	cipherLen := buildLen(len(credInfoBytes))
	cipherOctet := append([]byte{0x04}, cipherLen...)
	cipherOctet = append(cipherOctet, credInfoBytes...)
	cipherTagged := wrapContext(2, cipherOctet) // [2] cipher

	encPartSeq := wrapSeq(append(etypeTagged, cipherTagged...))
	encPartData := wrapContext(3, encPartSeq)

	// Build inner SEQUENCE
	inner := append(pvnoData, msgTypeData...)
	inner = append(inner, ticketsData...)
	inner = append(inner, encPartData...)

	innerSeq := wrapSeq(inner)

	// Wrap in APPLICATION 22
	krbCredBytes := wrapApp(22, innerSeq)

	// Build Cred struct with the ticket
	cred := &asn1krb5.KRBCred{
		PVNO:    asn1krb5.PVNO,
		MsgType: asn1krb5.MsgTypeKRBCred,
		Tickets: []asn1krb5.Ticket{parsedTicket},
		EncPart: asn1krb5.EncryptedData{
			EType:  0, // NULL encryption
			Cipher: credInfoBytes,
		},
	}

	// Return kirbi with both RawBytes AND Cred set
	return &ticket.Kirbi{
		RawBytes:       krbCredBytes,
		DecryptKey:     key.KeyValue,
		DecryptKeyType: int(key.KeyType),
		CredInfo:       &credInfo,
		Cred:           cred,
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
	// KRB-ERROR has APPLICATION tag 30 (0x7e)
	// Check for both short-form (0x7e) and long-form encoding
	if len(data) == 0 {
		return nil
	}

	// APPLICATION 30 = 0x60 | 30 = 0x7e
	isKrbError := data[0] == 0x7e

	// Also handle constructed form: 0x7e with length encoding
	if !isKrbError && len(data) > 2 {
		// Long form APPLICATION tag: 0x7f followed by tag number
		isKrbError = data[0] == 0x7f && data[1] == 30
	}

	if isKrbError {
		var krbErr asn1krb5.KRBError
		_, err := asn1.UnmarshalWithParams(data, &krbErr, "application,tag:30")
		if err == nil {
			return &KerberosError{
				Code:    krbErr.ErrorCode,
				Message: krbErr.EText,
			}
		}
		// If parsing fails, try to manually extract error code
		// Error code is at [6] tag within the SEQUENCE
		errorCode := extractErrorCode(data)
		if errorCode >= 0 {
			return &KerberosError{
				Code:    int32(errorCode),
				Message: fmt.Sprintf("(parsing failed: %v)", err),
			}
		}
		return fmt.Errorf("received KRB-ERROR but failed to parse: %w", err)
	}
	return nil
}

// extractErrorCode manually extracts error code from KRB-ERROR
func extractErrorCode(data []byte) int {
	// Find [6] tag (0xa6) which contains the error code
	for i := 0; i < len(data)-3; i++ {
		if data[i] == 0xa6 {
			// Found [6] tag, get length and extract INTEGER
			offset := i + 1
			var length int
			if data[offset] < 0x80 {
				length = int(data[offset])
				offset++
			} else if data[offset] == 0x81 {
				length = int(data[offset+1])
				offset += 2
			} else {
				continue
			}
			_ = length // suppress unused warning
			// Now we should have an INTEGER (0x02)
			if offset < len(data) && data[offset] == 0x02 {
				intLen := int(data[offset+1])
				if offset+2+intLen <= len(data) {
					// Read the integer value
					val := 0
					for j := 0; j < intLen; j++ {
						val = (val << 8) | int(data[offset+2+j])
					}
					return val
				}
			}
		}
	}
	return -1
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
