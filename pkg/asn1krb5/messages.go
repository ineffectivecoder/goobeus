package asn1krb5

import (
	"encoding/asn1"
	"time"
)

// ASREQ is an Authentication Service Request.
//
// EDUCATIONAL: The AS Exchange - Getting Your TGT
//
// The AS (Authentication Service) exchange is the first step in Kerberos.
// You send an AS-REQ to get a TGT (Ticket Granting Ticket):
//
//	Client                                KDC
//	   |                                   |
//	   |  1. AS-REQ (I am jsmith)          |
//	   |---------------------------------->|
//	   |                                   |
//	   |  2. AS-REP (Here's your TGT)      |
//	   |<----------------------------------|
//
// The AS-REQ contains:
//   - Who you are (CName)
//   - What you want (TGT for krbtgt/REALM)
//   - Pre-authentication (encrypted timestamp proving password)
//   - Requested encryption types
//   - Requested ticket options
//
// Pre-Authentication Attack Surface:
//   - If account has "Do not require Kerberos preauthentication" → AS-REP Roast
//   - If you have password/hash, you can request a TGT (overpass-the-hash)
type ASREQ struct {
	PVNO    int        `asn1:"explicit,tag:1"`
	MsgType int        `asn1:"explicit,tag:2"`
	PAData  []PAData   `asn1:"optional,explicit,tag:3"`
	ReqBody KDCReqBody `asn1:"explicit,tag:4"`
}

// TGSREQ is a Ticket Granting Service Request.
//
// EDUCATIONAL: The TGS Exchange - Getting Service Tickets
//
// After you have a TGT, you use it to request service tickets:
//
//	Client                                KDC
//	   |                                   |
//	   |  1. TGS-REQ (TGT + I want HTTP/web)|
//	   |---------------------------------->|
//	   |                                   |
//	   |  2. TGS-REP (Here's your ST)      |
//	   |<----------------------------------|
//
// Key differences from AS-REQ:
//   - Includes your TGT in padata (PA-TGS-REQ)
//   - No password-based pre-auth needed (you proved identity via TGT)
//   - SName is the service you want, not krbtgt
//
// Kerberoasting Attack:
//   - Any authenticated user can request a TGS for any SPN
//   - The TGS is encrypted with the service's password hash
//   - We can extract and crack this offline!
type TGSREQ struct {
	PVNO    int        `asn1:"explicit,tag:1"`
	MsgType int        `asn1:"explicit,tag:2"`
	PAData  []PAData   `asn1:"optional,explicit,tag:3"`
	ReqBody KDCReqBody `asn1:"explicit,tag:4"`
}

// KDCReqBody is the body of AS-REQ and TGS-REQ messages.
//
// EDUCATIONAL: Request Body Contents
//
// The request body specifies:
//
//	KDCOptions:   Ticket flags you're requesting
//	CName:        Your principal name (optional in TGS-REQ)
//	Realm:        Target realm
//	SName:        Service you want a ticket for
//	From:         When ticket should be valid (optional)
//	Till:         When ticket should expire
//	RTime:        Renewal time (if requesting renewable)
//	Nonce:        Random value to match reply
//	EType:        Preferred encryption types (in order)
//	Addresses:    Restrict ticket to these IPs (optional)
//	EncAuthzData: Additional authorization data (optional)
//	AddTickets:   For S4U2Proxy (constrained delegation)
type KDCReqBody struct {
	KDCOptions           asn1.BitString `asn1:"explicit,tag:0"`
	CName                PrincipalName  `asn1:"optional,explicit,tag:1"`
	Realm                string         `asn1:"generalstring,explicit,tag:2"`
	SName                PrincipalName  `asn1:"optional,explicit,tag:3"`
	From                 time.Time      `asn1:"generalized,optional,explicit,tag:4"`
	Till                 time.Time      `asn1:"generalized,explicit,tag:5"`
	RTime                time.Time      `asn1:"generalized,optional,explicit,tag:6"`
	Nonce                int32          `asn1:"explicit,tag:7"`
	EType                []int32        `asn1:"explicit,tag:8"`
	Addresses            HostAddresses  `asn1:"optional,explicit,tag:9"`
	EncAuthorizationData EncryptedData  `asn1:"optional,explicit,tag:10"`
	AdditionalTickets    []Ticket       `asn1:"optional,explicit,tag:11"`
}

// ASREP is an Authentication Service Reply.
//
// EDUCATIONAL: The AS-REP - Your Golden Ticket (Well, TGT)
//
// The AS-REP contains:
//   - Your TGT (encrypted with krbtgt's key - you can't read it!)
//   - Encrypted part (encrypted with YOUR key - session key inside!)
//
// Two encrypted blobs, two different keys:
//
//  1. Ticket.EncPart: Encrypted with krbtgt's key
//     - Only KDC can decrypt
//     - Contains session key, your identity, PAC, validity times
//
//  2. EncPart: Encrypted with your password-derived key
//     - You can decrypt this!
//     - Contains: session key (copy), nonce, times, flags
//
// Golden Ticket Attack:
//   - If you have krbtgt's key, you can decrypt AND forge any TGT
//   - You control the PAC = you control group memberships
//   - Valid until krbtgt password changes TWICE
type ASREP struct {
	PVNO    int           `asn1:"explicit,tag:0"`
	MsgType int           `asn1:"explicit,tag:1"`
	PAData  []PAData      `asn1:"optional,explicit,tag:2"`
	CRealm  string        `asn1:"generalstring,explicit,tag:3"`
	CName   PrincipalName `asn1:"explicit,tag:4"`
	Ticket  Ticket        `asn1:"explicit,tag:5"`
	EncPart EncryptedData `asn1:"explicit,tag:6"`
}

// TGSREP is a Ticket Granting Service Reply.
//
// EDUCATIONAL: The TGS-REP - Your Service Ticket
//
// Similar structure to AS-REP, but:
//   - Ticket is for the requested service, not krbtgt
//   - Ticket.EncPart encrypted with service's key
//   - EncPart encrypted with TGT's session key
//
// Kerberoasting Target:
//   - Ticket.EncPart is encrypted with service account's hash
//   - We extract this and crack offline
//   - Service accounts often have weak passwords!
type TGSREP struct {
	PVNO    int           `asn1:"explicit,tag:0"`
	MsgType int           `asn1:"explicit,tag:1"`
	PAData  []PAData      `asn1:"optional,explicit,tag:2"`
	CRealm  string        `asn1:"generalstring,explicit,tag:3"`
	CName   PrincipalName `asn1:"explicit,tag:4"`
	Ticket  Ticket        `asn1:"explicit,tag:5"`
	EncPart EncryptedData `asn1:"explicit,tag:6"`
}

// EncASRepPart is the encrypted part of AS-REP (decryptable by client).
//
// EDUCATIONAL: What's Inside Your Encrypted Reply
//
// After decrypting with your password-derived key, you get:
//   - Key: Session key to use with this TGT
//   - LastReq: Last request times (informational)
//   - Nonce: Should match your request (anti-replay)
//   - KeyExpiration: When your password expires
//   - Flags: What the ticket allows
//   - AuthTime: When you authenticated
//   - StartTime: When ticket is valid from
//   - EndTime: When ticket expires
//   - RenewTill: Can renew until this time
//   - SRealm/SName: What service the ticket is for
//   - CAddr: Address restrictions
type EncASRepPart struct {
	Key           EncryptionKey  `asn1:"explicit,tag:0"`
	LastReq       LastReq        `asn1:"explicit,tag:1"`
	Nonce         int32          `asn1:"explicit,tag:2"`
	KeyExpiration time.Time      `asn1:"generalized,optional,explicit,tag:3"`
	Flags         asn1.BitString `asn1:"explicit,tag:4"`
	AuthTime      time.Time      `asn1:"generalized,explicit,tag:5"`
	StartTime     time.Time      `asn1:"generalized,optional,explicit,tag:6"`
	EndTime       time.Time      `asn1:"generalized,explicit,tag:7"`
	RenewTill     time.Time      `asn1:"generalized,optional,explicit,tag:8"`
	SRealm        string         `asn1:"generalstring,explicit,tag:9"`
	SName         PrincipalName  `asn1:"explicit,tag:10"`
	CAddr         HostAddresses  `asn1:"optional,explicit,tag:11"`
}

// EncTGSRepPart is identical to EncASRepPart but with APPLICATION tag 26
type EncTGSRepPart = EncASRepPart

// APREQ is an AP-REQ message (Application Request).
//
// EDUCATIONAL: AP Exchange
//
// AP-REQ is sent from client to application server to authenticate.
// It contains:
//   - APOptions: Flags for the request
//   - Ticket: The service ticket from TGS exchange
//   - Authenticator: Encrypted blob proving you have the session key
//
// For TGS-REQ, we include an AP-REQ in the PA-TGS-REQ padata with
// the TGT as the ticket.
type APREQ struct {
	PVNO          int            `asn1:"explicit,tag:0"`
	MsgType       int            `asn1:"explicit,tag:1"`
	APOptions     asn1.BitString `asn1:"explicit,tag:2"`
	Ticket        Ticket         `asn1:"explicit,tag:3"`
	Authenticator EncryptedData  `asn1:"explicit,tag:4"`
}

// APREP is an AP-REP message (Application Reply).
type APREP struct {
	PVNO    int           `asn1:"explicit,tag:0"`
	MsgType int           `asn1:"explicit,tag:1"`
	EncPart EncryptedData `asn1:"explicit,tag:2"`
}

// Authenticator proves knowledge of the session key.
//
// EDUCATIONAL: Authenticators
//
// An Authenticator proves you have the session key without revealing it.
// It contains:
//   - CTime/CUsec: Current timestamp (anti-replay)
//   - CRealm/CName: Your identity
//   - Subkey: Optional new session key for forward secrecy
//   - SeqNumber: Sequence number for ordering
//
// The authenticator is encrypted with the session key from the TGT
// (for TGS-REQ) or service ticket (for AP-REQ to a service).
type Authenticator struct {
	AuthenticatorVno  int               `asn1:"explicit,tag:0"`
	CRealm            string            `asn1:"generalstring,explicit,tag:1"`
	CName             PrincipalName     `asn1:"explicit,tag:2"`
	Cksum             Checksum          `asn1:"optional,explicit,tag:3"`
	CUsec             int32             `asn1:"explicit,tag:4"`
	CTime             time.Time         `asn1:"generalized,explicit,tag:5"`
	Subkey            EncryptionKey     `asn1:"optional,explicit,tag:6"`
	SeqNumber         uint32            `asn1:"optional,explicit,tag:7"`
	AuthorizationData AuthorizationData `asn1:"optional,explicit,tag:8"`
}

// KRBError is a Kerberos error message.
//
// EDUCATIONAL: Kerberos Error Codes
//
// Common error codes you'll encounter:
//
//	KDC_ERR_C_PRINCIPAL_UNKNOWN (6): User doesn't exist
//	KDC_ERR_PREAUTH_REQUIRED (25): Need pre-authentication
//	KDC_ERR_PREAUTH_FAILED (24): Wrong password
//	KRB_AP_ERR_TKT_EXPIRED (32): Ticket expired
//	KRB_AP_ERR_SKEW (37): Time difference too great
//
// Attack use:
//   - Error 6 = user enumeration (user doesn't exist)
//   - Error 25+edata = tells you what etypes are supported
//   - Successfully getting any error after sending creds = user exists
type KRBError struct {
	PVNO      int           `asn1:"explicit,tag:0"`
	MsgType   int           `asn1:"explicit,tag:1"`
	CTime     time.Time     `asn1:"generalized,optional,explicit,tag:2"`
	CUSec     int32         `asn1:"optional,explicit,tag:3"`
	STime     time.Time     `asn1:"generalized,explicit,tag:4"`
	SUSec     int32         `asn1:"explicit,tag:5"`
	ErrorCode int32         `asn1:"explicit,tag:6"`
	CRealm    string        `asn1:"generalstring,optional,explicit,tag:7"`
	CName     PrincipalName `asn1:"optional,explicit,tag:8"`
	Realm     string        `asn1:"generalstring,explicit,tag:9"`
	SName     PrincipalName `asn1:"explicit,tag:10"`
	EText     string        `asn1:"generalstring,optional,explicit,tag:11"`
	EData     []byte        `asn1:"optional,explicit,tag:12"`
}

// Error codes
const (
	KDCErrNone                   = 0
	KDCErrNameExpired            = 1
	KDCErrServiceExpired         = 2
	KDCErrBadPvno                = 3
	KDCErrCOldMastKVNO           = 4
	KDCErrSOldMastKVNO           = 5
	KDCErrCPrincipalUnknown      = 6
	KDCErrSPrincipalUnknown      = 7
	KDCErrPrincipalNotUnique     = 8
	KDCErrNullKey                = 9
	KDCErrCannotPostdate         = 10
	KDCErrNeverValid             = 11
	KDCErrPolicy                 = 12
	KDCErrBadOption              = 13
	KDCErrEtypeNotSupp           = 14
	KDCErrSumtypeNotSupp         = 15
	KDCErrPadataTypeNotSupp      = 16
	KDCErrTrTypeNotSupp          = 17
	KDCErrClientRevoked          = 18
	KDCErrServiceRevoked         = 19
	KDCErrTgtRevoked             = 20
	KDCErrClientNotYetValid      = 21
	KDCErrServiceNotYetValid     = 22
	KDCErrKeyExpired             = 23
	KDCErrPreauthFailed          = 24
	KDCErrPreauthRequired        = 25
	KDCErrServerNomatch          = 26
	KDCErrMustUseUser2User       = 27
	KDCErrPathNotAccepted        = 28
	KDCErrSvcUnavailable         = 29
	KRBAPErrBadIntegrity         = 31
	KRBAPErrTktExpired           = 32
	KRBAPErrTktNYV               = 33
	KRBAPErrRepeat               = 34
	KRBAPErrNotUs                = 35
	KRBAPErrBadMatch             = 36
	KRBAPErrSkew                 = 37
	KRBAPErrBadAddr              = 38
	KRBAPErrBadVersion           = 39
	KRBAPErrMsgType              = 40
	KRBAPErrModified             = 41
	KRBAPErrBadOrder             = 42
	KRBAPErrBadKeyVer            = 44
	KRBAPErrNoKey                = 45
	KRBAPErrMutFail              = 46
	KRBAPErrBsecKCsum            = 47
	KRBAPErrNoTgt                = 48
	KRBErrGeneric                = 60
	KRBErrFieldToolong           = 61
	KDCErrClientNotTrusted       = 62
	KDCErrKDCNotTrusted          = 63
	KDCErrInvalidSig             = 64
	KDCErrDHKeyParamsNotAccepted = 65
	KDCErrCertificateRevoked     = 70
	KDCErrCertPathValidation     = 71
	KDCErrSupplementalMismatch   = 72
)

// NewASREQ creates a new AS-REQ message.
func NewASREQ(realm string, cname, sname PrincipalName, padata []PAData, options KDCReqBody) *ASREQ {
	return &ASREQ{
		PVNO:    PVNO,
		MsgType: MsgTypeASREQ,
		PAData:  padata,
		ReqBody: options,
	}
}

// NewTGSREQ creates a new TGS-REQ message.
func NewTGSREQ(realm string, sname PrincipalName, padata []PAData, options KDCReqBody) *TGSREQ {
	return &TGSREQ{
		PVNO:    PVNO,
		MsgType: MsgTypeTGSREQ,
		PAData:  padata,
		ReqBody: options,
	}
}

// KRBPriv is a KRB-PRIV message for encrypted private data.
//
// EDUCATIONAL: KRB-PRIV Message
//
// KRB-PRIV carries encrypted application data with integrity.
// Used for:
//   - Password change protocol (kpasswd)
//   - Secure data exchange between principals
type KRBPriv struct {
	PVNO    int           `asn1:"explicit,tag:0"`
	MsgType int           `asn1:"explicit,tag:1"`
	EncPart EncryptedData `asn1:"explicit,tag:3"`
}
