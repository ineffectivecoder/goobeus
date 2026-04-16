// Package gssapi - AP-REQ construction for direct Kerberos authentication.
// This bypasses Windows SSPI and allows goobeus to control all AP-REQ fields.
package gssapi

import (
	"crypto/rand"
	"encoding/asn1"
	"fmt"
	"time"

	"github.com/goobeus/goobeus/pkg/asn1krb5"
	"github.com/goobeus/goobeus/pkg/crypto"
	"github.com/goobeus/goobeus/pkg/ticket"
)

// AP-REQ ASN.1 structure (RFC 4120)
// AP-REQ ::= [APPLICATION 14] SEQUENCE {
//     pvno [0] INTEGER,
//     msg-type [1] INTEGER,
//     ap-options [2] APOptions,
//     ticket [3] Ticket,
//     authenticator [4] EncryptedData
// }

// APOptions flags
const (
	APOptionReserved       = 0
	APOptionUseSessionKey  = 1 // bit 1
	APOptionMutualRequired = 2 // bit 2
)

// APREQ represents a Kerberos AP-REQ message
type APREQ struct {
	PVNO          int                    // Always 5
	MsgType       int                    // Always 14
	APOptions     asn1.BitString         // AP options
	Ticket        asn1krb5.Ticket        // The service ticket
	Authenticator asn1krb5.EncryptedData // Encrypted authenticator
}

// Authenticator structure (RFC 4120)
// Authenticator ::= [APPLICATION 2] SEQUENCE {
//     authenticator-vno [0] INTEGER,
//     crealm [1] Realm,
//     cname [2] PrincipalName,
//     cksum [3] Checksum OPTIONAL,
//     cusec [4] Microseconds,
//     ctime [5] KerberosTime,
//     subkey [6] EncryptionKey OPTIONAL,
//     seq-number [7] UInt32 OPTIONAL,
//     authorization-data [8] AuthorizationData OPTIONAL
// }

// KerberosAuthenticator is the plaintext authenticator before encryption
type KerberosAuthenticator struct {
	AuthenticatorVno int                     `asn1:"explicit,tag:0"`
	CRealm           string                  `asn1:"generalstring,explicit,tag:1"`
	CName            asn1krb5.PrincipalName  `asn1:"explicit,tag:2"`
	Cksum            *Checksum               `asn1:"optional,explicit,tag:3"`
	Cusec            int                     `asn1:"explicit,tag:4"`
	Ctime            time.Time               `asn1:"generalized,explicit,tag:5"`
	Subkey           *asn1krb5.EncryptionKey `asn1:"optional,explicit,tag:6"`
	SeqNumber        *uint32                 `asn1:"optional,explicit,tag:7"`
}

// Checksum structure for authenticator
type Checksum struct {
	CksumType int    `asn1:"explicit,tag:0"`
	Checksum  []byte `asn1:"explicit,tag:1"`
}

// APREQRequest contains the parameters for building an AP-REQ
type APREQRequest struct {
	Ticket         *ticket.Kirbi // Service ticket (from TGS or forged)
	SessionKey     []byte        // Session key from ticket
	SessionKeyType int32         // Encryption type of session key
	CRealm         string        // Client realm
	CName          []string      // Client principal name
	TargetSPN      string        // Target service principal (for logging)
	GSSFlags       uint32        // GSS-API flags
	MutualAuth     bool          // Request mutual authentication
	Subkey         []byte        // Optional subkey (nil = no subkey)
	SeqNumber      uint32        // Sequence number
}

// BuildAPREQ constructs a complete AP-REQ message ready for transmission.
// This is the core function that bypasses Windows SSPI.
func BuildAPREQ(req *APREQRequest) ([]byte, error) {
	if req.Ticket == nil || len(req.Ticket.Cred.Tickets) == 0 {
		return nil, ErrInvalidAPREQ
	}
	if len(req.SessionKey) == 0 {
		return nil, ErrMissingSessionKey
	}

	// Build the GSS checksum (this is what CrowdStrike checks!)
	gssChecksum := NewCheckSumField(req.GSSFlags)
	checksumBytes := gssChecksum.Marshal()

	// Build authenticator
	now := time.Now().UTC()
	seqNum := req.SeqNumber
	if seqNum == 0 {
		// Generate random sequence number
		buf := make([]byte, 4)
		rand.Read(buf)
		seqNum = uint32(buf[0])<<24 | uint32(buf[1])<<16 | uint32(buf[2])<<8 | uint32(buf[3])
	}

	auth := KerberosAuthenticator{
		AuthenticatorVno: 5,
		CRealm:           req.CRealm,
		CName: asn1krb5.PrincipalName{
			NameType:   asn1krb5.NTPrincipal,
			NameString: req.CName,
		},
		Cksum: &Checksum{
			CksumType: GSS_CHECKSUM_TYPE, // 0x8003
			Checksum:  checksumBytes,
		},
		Cusec:     int(now.Nanosecond() / 1000),
		Ctime:     now,
		SeqNumber: &seqNum,
	}

	// Add subkey if provided
	if len(req.Subkey) > 0 {
		auth.Subkey = &asn1krb5.EncryptionKey{
			KeyType:  req.SessionKeyType,
			KeyValue: req.Subkey,
		}
	}

	// Marshal authenticator
	authBytes, err := marshalAuthenticator(&auth)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal authenticator: %w", err)
	}

	// Encrypt authenticator with session key (key usage 11)
	var encAuthBytes []byte
	switch req.SessionKeyType {
	case crypto.EtypeAES256, crypto.EtypeAES128:
		encAuthBytes, err = crypto.EncryptAES(req.SessionKey, authBytes, 11, int(req.SessionKeyType))
	case crypto.EtypeRC4:
		encAuthBytes, err = crypto.EncryptRC4(req.SessionKey, authBytes, 11)
	default:
		return nil, ErrUnsupportedEtype
	}
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt authenticator: %w", err)
	}

	// Build AP options
	apOptions := asn1.BitString{
		Bytes:     make([]byte, 4),
		BitLength: 32,
	}
	if req.MutualAuth {
		// Set mutual-required bit (bit 2)
		apOptions.Bytes[0] |= 0x20 // bit 2
	}

	// Build AP-REQ
	apreq := &APREQ{
		PVNO:      5,
		MsgType:   14, // AP-REQ
		APOptions: apOptions,
		Ticket:    req.Ticket.Cred.Tickets[0],
		Authenticator: asn1krb5.EncryptedData{
			EType:  req.SessionKeyType,
			Cipher: encAuthBytes,
		},
	}

	// Marshal AP-REQ
	apreqBytes, err := marshalAPREQ(apreq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal AP-REQ: %w", err)
	}

	return apreqBytes, nil
}

// BuildGSSAPIToken wraps an AP-REQ in a GSS-API token for SPNEGO.
func BuildGSSAPIToken(apreqBytes []byte) []byte {
	// GSS-API token format:
	// 0x60 [length] OID AP-REQ-token
	// AP-REQ-token: 0x01 0x00 [AP-REQ bytes]

	apReqToken := append([]byte{0x01, 0x00}, apreqBytes...) // KRB5_AP_REQ prefix
	innerToken := append(KerberosOID, apReqToken...)

	// Wrap in APPLICATION 0 (0x60)
	return wrapApplication0(innerToken)
}

// wrapApplication0 wraps data in ASN.1 APPLICATION 0 tag
func wrapApplication0(data []byte) []byte {
	length := len(data)
	var result []byte

	if length < 128 {
		result = make([]byte, 2+length)
		result[0] = 0x60
		result[1] = byte(length)
		copy(result[2:], data)
	} else if length < 256 {
		result = make([]byte, 3+length)
		result[0] = 0x60
		result[1] = 0x81
		result[2] = byte(length)
		copy(result[3:], data)
	} else {
		result = make([]byte, 4+length)
		result[0] = 0x60
		result[1] = 0x82
		result[2] = byte(length >> 8)
		result[3] = byte(length)
		copy(result[4:], data)
	}

	return result
}

// marshalAuthenticator encodes the authenticator with APPLICATION 2 tag
func marshalAuthenticator(auth *KerberosAuthenticator) ([]byte, error) {
	// Marshal the authenticator sequence
	seqBytes, err := asn1.Marshal(*auth)
	if err != nil {
		return nil, err
	}

	// Wrap in APPLICATION 2
	return wrapApplication(2, seqBytes), nil
}

// marshalAPREQ encodes the AP-REQ with APPLICATION 14 tag
func marshalAPREQ(apreq *APREQ) ([]byte, error) {
	// We need to manually construct this due to the Ticket field
	// which requires APPLICATION 1 wrapping

	// Helper to build length bytes
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

	// [0] pvno INTEGER
	pvnoBytes, _ := asn1.Marshal(apreq.PVNO)
	pvno := wrapExplicit(0, pvnoBytes)

	// [1] msg-type INTEGER
	msgTypeBytes, _ := asn1.Marshal(apreq.MsgType)
	msgType := wrapExplicit(1, msgTypeBytes)

	// [2] ap-options BIT STRING
	apOptionsBytes, _ := asn1.Marshal(apreq.APOptions)
	apOptions := wrapExplicit(2, apOptionsBytes)

	// [3] ticket Ticket - use raw bytes if available
	var ticketBytes []byte
	if len(apreq.Ticket.RawBytes) > 0 {
		ticketBytes = apreq.Ticket.RawBytes
	} else {
		ticketBytes, _ = apreq.Ticket.Marshal()
	}
	ticketField := wrapExplicit(3, ticketBytes)

	// [4] authenticator EncryptedData
	encDataBytes, _ := asn1.Marshal(apreq.Authenticator)
	authenticator := wrapExplicit(4, encDataBytes)

	// Build inner sequence
	inner := append(pvno, msgType...)
	inner = append(inner, apOptions...)
	inner = append(inner, ticketField...)
	inner = append(inner, authenticator...)

	innerSeq := wrapSeq(inner)

	// Wrap in APPLICATION 14
	return wrapApplication(14, innerSeq), nil
}

// wrapApplication wraps data in an ASN.1 APPLICATION tag
func wrapApplication(tag int, data []byte) []byte {
	appTag := byte(0x60 + tag) // APPLICATION tags start at 0x60
	length := len(data)

	var result []byte
	if length < 128 {
		result = make([]byte, 2+length)
		result[0] = appTag
		result[1] = byte(length)
		copy(result[2:], data)
	} else if length < 256 {
		result = make([]byte, 3+length)
		result[0] = appTag
		result[1] = 0x81
		result[2] = byte(length)
		copy(result[3:], data)
	} else {
		result = make([]byte, 4+length)
		result[0] = appTag
		result[1] = 0x82
		result[2] = byte(length >> 8)
		result[3] = byte(length)
		copy(result[4:], data)
	}

	return result
}
