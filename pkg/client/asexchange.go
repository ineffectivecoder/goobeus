package client

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/goobeus/goobeus/internal/network"
	"github.com/goobeus/goobeus/pkg/asn1krb5"
	"github.com/goobeus/goobeus/pkg/crypto"
)

// NativeASExchange performs AS exchange using our own ASN.1 encoding.
// This bypasses gokrb5 to ensure we get exact control over the request
// and response handling, particularly for the session key.
//
// It implements 2-phase AS exchange like Impacket:
// 1. Send AS-REQ without preauth to get KDC's preauth requirements
// 2. Send AS-REQ with PA-ENC-TIMESTAMP after receiving KDC_ERR_PREAUTH_REQUIRED
func NativeASExchange(ctx context.Context, domain, username, password, kdc string) (*NativeASResult, error) {
	realm := strings.ToUpper(domain)

	fmt.Println("[*] Native AS exchange starting...")

	// Generate client key from password (RFC 3962 string-to-key)
	salt := crypto.BuildAESSalt(realm, username)
	clientKey := crypto.AES256Key(password, salt)

	fmt.Printf("[DEBUG] Native AS-REQ: realm=%s, user=%s, salt=%s\n", realm, username, salt)
	fmt.Printf("[DEBUG] Client key (AES256): first8=%x\n", clientKey[:8])

	// Phase 1: Send AS-REQ WITHOUT preauth
	asReq1 := buildNativeASREQNoPreauth(realm, username)

	fmt.Printf("[DEBUG] Phase 1 AS-REQ (no preauth): %d bytes\n", len(asReq1))
	os.WriteFile("native_asreq_p1.bin", asReq1, 0600)

	resp1, err := network.SendToKDCWithContext(ctx, realm, kdc, asReq1)
	if err != nil {
		return nil, fmt.Errorf("AS Phase 1 failed: %w", err)
	}

	fmt.Printf("[DEBUG] Phase 1 response: %d bytes\n", len(resp1))

	// Check if we got AS-REP (account has no preauth required) or KRB-ERROR
	if len(resp1) > 0 && resp1[0] == 0x6b { // APPLICATION 11 = AS-REP
		fmt.Println("[DEBUG] Got AS-REP without preauth (account has no preauth required)")
		return parseNativeASREP(resp1, clientKey)
	}

	// Expect KDC_ERR_PREAUTH_REQUIRED (25)
	if len(resp1) > 0 && resp1[0] == 0x7e { // APPLICATION 30 = KRB-ERROR
		fmt.Println("[DEBUG] Got KRB-ERROR (expected preauth required)")
		// Parse error to confirm it's preauth required
		// For now, just proceed with Phase 2
	} else if len(resp1) == 0 {
		return nil, fmt.Errorf("KDC returned empty response in Phase 1")
	}

	// Phase 2: Send AS-REQ WITH preauth
	now := time.Now().UTC()
	asReq2, nonce, err := buildNativeASREQWithPreauth(realm, username, clientKey, now)
	if err != nil {
		return nil, fmt.Errorf("failed to build Phase 2 AS-REQ: %w", err)
	}

	fmt.Printf("[DEBUG] Phase 2 AS-REQ (with preauth): %d bytes\n", len(asReq2))
	os.WriteFile("native_asreq_p2.bin", asReq2, 0600)
	_ = nonce // will use for validation later

	resp2, err := network.SendToKDCWithContext(ctx, realm, kdc, asReq2)
	if err != nil {
		return nil, fmt.Errorf("AS Phase 2 failed: %w", err)
	}

	fmt.Printf("[DEBUG] Phase 2 response: %d bytes\n", len(resp2))

	// Parse AS-REP and extract ticket + session key
	return parseNativeASREP(resp2, clientKey)
}

// NativeASResult contains the result of a native AS exchange.
type NativeASResult struct {
	TicketBytes []byte                 // Raw ticket bytes (APPLICATION 1)
	Ticket      asn1krb5.Ticket        // Parsed ticket struct
	SessionKey  asn1krb5.EncryptionKey // Session key from enc-part
	CRealm      string
	CName       []string
}

// buildNativeASREQNoPreauth builds Phase 1 AS-REQ without preauth (like Impacket's first request).
// KDC will respond with KDC_ERR_PREAUTH_REQUIRED (25) and tell us what preauth types it accepts.
func buildNativeASREQNoPreauth(realm, username string) []byte {
	now := time.Now().UTC()
	till := now.Add(24 * time.Hour)
	nonce := rand.Uint32()

	// KDC options: FORWARDABLE | RENEWABLE (matching Impacket's 0x50800000)
	kdcOptions := []byte{0x50, 0x80, 0x00, 0x00}

	// Build name strings
	cname := buildPrincipalName(1, []string{username})        // NT_PRINCIPAL
	sname := buildPrincipalName(1, []string{"krbtgt", realm}) // NT_PRINCIPAL for krbtgt

	// Build req-body
	reqBody := buildASReqBody(kdcOptions, cname, realm, sname, till, nonce)

	// Only PA-PAC-REQUEST, no PA-ENC-TIMESTAMP
	paPacRequest := buildPAPacRequestValue(true) // Just the value, not wrapped in PA-DATA

	// Build padata SEQUENCE containing only PA-PAC-REQUEST
	padataSeq := buildPAData(128, paPacRequest) // PA-PAC-REQUEST = 128
	padataField := wrapContextTag(3, wrapSequence(padataSeq))

	// Build AS-REQ without PA-ENC-TIMESTAMP
	var asReq []byte
	// [1] pvno
	asReq = append(asReq, wrapContextTag(1, []byte{0x02, 0x01, 0x05})...)
	// [2] msg-type (AS-REQ = 10)
	asReq = append(asReq, wrapContextTag(2, []byte{0x02, 0x01, 0x0a})...)
	// [3] padata
	asReq = append(asReq, padataField...)
	// [4] req-body
	asReq = append(asReq, wrapContextTag(4, reqBody)...)

	innerSeq := wrapSequence(asReq)
	return wrapApplication(10, innerSeq)
}

// buildNativeASREQWithPreauth builds Phase 2 AS-REQ with PA-ENC-TIMESTAMP preauth.
func buildNativeASREQWithPreauth(realm, username string, clientKey []byte, now time.Time) ([]byte, uint32, error) {
	till := now.Add(24 * time.Hour)
	nonce := rand.Uint32()

	// KDC options: FORWARDABLE | RENEWABLE | PROXIABLE
	kdcOptions := []byte{0x40, 0x81, 0x00, 0x10}

	// Build name strings
	cname := buildPrincipalName(1, []string{username})
	sname := buildPrincipalName(1, []string{"krbtgt", realm})

	// Build req-body
	reqBody := buildASReqBody(kdcOptions, cname, realm, sname, till, nonce)

	// Build PA-ENC-TIMESTAMP
	paTimestamp, err := buildPAEncTimestampNative(clientKey, 18, now)
	if err != nil {
		return nil, 0, err
	}

	// Build PA-PAC-REQUEST
	paPacRequest := buildPAPacRequest(true)

	// Build AS-REQ
	asReq := buildASReq(paTimestamp, paPacRequest, reqBody)

	return asReq, nonce, nil
}

// buildPAPacRequestValue builds just the KERB-PA-PAC-REQUEST value (without PA-DATA wrapper).
func buildPAPacRequestValue(includePac bool) []byte {
	pacReq := wrapContextTag(0, []byte{0x01, 0x01, 0xff}) // BOOLEAN TRUE (0xff per Impacket)
	if !includePac {
		pacReq = wrapContextTag(0, []byte{0x01, 0x01, 0x00}) // BOOLEAN FALSE
	}
	return wrapSequence(pacReq)
}
func buildNativeASREQ(realm, username, password string) ([]byte, []byte, error) {
	// Generate client key from password
	salt := crypto.BuildAESSalt(realm, username)
	clientKey := crypto.AES256Key(password, salt)

	fmt.Printf("[DEBUG] Native AS-REQ: realm=%s, user=%s, salt=%s\n", realm, username, salt)
	fmt.Printf("[DEBUG] Client key (AES256): first8=%x\n", clientKey[:8])

	// Build KDC-REQ-BODY
	now := time.Now().UTC()
	till := now.Add(24 * time.Hour)
	nonce := rand.Uint32()

	// KDC options: FORWARDABLE | RENEWABLE | PROXIABLE
	kdcOptions := []byte{0x40, 0x81, 0x00, 0x10} // 0x40810010

	// Build name strings with GeneralString encoding
	cname := buildPrincipalName(1, []string{username})        // NT_PRINCIPAL
	sname := buildPrincipalName(1, []string{"krbtgt", realm}) // NT_PRINCIPAL for krbtgt

	// Build req-body
	reqBody := buildASReqBody(kdcOptions, cname, realm, sname, till, nonce)

	// Build PA-ENC-TIMESTAMP
	paTimestamp, err := buildPAEncTimestampNative(clientKey, 18, now)
	if err != nil {
		return nil, nil, err
	}

	// Build PA-PAC-REQUEST
	paPacRequest := buildPAPacRequest(true)

	// Build AS-REQ
	asReq := buildASReq(paTimestamp, paPacRequest, reqBody)

	fmt.Printf("[DEBUG] AS-REQ built: %d bytes\n", len(asReq))

	return asReq, clientKey, nil
}

func buildPrincipalName(nameType int, components []string) []byte {
	// PrincipalName ::= SEQUENCE { [0] name-type, [1] SEQUENCE OF GeneralString }

	// Build name-string SEQUENCE OF
	var nameStrings []byte
	for _, s := range components {
		// GeneralString encoding
		nameStrings = append(nameStrings, 0x1b) // GeneralString tag
		nameStrings = append(nameStrings, byte(len(s)))
		nameStrings = append(nameStrings, []byte(s)...)
	}
	nameStringSeq := wrapSequence(nameStrings)

	// Build name-type INTEGER
	nameTypeBytes := wrapContextTag(0, []byte{0x02, 0x01, byte(nameType)})

	// Build [1] name-string
	nameStringField := wrapContextTag(1, nameStringSeq)

	return wrapSequence(append(nameTypeBytes, nameStringField...))
}

func buildASReqBody(kdcOpts, cname []byte, realm string, sname []byte, till time.Time, nonce uint32) []byte {
	var body []byte

	// [0] kdc-options
	kdcOptsField := wrapContextTag(0, append([]byte{0x03, 0x05, 0x00}, kdcOpts...))
	body = append(body, kdcOptsField...)

	// [1] cname
	cnameField := wrapContextTag(1, cname)
	body = append(body, cnameField...)

	// [2] realm
	realmBytes := []byte{0x1b, byte(len(realm))}
	realmBytes = append(realmBytes, []byte(realm)...)
	realmField := wrapContextTag(2, realmBytes)
	body = append(body, realmField...)

	// [3] sname
	snameField := wrapContextTag(3, sname)
	body = append(body, snameField...)

	// [5] till
	tillStr := till.Format("20060102150405Z")
	tillBytes := []byte{0x18, byte(len(tillStr))}
	tillBytes = append(tillBytes, []byte(tillStr)...)
	tillField := wrapContextTag(5, tillBytes)
	body = append(body, tillField...)

	// [6] rtime (same as till)
	rtimeField := wrapContextTag(6, tillBytes)
	body = append(body, rtimeField...)

	// [7] nonce
	nonceBytes := []byte{0x02, 0x04, byte(nonce >> 24), byte(nonce >> 16), byte(nonce >> 8), byte(nonce)}
	nonceField := wrapContextTag(7, nonceBytes)
	body = append(body, nonceField...)

	// [8] etype
	etypes := []byte{0x30, 0x03, 0x02, 0x01, 0x12} // SEQUENCE { INTEGER 18 }
	etypesField := wrapContextTag(8, etypes)
	body = append(body, etypesField...)

	return wrapSequence(body)
}

func buildPAEncTimestampNative(key []byte, etype int, now time.Time) ([]byte, error) {
	// PA-ENC-TS-ENC ::= SEQUENCE { [0] patimestamp, [1] pausec }
	timestamp := now.Format("20060102150405Z")
	usec := now.Nanosecond() / 1000

	var paEncTs []byte
	// [0] patimestamp
	tsBytes := []byte{0x18, byte(len(timestamp))}
	tsBytes = append(tsBytes, []byte(timestamp)...)
	paEncTs = append(paEncTs, wrapContextTag(0, tsBytes)...)

	// [1] pausec
	usecBytes := []byte{0x02, 0x03, byte(usec >> 16), byte(usec >> 8), byte(usec)}
	paEncTs = append(paEncTs, wrapContextTag(1, usecBytes)...)

	plaintext := wrapSequence(paEncTs)

	// Encrypt with key usage 1
	ciphertext, err := crypto.EncryptAES(key, plaintext, 1, etype)
	if err != nil {
		return nil, err
	}

	// Build EncryptedData
	encData := buildEncryptedData(int32(etype), ciphertext)

	// Build PA-DATA
	paData := buildPAData(2, encData) // PA-ENC-TIMESTAMP = 2

	return paData, nil
}

func buildPAPacRequest(includePac bool) []byte {
	// KERB-PA-PAC-REQUEST ::= SEQUENCE { [0] include-pac BOOLEAN }
	pacReq := wrapContextTag(0, []byte{0x01, 0x01, 0x01}) // BOOLEAN TRUE
	if !includePac {
		pacReq = wrapContextTag(0, []byte{0x01, 0x01, 0x00}) // BOOLEAN FALSE
	}
	pacReqSeq := wrapSequence(pacReq)

	return buildPAData(128, pacReqSeq) // PA-PAC-REQUEST = 128
}

func buildPAData(paType int, paValue []byte) []byte {
	// PA-DATA ::= SEQUENCE { [1] padata-type INTEGER, [2] padata-value OCTET STRING }
	// NOTE: RFC 4120 uses [1] and [2], not [0] and [1]!
	var pa []byte

	// [1] padata-type
	paTypeBytes := []byte{0x02, 0x01, byte(paType)}
	if paType > 127 {
		paTypeBytes = []byte{0x02, 0x02, byte(paType >> 8), byte(paType)}
	}
	pa = append(pa, wrapContextTag(1, paTypeBytes)...)

	// [2] padata-value (OCTET STRING containing paValue)
	paValueOctet := append([]byte{0x04}, buildLength(len(paValue))...)
	paValueOctet = append(paValueOctet, paValue...)
	pa = append(pa, wrapContextTag(2, paValueOctet)...)

	return wrapSequence(pa)
}

func buildEncryptedData(etype int32, cipher []byte) []byte {
	var enc []byte

	// [0] etype
	etypeBytes := []byte{0x02, 0x01, byte(etype)}
	enc = append(enc, wrapContextTag(0, etypeBytes)...)

	// [2] cipher
	cipherOctet := append([]byte{0x04}, buildLength(len(cipher))...)
	cipherOctet = append(cipherOctet, cipher...)
	enc = append(enc, wrapContextTag(2, cipherOctet)...)

	return wrapSequence(enc)
}

func buildASReq(paTimestamp, paPacRequest, reqBody []byte) []byte {
	var asReq []byte

	// [1] pvno
	pvnoField := wrapContextTag(1, []byte{0x02, 0x01, 0x05})
	asReq = append(asReq, pvnoField...)

	// [2] msg-type (AS-REQ = 10)
	msgTypeField := wrapContextTag(2, []byte{0x02, 0x01, 0x0a})
	asReq = append(asReq, msgTypeField...)

	// [3] padata
	padata := wrapSequence(append(paTimestamp, paPacRequest...))
	padataField := wrapContextTag(3, padata)
	asReq = append(asReq, padataField...)

	// [4] req-body
	reqBodyField := wrapContextTag(4, reqBody)
	asReq = append(asReq, reqBodyField...)

	innerSeq := wrapSequence(asReq)

	// Wrap with APPLICATION 10
	return wrapApplication(10, innerSeq)
}

func parseNativeASREP(data []byte, clientKey []byte) (*NativeASResult, error) {
	// Check for KRB-ERROR
	if len(data) > 0 && data[0] == 0x7e { // APPLICATION 30
		return nil, fmt.Errorf("KDC returned error")
	}

	// AS-REP is APPLICATION 11
	if len(data) < 10 || data[0] != 0x6b {
		return nil, fmt.Errorf("not an AS-REP: first byte 0x%02x", data[0])
	}

	fmt.Printf("[DEBUG] Parsing AS-REP: %d bytes, first20=%x\n", len(data), data[:20])

	// Extract ticket (look for [5] -> APPLICATION 1)
	// Format: [5] a5 82 XX XX 61 82 YY YY ...
	var ticketBytes []byte
	var ticketEnd int // Track where ticket ends so we can find [6] after it
	for i := 0; i < len(data)-10; i++ {
		if data[i] == 0xa5 {
			// Found [5], get its length
			fieldLen := 0
			contentPos := i + 2
			if data[i+1] == 0x82 {
				fieldLen = (int(data[i+2]) << 8) | int(data[i+3])
				contentPos = i + 4
			} else if data[i+1] == 0x81 {
				fieldLen = int(data[i+2])
				contentPos = i + 3
			} else if data[i+1] < 0x80 {
				fieldLen = int(data[i+1])
				contentPos = i + 2
			}

			// Ticket content should start with APPLICATION 1 (0x61)
			if contentPos < len(data) && data[contentPos] == 0x61 {
				ticketBytes = data[contentPos : contentPos+fieldLen]
				ticketEnd = contentPos + fieldLen
				fmt.Printf("[DEBUG] Found ticket at %d, len=%d, ends at %d\n", i, fieldLen, ticketEnd)
				break
			}
		}
	}

	if len(ticketBytes) == 0 {
		return nil, fmt.Errorf("could not find ticket in AS-REP")
	}

	// Extract enc-part (look for [6] AFTER the ticket ends)
	var encPartStart int
	for i := ticketEnd; i < len(data)-6; i++ {
		if data[i] == 0xa6 {
			encPartStart = i
			break
		}
	}

	if encPartStart == 0 {
		return nil, fmt.Errorf("could not find enc-part in AS-REP")
	}

	fmt.Printf("[DEBUG] Found enc-part at %d\n", encPartStart)

	// Parse enc-part to get etype and cipher
	encPartData := data[encPartStart:]

	// Skip [6] wrapper to get to EncryptedData SEQUENCE
	pos := 2
	if encPartData[1] == 0x82 {
		pos = 4
	} else if encPartData[1] == 0x81 {
		pos = 3
	}

	// Now at EncryptedData SEQUENCE
	// Parse etype
	seqStart := pos
	if encPartData[seqStart] != 0x30 {
		return nil, fmt.Errorf("expected SEQUENCE at enc-part, got 0x%02x", encPartData[seqStart])
	}

	// Find etype [0]
	etype := 0
	for i := seqStart; i < len(encPartData)-5; i++ {
		if encPartData[i] == 0xa0 && encPartData[i+2] == 0x02 && encPartData[i+3] == 0x01 {
			etype = int(encPartData[i+4])
			break
		}
	}

	fmt.Printf("[DEBUG] enc-part etype: %d\n", etype)

	// Find cipher [2]
	var cipher []byte
	for i := seqStart; i < len(encPartData)-6; i++ {
		if encPartData[i] == 0xa2 {
			// [2] -> OCTET STRING -> cipher
			cipherStart := i + 2
			if encPartData[i+1] == 0x82 {
				cipherStart = i + 4
			} else if encPartData[i+1] == 0x81 {
				cipherStart = i + 3
			}
			// Skip OCTET STRING header
			if encPartData[cipherStart] == 0x04 {
				if encPartData[cipherStart+1] == 0x82 {
					cipherLen := (int(encPartData[cipherStart+2]) << 8) | int(encPartData[cipherStart+3])
					cipher = encPartData[cipherStart+4 : cipherStart+4+cipherLen]
				} else if encPartData[cipherStart+1] == 0x81 {
					cipherLen := int(encPartData[cipherStart+2])
					cipher = encPartData[cipherStart+3 : cipherStart+3+cipherLen]
				}
			}
			break
		}
	}

	if len(cipher) == 0 {
		return nil, fmt.Errorf("could not find cipher in enc-part")
	}

	fmt.Printf("[DEBUG] enc-part cipher: %d bytes\n", len(cipher))

	// Decrypt enc-part with client key, usage 3 (AS-REP)
	plaintext, err := crypto.DecryptAES(clientKey, cipher, 3, etype)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt enc-part: %w", err)
	}

	fmt.Printf("[DEBUG] Decrypted enc-part: %d bytes\n", len(plaintext))

	// Parse EncASRepPart to get session key
	// EncKDCRepPart ::= SEQUENCE { [0] key EncryptionKey, ... }
	sessionKey, err := extractSessionKey(plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to extract session key: %w", err)
	}

	fmt.Printf("[DEBUG] Session key: etype=%d, len=%d, first8=%x\n",
		sessionKey.KeyType, len(sessionKey.KeyValue), sessionKey.KeyValue[:8])

	// Parse ticket - extract key fields needed for TGS-REQ
	// The ticketBytes already contain the APPLICATION 1 wrapped ticket
	realm, sname := extractTicketFields(ticketBytes)
	ticket := asn1krb5.Ticket{
		TktVno:   5,
		Realm:    realm,
		SName:    sname,
		RawBytes: ticketBytes,
	}

	return &NativeASResult{
		TicketBytes: ticketBytes,
		Ticket:      ticket,
		SessionKey:  sessionKey,
		CRealm:      realm,
	}, nil
}

// extractTicketFields extracts realm and sname from raw ticket bytes.
// Format: APPLICATION 1 -> SEQUENCE -> [0] tkt-vno, [1] realm, [2] sname, [3] enc-part
func extractTicketFields(data []byte) (string, asn1krb5.PrincipalName) {
	realm := ""
	sname := asn1krb5.PrincipalName{}

	if len(data) < 10 {
		return realm, sname
	}

	// Skip APPLICATION 1 header
	pos := 0
	if data[0] == 0x61 {
		if data[1] == 0x82 {
			pos = 4
		} else if data[1] == 0x81 {
			pos = 3
		} else {
			pos = 2
		}
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

	// Skip [0] tkt-vno
	if pos < len(data) && data[pos] == 0xa0 {
		fieldLen := int(data[pos+1])
		if data[pos+1] == 0x82 {
			fieldLen = (int(data[pos+2]) << 8) | int(data[pos+3])
			pos += 4 + fieldLen
		} else if data[pos+1] == 0x81 {
			fieldLen = int(data[pos+2])
			pos += 3 + fieldLen
		} else if data[pos+1] < 0x80 {
			pos += 2 + fieldLen
		}
	}

	// Parse [1] realm - GeneralString
	if pos < len(data) && data[pos] == 0xa1 {
		contentLen := 0
		contentPos := pos + 2
		if data[pos+1] == 0x82 {
			contentLen = (int(data[pos+2]) << 8) | int(data[pos+3])
			contentPos = pos + 4
		} else if data[pos+1] == 0x81 {
			contentLen = int(data[pos+2])
			contentPos = pos + 3
		} else if data[pos+1] < 0x80 {
			contentLen = int(data[pos+1])
		}

		// GeneralString (0x1b)
		if contentPos < len(data) && data[contentPos] == 0x1b {
			strLen := int(data[contentPos+1])
			if contentPos+2+strLen <= len(data) {
				realm = string(data[contentPos+2 : contentPos+2+strLen])
			}
		}

		pos = contentPos + contentLen
	}

	// Parse [2] sname - PrincipalName
	if pos < len(data) && data[pos] == 0xa2 {
		contentLen := 0
		contentPos := pos + 2
		if data[pos+1] == 0x82 {
			contentLen = (int(data[pos+2]) << 8) | int(data[pos+3])
			contentPos = pos + 4
		} else if data[pos+1] == 0x81 {
			contentLen = int(data[pos+2])
			contentPos = pos + 3
		} else if data[pos+1] < 0x80 {
			contentLen = int(data[pos+1])
		}

		snameData := data[contentPos : contentPos+contentLen]
		sname = parsePrincipalName(snameData)
	}

	return realm, sname
}

// parsePrincipalName parses a PrincipalName from ASN.1 bytes.
func parsePrincipalName(data []byte) asn1krb5.PrincipalName {
	pname := asn1krb5.PrincipalName{}

	if len(data) < 4 {
		return pname
	}

	// Skip SEQUENCE header
	pos := 0
	if data[pos] == 0x30 {
		if data[pos+1] == 0x82 {
			pos += 4
		} else if data[pos+1] == 0x81 {
			pos += 3
		} else {
			pos += 2
		}
	}

	// Parse [0] name-type INTEGER
	if pos < len(data) && data[pos] == 0xa0 {
		fieldLen := int(data[pos+1])
		contentPos := pos + 2
		if data[pos+1] < 0x80 && contentPos+fieldLen <= len(data) {
			// INTEGER
			if data[contentPos] == 0x02 {
				intLen := int(data[contentPos+1])
				if intLen == 1 {
					pname.NameType = int32(data[contentPos+2])
				} else if intLen == 2 {
					pname.NameType = int32(data[contentPos+2])<<8 | int32(data[contentPos+3])
				}
			}
		}
		pos += 2 + fieldLen
	}

	// Parse [1] name-string SEQUENCE OF GeneralString
	if pos < len(data) && data[pos] == 0xa1 {
		contentLen := 0
		contentPos := pos + 2
		if data[pos+1] == 0x82 {
			contentLen = (int(data[pos+2]) << 8) | int(data[pos+3])
			contentPos = pos + 4
		} else if data[pos+1] == 0x81 {
			contentLen = int(data[pos+2])
			contentPos = pos + 3
		} else if data[pos+1] < 0x80 {
			contentLen = int(data[pos+1])
		}

		// Parse SEQUENCE OF GeneralString
		seqData := data[contentPos : contentPos+contentLen]
		spos := 0
		if spos < len(seqData) && seqData[spos] == 0x30 {
			if seqData[spos+1] == 0x82 {
				spos += 4
			} else if seqData[spos+1] == 0x81 {
				spos += 3
			} else {
				spos += 2
			}
		}

		// Extract GeneralStrings
		for spos < len(seqData) {
			if seqData[spos] != 0x1b {
				break
			}
			strLen := int(seqData[spos+1])
			if spos+2+strLen > len(seqData) {
				break
			}
			pname.NameString = append(pname.NameString, string(seqData[spos+2:spos+2+strLen]))
			spos += 2 + strLen
		}
	}

	return pname
}

func extractSessionKey(encKDCRepPart []byte) (asn1krb5.EncryptionKey, error) {
	// EncKDCRepPart is APPLICATION 25 or 26, containing SEQUENCE
	// First field [0] is the key: EncryptionKey ::= SEQUENCE { [0] keytype, [1] keyvalue }

	// Skip APPLICATION tag
	pos := 0
	if encKDCRepPart[0] == 0x79 || encKDCRepPart[0] == 0x7a { // APPLICATION 25 or 26
		if encKDCRepPart[1] == 0x82 {
			pos = 4
		} else if encKDCRepPart[1] == 0x81 {
			pos = 3
		} else {
			pos = 2
		}
	}

	// Skip SEQUENCE
	if encKDCRepPart[pos] == 0x30 {
		if encKDCRepPart[pos+1] == 0x82 {
			pos += 4
		} else if encKDCRepPart[pos+1] == 0x81 {
			pos += 3
		} else {
			pos += 2
		}
	}

	// Now at fields, find [0] key
	if encKDCRepPart[pos] != 0xa0 {
		return asn1krb5.EncryptionKey{}, fmt.Errorf("expected [0] key, got 0x%02x", encKDCRepPart[pos])
	}

	// Skip [0] wrapper to get EncryptionKey SEQUENCE
	keyStart := pos + 2
	if encKDCRepPart[pos+1] == 0x81 {
		keyStart = pos + 3
	}

	// Parse EncryptionKey SEQUENCE { [0] keytype, [1] keyvalue }
	if encKDCRepPart[keyStart] != 0x30 {
		return asn1krb5.EncryptionKey{}, fmt.Errorf("expected SEQUENCE for key, got 0x%02x", encKDCRepPart[keyStart])
	}

	keySeqStart := keyStart + 2
	if encKDCRepPart[keyStart+1] >= 0x80 {
		keySeqStart = keyStart + 3
	}

	// [0] keytype
	var keyType int32
	if encKDCRepPart[keySeqStart] == 0xa0 {
		keyType = int32(encKDCRepPart[keySeqStart+4])
	}

	// [1] keyvalue - find it
	var keyValue []byte
	for i := keySeqStart; i < len(encKDCRepPart)-5; i++ {
		if encKDCRepPart[i] == 0xa1 {
			// Skip [1] wrapper to OCTET STRING
			octetStart := i + 2
			if encKDCRepPart[i+1] >= 0x80 {
				octetStart = i + 3
			}
			if encKDCRepPart[octetStart] == 0x04 {
				keyLen := int(encKDCRepPart[octetStart+1])
				keyValue = encKDCRepPart[octetStart+2 : octetStart+2+keyLen]
				break
			}
		}
	}

	return asn1krb5.EncryptionKey{
		KeyType:  keyType,
		KeyValue: keyValue,
	}, nil
}

// Helper functions
func wrapSequence(data []byte) []byte {
	result := []byte{0x30}
	result = append(result, buildLength(len(data))...)
	return append(result, data...)
}

func wrapContextTag(tag int, data []byte) []byte {
	result := []byte{byte(0xa0 + tag)}
	result = append(result, buildLength(len(data))...)
	return append(result, data...)
}

func wrapApplication(tag int, data []byte) []byte {
	result := []byte{byte(0x60 + tag)}
	result = append(result, buildLength(len(data))...)
	return append(result, data...)
}

func buildLength(l int) []byte {
	if l < 128 {
		return []byte{byte(l)}
	} else if l < 256 {
		return []byte{0x81, byte(l)}
	}
	return []byte{0x82, byte(l >> 8), byte(l)}
}
