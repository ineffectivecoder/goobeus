# Kerberos Ticket Structure and Formats

> Tickets are the currency of Kerberos. Understanding their structure is essential for manipulation, forgery, and detection.

## Table of Contents

1. [Ticket Structure](#ticket-structure)
2. [PAC (Privilege Attribute Certificate)](#pac-privilege-attribute-certificate)
3. [File Formats](#file-formats)
4. [Ticket Flags](#ticket-flags)
5. [Manipulation with Goobeus](#manipulation-with-goobeus)

---

## Ticket Structure

### KRB-CRED (The .kirbi container)

A `.kirbi` file contains a `KRB-CRED` structure:

```
KRB-CRED ::= [APPLICATION 22] SEQUENCE {
    pvno            [0] INTEGER (5),           -- Protocol version
    msg-type        [1] INTEGER (22),          -- Message type
    tickets         [2] SEQUENCE OF Ticket,    -- The actual tickets
    enc-part        [3] EncryptedData          -- Encrypted credential info
}
```

### Ticket Structure

```
Ticket ::= [APPLICATION 1] SEQUENCE {
    tkt-vno     [0] INTEGER (5),            -- Ticket version
    realm       [1] Realm,                   -- Service realm
    sname       [2] PrincipalName,          -- Service name (e.g., krbtgt/REALM)
    enc-part    [3] EncryptedData {         -- Encrypted with service key
        EncTicketPart ::= [APPLICATION 3] SEQUENCE {
            flags           [0] TicketFlags,
            key             [1] EncryptionKey,    -- Session key
            crealm          [2] Realm,            -- Client realm
            cname           [3] PrincipalName,    -- Client name
            transited       [4] TransitedEncoding,
            authtime        [5] KerberosTime,
            starttime       [6] KerberosTime OPTIONAL,
            endtime         [7] KerberosTime,
            renew-till      [8] KerberosTime OPTIONAL,
            caddr           [9] HostAddresses OPTIONAL,
            authorization-data [10] AuthorizationData  -- Contains PAC!
        }
    }
}
```

### Visual Breakdown

```
┌─────────────────────────────────────────────────────────────────┐
│                        .kirbi file                              │
├─────────────────────────────────────────────────────────────────┤
│  KRB-CRED                                                       │
│  ├── pvno: 5                                                    │
│  ├── msg-type: 22                                               │
│  ├── tickets[]                                                  │
│  │   └── Ticket                                                 │
│  │       ├── tkt-vno: 5                                         │
│  │       ├── realm: "CORP.LOCAL"                                │
│  │       ├── sname: krbtgt/CORP.LOCAL                           │
│  │       └── enc-part [encrypted with krbtgt key]              │
│  │           └── EncTicketPart                                  │
│  │               ├── flags: FORWARDABLE, RENEWABLE, ...        │
│  │               ├── key: [session key]                         │
│  │               ├── cname: jsmith                              │
│  │               ├── crealm: CORP.LOCAL                         │
│  │               ├── authtime: 2024-01-15 10:00:00             │
│  │               ├── endtime: 2024-01-15 20:00:00              │
│  │               ├── renew-till: 2024-01-22 10:00:00           │
│  │               └── authorization-data                         │
│  │                   └── PAC [Privilege Attribute Certificate] │
│  └── enc-part [credential info, often NULL encrypted]          │
│      └── EncKRBCredPart                                         │
│          └── ticket-info[]                                      │
│              ├── pname, prealm (client identity)               │
│              ├── flags, times (convenience copy)               │
│              └── session key                                    │
└─────────────────────────────────────────────────────────────────┘
```

---

## PAC (Privilege Attribute Certificate)

The PAC is Microsoft's extension to Kerberos, embedded in the ticket's `authorization-data`. It contains:

### PAC Structure

```
PACTYPE ::= SEQUENCE {
    cBuffers    ULONG,          -- Number of buffers
    Version     ULONG,          -- Always 0
    Buffers[]   PAC_INFO_BUFFER -- Array of buffer descriptors
}

PAC_INFO_BUFFER ::= SEQUENCE {
    ulType      ULONG,          -- Buffer type
    cbBufferSize ULONG,         -- Size
    Offset      ULONG64         -- Offset in PAC
}
```

### PAC Buffer Types

| Type | Name | Contents |
|------|------|----------|
| 0x01 | LOGON_INFO | User SIDs, groups, user flags |
| 0x02 | CREDENTIALS_INFO | Supplemental credentials |
| 0x06 | SERVER_CHECKSUM | Signed by service key |
| 0x07 | PRIVSVR_CHECKSUM | Signed by krbtgt key |
| 0x0A | CLIENT_INFO | Client name and auth time |
| 0x0C | UPN_DNS_INFO | UPN and DNS domain name |
| 0x0D | CLIENT_CLAIMS | AD claims |
| 0x0E | DEVICE_INFO | Device SIDs |
| 0x0F | DEVICE_CLAIMS | Device claims |
| 0x10 | TICKET_CHECKSUM | Signed by krbtgt (newer) |

### PAC Signatures

The PAC has two critical signatures:

1. **Server Checksum (0x06)** - Signed with the service key
2. **KDC Checksum (0x07)** - Signed with the krbtgt key

**Attack Note:** If you can forge both signatures, you control the PAC:

- **Silver Ticket:** Service key only → fake SERVER_CHECKSUM
- **Golden Ticket:** krbtgt key → fake both checksums

---

## File Formats

### .kirbi (Binary DER)

| Property | Value |
|----------|-------|
| Format | Binary DER-encoded ASN.1 |
| Extension | `.kirbi` |
| Used by | Windows, Mimikatz, Rubeus |
| Structure | KRB-CRED |

```bash
# View with goobeus
goobeus.exe describe ticket.kirbi
```

### .ccache (MIT Credential Cache)

| Property | Value |
|----------|-------|
| Format | Binary (MIT format) |
| Extension | `.ccache` |
| Used by | Linux, Impacket, krb5 |
| Structure | File format version + credentials |

```bash
# Convert with goobeus
goobeus.exe describe ticket.kirbi -o ticket.ccache

# Use on Linux
export KRB5CCNAME=ticket.ccache
```

### Base64

Both formats can be base64 encoded for transport:

```bash
# Base64 kirbi (Rubeus style)
goobeus.exe dump --base64

# Decode
echo "doIF..." | base64 -d > ticket.kirbi
```

### Conversion Table

| From | To | Command |
|------|-----|---------|
| .kirbi | .ccache | `goobeus describe ticket.kirbi -o ticket.ccache` |
| .ccache | .kirbi | `goobeus describe ticket.ccache -o ticket.kirbi` |
| Base64 | .kirbi | `echo "..." | base64 -d > ticket.kirbi` |
| .kirbi | Base64 | `base64 ticket.kirbi` |

---

## Ticket Flags

Ticket flags control what operations are permitted:

| Flag | Bit | Description | Attack Relevance |
|------|-----|-------------|------------------|
| FORWARDABLE | 1 | Can be forwarded to another host | Delegation abuse |
| FORWARDED | 2 | Has been forwarded | tgtdeleg indicator |
| PROXIABLE | 3 | Can create proxy tickets | Delegation |
| PROXY | 4 | Is a proxy ticket | - |
| ALLOW-POSTDATE | 5 | Can be postdated | - |
| POSTDATED | 6 | Has been postdated | - |
| INVALID | 7 | Ticket is not yet valid | - |
| RENEWABLE | 8 | Can be renewed | Persistence |
| INITIAL | 9 | Issued via AS exchange | Fresh TGT |
| PRE-AUTHENT | 10 | Pre-authentication was used | Security |
| HW-AUTHENT | 11 | Hardware auth used | - |
| TRANSITED-POLICY-CHECKED | 12 | Transit checked | - |
| OK-AS-DELEGATE | 13 | Service trusted for delegation | Target indicator |

### Flag Combinations for Attacks

```
Golden Ticket Flags:    0x40E10000 (FORWARDABLE, PROXIABLE, RENEWABLE, PRE-AUTHENT)
Silver Ticket Flags:    0x40A50000 (FORWARDABLE, PROXIABLE, RENEWABLE)
tgtdeleg Ticket:        FORWARDABLE + FORWARDED (key indicator!)
```

---

## Manipulation with Goobeus

### View Ticket Details

```bash
# Basic describe
goobeus.exe describe ticket.kirbi

# Decrypt with krbtgt key
goobeus.exe describe ticket.kirbi -k <krbtgt_aes256_hex>
```

### Convert Formats

```bash
# Kirbi to ccache
goobeus.exe describe ticket.kirbi -o ticket.ccache

# Use output
export KRB5CCNAME=ticket.ccache
```

### Forge Tickets

```bash
# Golden Ticket
goobeus.exe golden -d CORP.LOCAL -sid S-1-5-21-... -krbtgt <hash> -user fakeadmin

# Silver Ticket
goobeus.exe silver -d CORP.LOCAL -sid S-1-5-21-... -rc4 <hash> -service cifs/server -user admin
```

---

## Related Documents

- [KERBEROS_101.md](KERBEROS_101.md) - Kerberos fundamentals
- [ENCRYPTION.md](ENCRYPTION.md) - Encryption types
- [ATTACKS.md](ATTACKS.md) - Attack techniques
