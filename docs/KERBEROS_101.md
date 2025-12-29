# Kerberos 101: A Complete Guide

> "The Kerberos protocol is named after Cerberus, the three-headed dog guarding the gates of Hades. The three heads represent the client, server, and Key Distribution Center (KDC)."

## Table of Contents

1. [What is Kerberos?](#what-is-kerberos)
2. [The Three Actors](#the-three-actors)
3. [The Authentication Flow](#the-authentication-flow)
4. [Ticket Types](#ticket-types)
5. [Why Attackers Love Kerberos](#why-attackers-love-kerberos)
6. [RFC References](#rfc-references)

---

## What is Kerberos?

Kerberos is a **network authentication protocol** designed to provide strong authentication for client/server applications using secret-key cryptography. It was developed at MIT in the 1980s and is now the primary authentication mechanism in Windows Active Directory environments.

### Key Properties

| Property | Description |
|----------|-------------|
| **Mutual Authentication** | Both client and server verify each other's identity |
| **Single Sign-On (SSO)** | Authenticate once, access many services |
| **Ticket-Based** | Credentials are represented as encrypted tickets |
| **Time-Sensitive** | Tickets have limited validity (prevents replay attacks) |

### Why "Kerberos"?

The protocol involves three parties:

1. **Client** - The user/machine requesting access
2. **Server** - The service being accessed  
3. **KDC** - The trusted third party (Key Distribution Center)

Just like Cerberus guards the underworld with three heads, Kerberos guards your network with three trusted components.

---

## The Three Actors

### 1. Client (Principal)

The entity requesting authentication. In Active Directory:

- **User principals**: `user@REALM` (e.g., `jsmith@CORP.LOCAL`)
- **Machine principals**: `COMPUTER$@REALM` (e.g., `WORKSTATION1$@CORP.LOCAL`)
- **Service principals**: `service/host@REALM` (e.g., `HTTP/webserver.corp.local@CORP.LOCAL`)

### 2. Key Distribution Center (KDC)

The KDC is the heart of Kerberos, running on Domain Controllers. It consists of two services:

| Service | Port | Function |
|---------|------|----------|
| **AS** (Authentication Service) | 88 | Issues TGTs after verifying credentials |
| **TGS** (Ticket Granting Service) | 88 | Issues service tickets in exchange for TGTs |

### 3. Service (Application Server)

Any service the client wants to access:

- File shares (CIFS/SMB)
- Web servers (HTTP)
- Databases (MSSQL, Oracle)
- Remote management (WinRM, RDP)

---

## The Authentication Flow

### Step 1: AS-REQ / AS-REP (Getting a TGT)

```
┌────────┐                           ┌────────┐
│ Client │ ─── AS-REQ ────────────▶  │  KDC   │
│        │     (username, timestamp)  │  (AS)  │
│        │ ◀── AS-REP ────────────── │        │
│        │     (TGT, session key)     │        │
└────────┘                           └────────┘
```

**What happens:**

1. Client sends username and encrypted timestamp (pre-authentication)
2. KDC verifies the password by decrypting the timestamp
3. KDC returns a **TGT** (Ticket Granting Ticket) encrypted with the `krbtgt` key
4. Client receives a **session key** for future TGS requests

**Security Note:** The TGT is encrypted with the `krbtgt` account's hash. If an attacker obtains this hash, they can forge **Golden Tickets**.

### Step 2: TGS-REQ / TGS-REP (Getting a Service Ticket)

```
┌────────┐                           ┌────────┐
│ Client │ ─── TGS-REQ ───────────▶  │  KDC   │
│        │     (TGT, target SPN)      │ (TGS)  │
│        │ ◀── TGS-REP ───────────── │        │
│        │     (Service Ticket)       │        │
└────────┘                           └────────┘
```

**What happens:**

1. Client presents the TGT and requests access to a specific service (SPN)
2. KDC validates the TGT, generates a Service Ticket
3. Service Ticket is encrypted with the **target service's key**

**Security Note:** The service ticket is encrypted with the service account's hash. This is why **Kerberoasting** works - you can request service tickets and crack them offline.

### Step 3: AP-REQ / AP-REP (Accessing the Service)

```
┌────────┐                           ┌─────────┐
│ Client │ ─── AP-REQ ───────────▶  │ Service │
│        │     (Service Ticket)       │         │
│        │ ◀── AP-REP ───────────── │         │
│        │     (mutual auth proof)    │         │
└────────┘                           └─────────┘
```

**What happens:**

1. Client sends service ticket and authenticator to the service
2. Service decrypts the ticket with its own key
3. Service validates the authenticator and grants access

---

## Ticket Types

### TGT (Ticket Granting Ticket)

- **Purpose:** Prove you authenticated to the KDC
- **Encrypted with:** `krbtgt` account hash
- **Validity:** 10 hours (default), renewable for 7 days
- **Attack relevance:** Golden Ticket (forge TGT with krbtgt hash)

### Service Ticket (ST)

- **Purpose:** Prove you're authorized to access a service
- **Encrypted with:** Service account hash
- **Validity:** 10 hours (default)
- **Attack relevance:** Kerberoasting (crack service hash), Silver Ticket (forge ST)

### Delegation Tickets

| Type | Description | Attack |
|------|-------------|--------|
| **Forwardable TGT** | TGT that can be sent to another service | Unconstrained Delegation abuse |
| **S4U2Self** | Service requests ticket on behalf of user | Constrained Delegation abuse |
| **S4U2Proxy** | Service uses user's ticket to access another service | Constrained Delegation abuse |

---

## Why Attackers Love Kerberos

### 1. Offline Cracking

Service tickets are encrypted with password-derived keys. Request a ticket, crack it offline - no lockouts!

### 2. Pass-the-Ticket

Tickets are bearer tokens. Steal one, use it from anywhere.

### 3. Ticket Forgery

With the right keys, you can forge tickets that claim any identity.

### 4. Weak Default Settings

- No pre-auth = AS-REP Roasting
- Weak service passwords = Kerberoasting
- Unconstrained delegation = Credential theft

### 5. Trust-Based Architecture

Kerberos trusts are transitive. Compromise one domain, pivot to others.

---

## RFC References

| RFC | Title | Relevance |
|-----|-------|-----------|
| [RFC 4120](https://datatracker.ietf.org/doc/html/rfc4120) | The Kerberos Network Authentication Service (V5) | Core protocol |
| [RFC 4121](https://datatracker.ietf.org/doc/html/rfc4121) | The Kerberos V5 GSS-API Mechanism | GSS-API integration |
| [RFC 3961](https://datatracker.ietf.org/doc/html/rfc3961) | Encryption and Checksum Specifications | Cryptography |
| [RFC 3962](https://datatracker.ietf.org/doc/html/rfc3962) | AES Encryption for Kerberos 5 | AES support |
| [RFC 4757](https://datatracker.ietf.org/doc/html/rfc4757) | RC4-HMAC Kerberos Encryption Type | RC4/NTLM |
| [MS-KILE](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-kile) | Microsoft Kerberos Extensions | PAC, S4U |
| [MS-SFU](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu) | Service for User Extensions | S4U2Self/Proxy |

---

## Next Steps

- [ENCRYPTION.md](ENCRYPTION.md) - Deep dive into Kerberos encryption
- [TICKETS.md](TICKETS.md) - Ticket structure and formats
- [ATTACKS.md](ATTACKS.md) - Attack techniques explained
- [DELEGATION.md](DELEGATION.md) - Delegation abuse techniques
