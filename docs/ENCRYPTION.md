# Kerberos Encryption Deep Dive

> Understanding encryption types is crucial for attacking (and defending) Kerberos. The encryption type determines what keys you need and how to crack tickets.

## Table of Contents

1. [Encryption Types Overview](#encryption-types-overview)
2. [Key Derivation](#key-derivation)
3. [RC4-HMAC (etype 23)](#rc4-hmac-etype-23)
4. [AES-256 (etype 18)](#aes-256-etype-18)
5. [AES-128 (etype 17)](#aes-128-etype-17)
6. [DES (etypes 1, 3)](#des-etypes-1-3)
7. [Attack Implications](#attack-implications)

---

## Encryption Types Overview

| EType | Name | Key Size | Security | Hashcat Mode |
|-------|------|----------|----------|--------------|
| 23 | RC4-HMAC | 16 bytes | ⚠️ Weak | 13100 |
| 18 | AES256-CTS-HMAC-SHA1-96 | 32 bytes | ✅ Strong | 19700 |
| 17 | AES128-CTS-HMAC-SHA1-96 | 16 bytes | ✅ Strong | 19600 |
| 3 | DES-CBC-MD5 | 8 bytes | ❌ Broken | N/A |
| 1 | DES-CBC-CRC | 8 bytes | ❌ Broken | N/A |

### Why This Matters for Attackers

- **RC4-HMAC**: The key IS the NTLM hash - ~1000x faster to crack than AES
- **AES**: Requires PBKDF2 key derivation with 4096 iterations - slow to crack
- **DES**: Rare in modern environments, but trivially broken

---

## Key Derivation

### Password to Key

Each encryption type has a different way of deriving the key from a password:

```
┌──────────────────────────────────────────────────────────────┐
│                    RC4-HMAC (etype 23)                       │
├──────────────────────────────────────────────────────────────┤
│  key = MD4(UTF16-LE(password))                               │
│                                                              │
│  This is just the NTLM hash!                                 │
│  Example: "password" → 8846f7eaee8fb117ad06bdd830b7586c      │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│                    AES (etype 17, 18)                        │
├──────────────────────────────────────────────────────────────┤
│  key = PBKDF2-HMAC-SHA1(                                     │
│            password,                                          │
│            salt = REALM + principal,                          │
│            iterations = 4096,                                 │
│            keylen = 16 or 32                                  │
│        )                                                      │
│                                                              │
│  The salt makes every user's key unique!                     │
│  Example salt: "CORP.LOCALjsmith"                            │
└──────────────────────────────────────────────────────────────┘
```

### Key Usage Numbers

Kerberos uses different derived keys for different purposes:

| Key Usage | Purpose |
|-----------|---------|
| 1 | AS-REQ PA-ENC-TIMESTAMP |
| 2 | Ticket encryption (AS-REP, TGS-REP) |
| 3 | AS-REP encrypted part |
| 7 | Authenticator encrypted part |
| 8 | TGS-REQ authenticator |
| 11 | AP-REQ authenticator checksum |
| 14 | KRB-CRED encrypted part |

---

## RC4-HMAC (etype 23)

### The NTLM Connection

RC4-HMAC is special because **the key is literally the NTLM hash**:

```
NTLM Hash = MD4(UTF16-LE(password))
RC4 Key   = NTLM Hash
```

This means:

- ✅ If you have the NTLM hash, you can request TGTs (Overpass-the-Hash)
- ✅ Cracking is fast because no key derivation needed
- ⚠️ All services for a user use the same key (no salt)

### Encryption Process

```
┌─────────────────────────────────────────────────────────────┐
│  1. K1 = HMAC-MD5(key, usage_number in little-endian)       │
│  2. confounder = 8 random bytes                              │
│  3. plaintext_with_confounder = confounder || plaintext     │
│  4. checksum = HMAC-MD5(K1, plaintext_with_confounder)      │
│  5. K2 = HMAC-MD5(K1, checksum)                             │
│  6. ciphertext = RC4(K2, plaintext_with_confounder)         │
│  7. output = checksum || ciphertext                          │
└─────────────────────────────────────────────────────────────┘
```

---

## AES-256 (etype 18)

### Key Derivation

AES keys require PBKDF2 with a salt:

```
salt = uppercase(REALM) + case-sensitive(principal)
key = PBKDF2-HMAC-SHA1(password, salt, 4096, 32)
```

Example:

```
Password: "Password123"
Realm: "CORP.LOCAL"
Principal: "jsmith"
Salt: "CORP.LOCALjsmith"
Key: 5b3e1... (32 bytes)
```

### Encryption Process (Simplified)

```
┌─────────────────────────────────────────────────────────────┐
│  1. Derive sub-keys using n-fold and DK                     │
│  2. confounder = 16 random bytes                            │
│  3. CBC encrypt with AES-256 in CTS mode                    │
│  4. HMAC-SHA1-96 for integrity (12 bytes)                   │
│  5. output = ciphertext || hmac                              │
└─────────────────────────────────────────────────────────────┘
```

### n-fold Algorithm

AES uses the n-fold algorithm (RFC 3961) to stretch constants:

```
The n-fold of a string S is computed by:
1. Replicate S multiple times to reach the target length
2. Rotate each copy by 13*i bits
3. Add all copies using ones-complement addition
```

This is used to derive encryption and integrity keys from the base key.

---

## AES-128 (etype 17)

Same as AES-256 but:

- Key size: 16 bytes instead of 32
- Block cipher: AES-128 instead of AES-256
- PBKDF2 output length: 16 bytes

Less common in modern environments as AES-256 is the default.

---

## DES (etypes 1, 3)

### ⚠️ DO NOT USE - BROKEN

DES encryption types are:

- **etype 1**: DES-CBC-CRC
- **etype 3**: DES-CBC-MD5

These are:

- Disabled by default in modern Windows
- Trivially crackable (2^56 key space)
- Only 7 bytes of password entropy

If you see DES in a Kerberos environment, it's a **critical misconfiguration**.

---

## Attack Implications

### Kerberoasting Speed Comparison

| EType | Crack Rate (RTX 4090) | Time for 8-char password |
|-------|----------------------|--------------------------|
| RC4 (23) | ~2.5 billion/sec | ~2 hours |
| AES-128 (17) | ~100,000/sec | ~100+ years |
| AES-256 (18) | ~50,000/sec | ~200+ years |

### Pass-the-Hash vs Pass-the-Key

| Attack | EType | Key Material |
|--------|-------|--------------|
| Pass-the-Hash | RC4 | NTLM hash |
| Pass-the-Key | AES | AES key (derived) |
| Overpass-the-Hash | Any | Request TGT with key |

### Downgrade Attacks

Attackers prefer RC4 because it's faster to crack. Techniques:

- Explicitly request etype 23 in AS-REQ
- Disable AES for specific accounts
- Wait for legacy service that only supports RC4

### Defense Tips

```powershell
# Disable RC4 for the entire domain (careful!)
Set-ADAccountControl -Identity krbtgt -DoesNotRequireDES $true

# Require AES for sensitive accounts
Set-ADUser -Identity admin -Replace @{'msDS-SupportedEncryptionTypes'=24}
# 24 = AES128 (8) + AES256 (16)
```

---

## Related Documents

- [KERBEROS_101.md](KERBEROS_101.md) - Kerberos fundamentals
- [TICKETS.md](TICKETS.md) - Ticket structure and formats
- [ATTACKS.md](ATTACKS.md) - Attack techniques explained

---

## References

- [RFC 3961](https://datatracker.ietf.org/doc/html/rfc3961) - Encryption and Checksum Specifications
- [RFC 3962](https://datatracker.ietf.org/doc/html/rfc3962) - AES Encryption for Kerberos 5
- [RFC 4757](https://datatracker.ietf.org/doc/html/rfc4757) - RC4-HMAC Kerberos Encryption Types
