package client

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/goobeus/goobeus/internal/network"
	"github.com/goobeus/goobeus/pkg/asn1krb5"
	"github.com/goobeus/goobeus/pkg/crypto"
	"github.com/goobeus/goobeus/pkg/ticket"
)

// EDUCATIONAL: Kerberos Client Operations
//
// This package implements the Kerberos protocol exchanges:
//
// AS Exchange (Authentication Service):
//   Client → KDC: AS-REQ (who am I, who do I want to talk to)
//   KDC → Client: AS-REP (here's your TGT) or KRB-ERROR
//
// TGS Exchange (Ticket Granting Service):
//   Client → KDC: TGS-REQ (here's my TGT, give me ticket for service X)
//   KDC → Client: TGS-REP (here's your service ticket) or KRB-ERROR
//
// The key insight: You never send your password directly.
// Instead, you prove you have it by encrypting a timestamp (pre-auth).

// Client is a Kerberos client.
type Client struct {
	Domain  string
	KDC     string // Explicit KDC address (auto-discovered if empty)
	Timeout time.Duration
	Verbose bool
}

// NewClient creates a new Kerberos client.
func NewClient(domain string) *Client {
	return &Client{
		Domain:  strings.ToUpper(domain),
		Timeout: 30 * time.Second,
	}
}

// WithKDC sets an explicit KDC address.
func (c *Client) WithKDC(kdc string) *Client {
	c.KDC = kdc
	return c
}

// WithVerbose enables verbose logging.
func (c *Client) WithVerbose(v bool) *Client {
	c.Verbose = v
	return c
}

// send sends a Kerberos message to the KDC.
func (c *Client) send(ctx context.Context, msg []byte) ([]byte, error) {
	return network.SendToKDCWithContext(ctx, c.Domain, c.KDC, msg)
}

// Credentials represents authentication credentials.
type Credentials struct {
	Username string
	Domain   string

	// One of these should be set
	Password string
	NTHash   []byte // 16 bytes - RC4 key
	AES128   []byte // 16 bytes
	AES256   []byte // 32 bytes
}

// GetKey derives the encryption key for the specified etype.
func (creds *Credentials) GetKey(etype int32) ([]byte, error) {
	switch etype {
	case crypto.EtypeRC4:
		if len(creds.NTHash) == 16 {
			return creds.NTHash, nil
		}
		if creds.Password != "" {
			return crypto.NTLMHash(creds.Password), nil
		}
	case crypto.EtypeAES128:
		if len(creds.AES128) == 16 {
			return creds.AES128, nil
		}
		if creds.Password != "" {
			salt := crypto.BuildAESSalt(creds.Domain, creds.Username)
			return crypto.AES128Key(creds.Password, salt), nil
		}
	case crypto.EtypeAES256:
		if len(creds.AES256) == 32 {
			return creds.AES256, nil
		}
		if creds.Password != "" {
			salt := crypto.BuildAESSalt(creds.Domain, creds.Username)
			return crypto.AES256Key(creds.Password, salt), nil
		}
	}
	return nil, fmt.Errorf("no key available for etype %d", etype)
}

// PreferredEtype returns the best available encryption type.
func (creds *Credentials) PreferredEtype() int32 {
	// Prefer AES256 > AES128 > RC4
	if len(creds.AES256) == 32 {
		return crypto.EtypeAES256
	}
	if len(creds.AES128) == 16 {
		return crypto.EtypeAES128
	}
	if len(creds.NTHash) == 16 {
		return crypto.EtypeRC4
	}
	// With password, default to AES256
	if creds.Password != "" {
		return crypto.EtypeAES256
	}
	return crypto.EtypeRC4
}

// SessionInfo contains session information from a ticket response.
type SessionInfo struct {
	SessionKey  asn1krb5.EncryptionKey
	Ticket      *asn1krb5.Ticket
	Kirbi       *ticket.Kirbi
	Flags       uint32
	AuthTime    time.Time
	StartTime   time.Time
	EndTime     time.Time
	RenewTill   time.Time
	ServerRealm string
	ServerName  asn1krb5.PrincipalName
}
