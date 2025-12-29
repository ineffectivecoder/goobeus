package adws

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Azure/go-ntlmssp"
)

// EDUCATIONAL: ADWS (Active Directory Web Services)
//
// ADWS is a SOAP-based protocol on port 9389 that provides AD access.
// It's the backend for PowerShell's Get-ADUser, Get-ADComputer, etc.
//
// Why it's sneakier than LDAP:
// 1. Different port (9389 vs 389) - fewer EDR rules
// 2. SOAP/XML protocol - looks like normal web traffic
// 3. Same functionality - can query anything LDAP can
//
// ADWS Endpoints:
// - /ActiveDirectoryWebServices/Windows/Enumerate - WS-Enumeration
// - /ActiveDirectoryWebServices/Windows/Resource  - WS-Transfer

// Default ports
const (
	DefaultADWSPort    = 9389
	DefaultADWSPortTLS = 9389 // Same port, negotiated
)

// Client is an ADWS client for Active Directory queries.
type Client struct {
	Host       string
	Port       int
	Domain     string
	Username   string
	Password   string
	NTHash     []byte // For pass-the-hash
	UseTLS     bool
	Timeout    time.Duration
	httpClient *http.Client
}

// Option configures the Client.
type Option func(*Client)

// WithCredentials sets username/password authentication.
func WithCredentials(domain, username, password string) Option {
	return func(c *Client) {
		c.Domain = domain
		c.Username = username
		c.Password = password
	}
}

// WithNTHash sets NTLM hash for pass-the-hash authentication.
func WithNTHash(domain, username string, ntHash []byte) Option {
	return func(c *Client) {
		c.Domain = domain
		c.Username = username
		c.NTHash = ntHash
	}
}

// WithTLS enables TLS for the connection.
func WithTLS(enabled bool) Option {
	return func(c *Client) {
		c.UseTLS = enabled
	}
}

// WithTimeout sets the request timeout.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) {
		c.Timeout = d
	}
}

// NewClient creates a new ADWS client.
func NewClient(host string, opts ...Option) *Client {
	c := &Client{
		Host:    host,
		Port:    DefaultADWSPort,
		Timeout: 30 * time.Second,
	}

	for _, opt := range opts {
		opt(c)
	}

	// Create HTTP transport with TLS
	// ADWS on Windows Server typically requires TLS 1.2+
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // For lab environments
			MinVersion:         tls.VersionTLS12,
			MaxVersion:         tls.VersionTLS13,
		},
	}

	// Authentication approach:
	// 1. If explicit creds provided: use NTLM negotiator
	// 2. If no creds on Windows: try SSPI for Kerberos/NTLM
	// 3. Fallback: NTLM negotiator (works for some scenarios)
	if c.Username != "" && c.Password != "" {
		// Explicit credentials - use NTLM
		c.httpClient = &http.Client{
			Timeout: c.Timeout,
			Transport: ntlmssp.Negotiator{
				RoundTripper: transport,
			},
		}
	} else {
		// No explicit creds - try SSPI first (Windows only)
		sspiClient, err := createSSPIClient(transport, c.Timeout)
		if err == nil && sspiClient != nil {
			c.httpClient = sspiClient
		} else {
			// Fallback to NTLM negotiator
			c.httpClient = &http.Client{
				Timeout: c.Timeout,
				Transport: ntlmssp.Negotiator{
					RoundTripper: transport,
				},
			}
		}
	}

	return c
}

// baseURL returns the ADWS base URL.
func (c *Client) baseURL() string {
	scheme := "http"
	if c.UseTLS {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s:%d", scheme, c.Host, c.Port)
}

// enumerateURL returns the WS-Enumeration endpoint URL.
func (c *Client) enumerateURL() string {
	return c.baseURL() + "/ActiveDirectoryWebServices/Windows/Enumerate"
}

// resourceURL returns the WS-Transfer endpoint URL.
func (c *Client) resourceURL() string {
	return c.baseURL() + "/ActiveDirectoryWebServices/Windows/Resource"
}

// sendSOAP sends a SOAP request and returns the response.
func (c *Client) sendSOAP(ctx context.Context, url, action, body string) ([]byte, error) {
	// Build full SOAP envelope
	envelope := c.buildEnvelope(action, body)

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader([]byte(envelope)))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/soap+xml; charset=utf-8")
	if c.Username != "" {
		req.SetBasicAuth(c.Domain+"\\"+c.Username, c.Password)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("SOAP request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("SOAP request failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

// buildEnvelope constructs a SOAP envelope with WS-Addressing headers.
func (c *Client) buildEnvelope(action, body string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:a="http://www.w3.org/2005/08/addressing"
            xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration"
            xmlns:ad="http://schemas.microsoft.com/2008/1/ActiveDirectory">
  <s:Header>
    <a:Action s:mustUnderstand="1">%s</a:Action>
    <a:To s:mustUnderstand="1">%s</a:To>
  </s:Header>
  <s:Body>
    %s
  </s:Body>
</s:Envelope>`, action, c.enumerateURL(), body)
}

// ADObject represents a queried AD object.
type ADObject struct {
	DN                 string
	ObjectClass        []string
	SAMAccountName     string
	UserPrincipalName  string
	SPNs               []string
	Description        string
	MemberOf           []string
	UserAccountControl uint32
	// Additional attributes can be extracted from RawAttributes
	RawAttributes map[string][]string
}

// parseEnumerateResponse parses WS-Enumeration response.
func parseEnumerateResponse(data []byte) ([]ADObject, error) {
	// Simple XML parsing for enumeration results
	// Full implementation would use proper WS-Enumeration parsing

	var objects []ADObject

	// Look for Items elements
	decoder := xml.NewDecoder(bytes.NewReader(data))
	var currentObject *ADObject
	var currentElement string

	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		switch t := token.(type) {
		case xml.StartElement:
			currentElement = t.Name.Local
			if currentElement == "objectReferenceProperty" || currentElement == "Item" {
				currentObject = &ADObject{
					RawAttributes: make(map[string][]string),
				}
			}
		case xml.CharData:
			if currentObject != nil {
				value := strings.TrimSpace(string(t))
				if value != "" {
					switch currentElement {
					case "distinguishedName":
						currentObject.DN = value
					case "sAMAccountName":
						currentObject.SAMAccountName = value
					case "userPrincipalName":
						currentObject.UserPrincipalName = value
					case "servicePrincipalName":
						currentObject.SPNs = append(currentObject.SPNs, value)
					case "description":
						currentObject.Description = value
					case "memberOf":
						currentObject.MemberOf = append(currentObject.MemberOf, value)
					default:
						if currentObject.RawAttributes[currentElement] == nil {
							currentObject.RawAttributes[currentElement] = []string{}
						}
						currentObject.RawAttributes[currentElement] = append(
							currentObject.RawAttributes[currentElement], value)
					}
				}
			}
		case xml.EndElement:
			if t.Name.Local == "objectReferenceProperty" || t.Name.Local == "Item" {
				if currentObject != nil && currentObject.DN != "" {
					objects = append(objects, *currentObject)
				}
				currentObject = nil
			}
		}
	}

	return objects, nil
}
