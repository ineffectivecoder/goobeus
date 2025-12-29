package asn1krb5

import (
	"encoding/asn1"
	"time"
)

// Ticket is a Kerberos ticket.
//
// EDUCATIONAL: Understanding the Ticket Structure
//
// A Kerberos ticket is a credential that proves identity. It contains:
//
//  1. TktVno: Version (always 5)
//  2. Realm: The realm that issued the ticket
//  3. SName: The service principal the ticket is for
//  4. EncPart: Encrypted ticket content
//
// The EncPart is encrypted with the SERVICE's key, NOT yours!
// This is why you can't read the contents of tickets you receive.
//
// For a TGT:
//   - Realm = "CORP.LOCAL"
//   - SName = "krbtgt/CORP.LOCAL" (encrypted with krbtgt's key)
//
// For a service ticket:
//   - Realm = "CORP.LOCAL"
//   - SName = "HTTP/webserver" (encrypted with service's key)
//
// If you have the service's key, you can decrypt the EncPart to see:
//   - Session key
//   - Client name
//   - Ticket flags
//   - Validity times
//   - Authorization data (PAC!)
//
// ASN.1: Ticket ::= [APPLICATION 1] SEQUENCE { ... }
type Ticket struct {
	TktVno  int           `asn1:"explicit,tag:0"`
	Realm   string        `asn1:"generalstring,explicit,tag:1"`
	SName   PrincipalName `asn1:"explicit,tag:2"`
	EncPart EncryptedData `asn1:"explicit,tag:3"`

	// RawBytes stores the original ASN.1-encoded ticket bytes from the KDC.
	// If set, Marshal() will return these bytes instead of re-encoding.
	// This ensures byte-for-byte compatibility with the KDC's encoding.
	RawBytes []byte `asn1:"-"`
}

// marshalTicket wraps Ticket with APPLICATION 1 tag for encoding
// Must manually construct ASN.1 because Go's asn1 package doesn't properly
// support GeneralString (tag 0x1b) which Kerberos requires.
func (t Ticket) Marshal() ([]byte, error) {
	// If we have raw bytes from the KDC, use them directly
	// This ensures byte-for-byte compatibility
	if len(t.RawBytes) > 0 {
		return t.RawBytes, nil
	}

	// Helper functions for ASN.1 construction
	buildLen := func(l int) []byte {
		if l < 128 {
			return []byte{byte(l)}
		} else if l < 256 {
			return []byte{0x81, byte(l)}
		}
		return []byte{0x82, byte(l >> 8), byte(l)}
	}

	wrapExplicit := func(tag int, data []byte) []byte {
		result := []byte{byte(0xa0 + tag)}
		result = append(result, buildLen(len(data))...)
		return append(result, data...)
	}

	wrapSeq := func(data []byte) []byte {
		result := []byte{0x30}
		result = append(result, buildLen(len(data))...)
		return append(result, data...)
	}

	buildGeneralString := func(s string) []byte {
		data := []byte(s)
		result := []byte{0x1b} // GeneralString tag
		result = append(result, buildLen(len(data))...)
		return append(result, data...)
	}

	buildInt := func(n int) []byte {
		if n < 128 {
			return []byte{0x02, 0x01, byte(n)}
		} else if n < 256 {
			return []byte{0x02, 0x02, 0x00, byte(n)}
		}
		return []byte{0x02, 0x04, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	}

	// Build Ticket SEQUENCE {
	//   [0] tkt-vno INTEGER,
	//   [1] realm GeneralString,
	//   [2] sname PrincipalName,
	//   [3] enc-part EncryptedData
	// }

	// [0] tkt-vno
	tktVno := wrapExplicit(0, buildInt(t.TktVno))

	// [1] realm (GeneralString)
	realm := wrapExplicit(1, buildGeneralString(t.Realm))

	// [2] sname (PrincipalName with GeneralString components)
	// PrincipalName ::= SEQUENCE { [0] name-type INTEGER, [1] name-string SEQUENCE OF GeneralString }
	snameTypeBytes := wrapExplicit(0, buildInt(int(t.SName.NameType)))
	var nameStringContent []byte
	for _, s := range t.SName.NameString {
		nameStringContent = append(nameStringContent, buildGeneralString(s)...)
	}
	nameStringSeq := wrapSeq(nameStringContent)
	nameStringBytes := wrapExplicit(1, nameStringSeq)
	sname := wrapExplicit(2, wrapSeq(append(snameTypeBytes, nameStringBytes...)))

	// [3] enc-part (EncryptedData) - use standard marshaling for this
	encPartData, err := asn1.Marshal(t.EncPart)
	if err != nil {
		return nil, err
	}
	encPart := wrapExplicit(3, encPartData)

	// Build inner SEQUENCE
	inner := append(tktVno, realm...)
	inner = append(inner, sname...)
	inner = append(inner, encPart...)
	ticketSeq := wrapSeq(inner)

	// Wrap in APPLICATION 1
	result := []byte{0x61} // APPLICATION 1 tag
	result = append(result, buildLen(len(ticketSeq))...)
	return append(result, ticketSeq...), nil
}

// UnmarshalTicket parses a Ticket from APPLICATION 1 wrapped bytes
func UnmarshalTicket(data []byte) (*Ticket, []byte, error) {
	var raw asn1.RawValue
	rest, err := asn1.Unmarshal(data, &raw)
	if err != nil {
		return nil, nil, err
	}
	if raw.Class != asn1.ClassApplication || raw.Tag != 1 {
		return nil, nil, asn1.StructuralError{Msg: "not an APPLICATION 1 Ticket"}
	}
	var ticket Ticket
	_, err = asn1.Unmarshal(raw.Bytes, &ticket)
	if err != nil {
		return nil, nil, err
	}
	return &ticket, rest, nil
}

// TicketRaw is the raw ASN.1 structure with APPLICATION tag
type TicketRaw struct {
	TktVno  int           `asn1:"explicit,tag:0"`
	Realm   string        `asn1:"generalstring,explicit,tag:1"`
	SName   PrincipalName `asn1:"explicit,tag:2"`
	EncPart EncryptedData `asn1:"explicit,tag:3"`
}

// EncTicketPart is the encrypted portion of a ticket.
//
// EDUCATIONAL: Inside the Encrypted Ticket
//
// This is what's inside the ticket's EncPart (encrypted with service key):
//
//	Flags:        Ticket options (forwardable, renewable, etc.)
//	Key:          Session key for this ticket
//	CRealm/CName: Client's identity
//	Transited:    Realms crossed (for cross-realm tickets)
//	AuthTime:     When the client authenticated
//	StartTime:    When ticket becomes valid
//	EndTime:      When ticket expires
//	RenewTill:    Maximum renewal time
//	CAddr:        Client addresses (optional restriction)
//	AuthzData:    Authorization data (contains PAC!)
//
// The PAC (Privilege Attribute Certificate) in AuthzData is critical -
// it contains the user's SID and group memberships that Windows uses
// for access control. This is what we forge in Golden/Silver tickets!
type EncTicketPart struct {
	Flags             asn1.BitString    `asn1:"explicit,tag:0"`
	Key               EncryptionKey     `asn1:"explicit,tag:1"`
	CRealm            string            `asn1:"generalstring,explicit,tag:2"`
	CName             PrincipalName     `asn1:"explicit,tag:3"`
	Transited         TransitedEncoding `asn1:"explicit,tag:4"`
	AuthTime          time.Time         `asn1:"generalized,explicit,tag:5"`
	StartTime         time.Time         `asn1:"generalized,optional,explicit,tag:6"`
	EndTime           time.Time         `asn1:"generalized,explicit,tag:7"`
	RenewTill         time.Time         `asn1:"generalized,optional,explicit,tag:8"`
	CAddr             HostAddresses     `asn1:"optional,explicit,tag:9"`
	AuthorizationData AuthorizationData `asn1:"optional,explicit,tag:10"`
}

// TransitedEncoding contains transit path information.
type TransitedEncoding struct {
	TRType   int32  `asn1:"explicit,tag:0"`
	Contents []byte `asn1:"explicit,tag:1"`
}

// KRBCred is the KRB-CRED message used in .kirbi files.
//
// EDUCATIONAL: The .kirbi Format
//
// .kirbi files are the Windows format for storing Kerberos credentials.
// They contain a KRB-CRED message which includes:
//
//  1. PVNO: Protocol version (5)
//  2. MsgType: Message type (22 for KRB-CRED)
//  3. Tickets: Array of tickets
//  4. EncPart: Encrypted credential info
//
// The interesting thing is that EncPart is typically encrypted with
// a NULL key (etype 0), which means it's essentially plaintext!
// This contains the session key, making .kirbi files portable.
//
// This is why Mimikatz and Rubeus can dump tickets that work on
// other machines - the session key is included in the .kirbi.
type KRBCred struct {
	PVNO       int           `asn1:"explicit,tag:0"`
	MsgType    int           `asn1:"explicit,tag:1"`
	TicketsRaw asn1.RawValue `asn1:"explicit,tag:2"` // Raw tickets for flexible parsing
	EncPart    EncryptedData `asn1:"explicit,tag:3"`
	Tickets    []Ticket      `asn1:"-"` // Parsed tickets (not directly from ASN.1)
}

// ParseTickets extracts Ticket structs from TicketsRaw.
// Handles both APPLICATION 1 wrapped and raw SEQUENCE tickets.
func (k *KRBCred) ParseTickets() error {
	if len(k.TicketsRaw.Bytes) == 0 {
		return nil
	}

	// TicketsRaw.Bytes contains the SEQUENCE OF Ticket
	data := k.TicketsRaw.Bytes
	for len(data) > 0 {
		tkt, rest, err := UnmarshalTicket(data)
		if err != nil {
			return err
		}
		if tkt != nil {
			k.Tickets = append(k.Tickets, *tkt)
		}
		data = rest
	}
	return nil
}

// EncKRBCredPart is the encrypted part of KRB-CRED.
type EncKRBCredPart struct {
	TicketInfo []KRBCredInfo `asn1:"explicit,tag:0"`
	Nonce      int32         `asn1:"optional,explicit,tag:1"`
	Timestamp  time.Time     `asn1:"generalized,optional,explicit,tag:2"`
	Usec       int32         `asn1:"optional,explicit,tag:3"`
	SAddress   HostAddress   `asn1:"optional,explicit,tag:4"`
	RAddress   HostAddress   `asn1:"optional,explicit,tag:5"`
}

// KRBCredInfo contains credential information for one ticket.
type KRBCredInfo struct {
	Key       EncryptionKey  `asn1:"explicit,tag:0"`
	PRealm    string         `asn1:"generalstring,optional,explicit,tag:1"`
	PName     PrincipalName  `asn1:"optional,explicit,tag:2"`
	Flags     asn1.BitString `asn1:"optional,explicit,tag:3"`
	AuthTime  time.Time      `asn1:"generalized,optional,explicit,tag:4"`
	StartTime time.Time      `asn1:"generalized,optional,explicit,tag:5"`
	EndTime   time.Time      `asn1:"generalized,optional,explicit,tag:6"`
	RenewTill time.Time      `asn1:"generalized,optional,explicit,tag:7"`
	SRealm    string         `asn1:"generalstring,optional,explicit,tag:8"`
	SName     PrincipalName  `asn1:"optional,explicit,tag:9"`
	CAddr     HostAddresses  `asn1:"optional,explicit,tag:10"`
}

// NewTicket creates a new ticket structure.
func NewTicket(realm string, sname PrincipalName, encPart EncryptedData) *Ticket {
	return &Ticket{
		TktVno:  5,
		Realm:   realm,
		SName:   sname,
		EncPart: encPart,
	}
}

// NewKRBCred creates a new KRB-CRED message for .kirbi format.
func NewKRBCred(tickets []Ticket, encPart EncryptedData) *KRBCred {
	return &KRBCred{
		PVNO:    5,
		MsgType: MsgTypeKRBCred,
		Tickets: tickets,
		EncPart: encPart,
	}
}
