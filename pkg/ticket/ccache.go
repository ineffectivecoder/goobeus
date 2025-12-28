package ticket

import (
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/goobeus/goobeus/pkg/asn1krb5"
)

// EDUCATIONAL: MIT Kerberos Credential Cache Format (.ccache)
//
// The ccache format is used by MIT Kerberos implementations on Linux/Unix.
// It's a binary format (not ASN.1) that stores multiple credentials.
//
// File structure:
//   - Header: Version (2 bytes), flags, etc.
//   - Default principal: The primary identity
//   - Credentials: Array of stored tickets with session keys
//
// Common locations:
//   - /tmp/krb5cc_<uid> (default)
//   - Specified by KRB5CCNAME environment variable
//
// Why we need this:
//   - Import tickets from Linux tools (Impacket getTGT, etc.)
//   - Export tickets for use with Linux tools
//   - Cross-platform ticket portability

// CCache represents a MIT Kerberos credential cache.
type CCache struct {
	Version      uint8
	Header       CCacheHeader
	DefaultPrinc CCachePrincipal
	Credentials  []CCacheCredential
}

// CCacheHeader contains ccache header information.
type CCacheHeader struct {
	HeaderLen uint16
	Fields    []CCacheHeaderField
}

// CCacheHeaderField is a header field.
type CCacheHeaderField struct {
	Tag    uint16
	Length uint16
	Data   []byte
}

// CCachePrincipal represents a principal in ccache format.
type CCachePrincipal struct {
	NameType   uint32
	NumComp    uint32
	Realm      string
	Components []string
}

// CCacheCredential represents a single credential in the cache.
type CCacheCredential struct {
	Client       CCachePrincipal
	Server       CCachePrincipal
	Key          CCacheKeyBlock
	AuthTime     uint32
	StartTime    uint32
	EndTime      uint32
	RenewTill    uint32
	IsSKey       uint8
	TicketFlags  uint32
	Addresses    []CCacheAddress
	AuthData     []CCacheAuthData
	Ticket       []byte // Raw ticket bytes
	SecondTicket []byte
}

// CCacheKeyBlock represents an encryption key.
type CCacheKeyBlock struct {
	KeyType uint16
	EType   uint16 // Only in version 0x0504
	Key     []byte
}

// CCacheAddress represents a host address.
type CCacheAddress struct {
	AddrType uint16
	Address  []byte
}

// CCacheAuthData represents authorization data.
type CCacheAuthData struct {
	ADType uint16
	Data   []byte
}

// ccache version constants
const (
	CCacheVersion3 = 0x0503
	CCacheVersion4 = 0x0504
)

// LoadCCache reads a ccache file from disk.
//
// EDUCATIONAL: Reading ccache Files
//
// ccache files are binary with big-endian byte order.
// Version 4 (0x0504) is most common and includes etype in keys.
func LoadCCache(path string) (*CCache, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open ccache: %w", err)
	}
	defer f.Close()

	return ParseCCache(f)
}

// ParseCCache parses a ccache from a reader.
func ParseCCache(r io.Reader) (*CCache, error) {
	cc := &CCache{}

	// Read version (2 bytes, big-endian)
	var versionBytes [2]byte
	if _, err := io.ReadFull(r, versionBytes[:]); err != nil {
		return nil, fmt.Errorf("failed to read version: %w", err)
	}
	version := binary.BigEndian.Uint16(versionBytes[:])

	if version != CCacheVersion3 && version != CCacheVersion4 {
		return nil, fmt.Errorf("unsupported ccache version: 0x%04x", version)
	}
	cc.Version = uint8(version & 0xFF)

	// Version 4 has header fields
	if version == CCacheVersion4 {
		if err := cc.readHeader(r); err != nil {
			return nil, err
		}
	}

	// Read default principal
	princ, err := readPrincipal(r, version)
	if err != nil {
		return nil, fmt.Errorf("failed to read default principal: %w", err)
	}
	cc.DefaultPrinc = *princ

	// Read credentials until EOF
	for {
		cred, err := readCredential(r, version)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read credential: %w", err)
		}
		cc.Credentials = append(cc.Credentials, *cred)
	}

	return cc, nil
}

// SaveCCache writes a ccache to disk.
func SaveCCache(cc *CCache, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create ccache: %w", err)
	}
	defer f.Close()

	return cc.Write(f)
}

// Write writes the ccache to a writer.
func (cc *CCache) Write(w io.Writer) error {
	// Write version (always use v4)
	if err := binary.Write(w, binary.BigEndian, uint16(CCacheVersion4)); err != nil {
		return err
	}

	// Write empty header for v4
	if err := binary.Write(w, binary.BigEndian, uint16(0)); err != nil {
		return err
	}

	// Write default principal
	if err := writePrincipal(w, &cc.DefaultPrinc); err != nil {
		return err
	}

	// Write credentials
	for _, cred := range cc.Credentials {
		if err := writeCredential(w, &cred); err != nil {
			return err
		}
	}

	return nil
}

// ToKirbi converts the first credential to a Kirbi.
func (cc *CCache) ToKirbi() (*Kirbi, error) {
	if len(cc.Credentials) == 0 {
		return nil, fmt.Errorf("no credentials in ccache")
	}
	return credentialToKirbi(&cc.Credentials[0])
}

// FromKirbi creates a CCache from a Kirbi.
func FromKirbi(kirbi *Kirbi) (*CCache, error) {
	if kirbi.Cred == nil || len(kirbi.Cred.Tickets) == 0 {
		return nil, fmt.Errorf("kirbi has no tickets")
	}

	cc := &CCache{
		Version: 4,
	}

	// Set default principal from credential info
	if kirbi.CredInfo != nil && len(kirbi.CredInfo.TicketInfo) > 0 {
		info := &kirbi.CredInfo.TicketInfo[0]
		cc.DefaultPrinc = CCachePrincipal{
			NameType:   uint32(info.PName.NameType),
			NumComp:    uint32(len(info.PName.NameString)),
			Realm:      info.PRealm,
			Components: info.PName.NameString,
		}
	}

	// Convert each ticket to a credential
	for i := range kirbi.Cred.Tickets {
		cred, err := kirbiToCredential(kirbi, i)
		if err != nil {
			return nil, err
		}
		cc.Credentials = append(cc.Credentials, *cred)
	}

	return cc, nil
}

func (cc *CCache) readHeader(r io.Reader) error {
	var headerLen uint16
	if err := binary.Read(r, binary.BigEndian, &headerLen); err != nil {
		return err
	}
	cc.Header.HeaderLen = headerLen

	// Read and discard header fields for now
	headerData := make([]byte, headerLen)
	_, err := io.ReadFull(r, headerData)
	return err
}

func readPrincipal(r io.Reader, version uint16) (*CCachePrincipal, error) {
	p := &CCachePrincipal{}

	if err := binary.Read(r, binary.BigEndian, &p.NameType); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.BigEndian, &p.NumComp); err != nil {
		return nil, err
	}

	// Read realm
	realm, err := readCountedString(r)
	if err != nil {
		return nil, err
	}
	p.Realm = realm

	// Read components
	p.Components = make([]string, p.NumComp)
	for i := uint32(0); i < p.NumComp; i++ {
		comp, err := readCountedString(r)
		if err != nil {
			return nil, err
		}
		p.Components[i] = comp
	}

	return p, nil
}

func writePrincipal(w io.Writer, p *CCachePrincipal) error {
	if err := binary.Write(w, binary.BigEndian, p.NameType); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, uint32(len(p.Components))); err != nil {
		return err
	}
	if err := writeCountedString(w, p.Realm); err != nil {
		return err
	}
	for _, comp := range p.Components {
		if err := writeCountedString(w, comp); err != nil {
			return err
		}
	}
	return nil
}

func readCredential(r io.Reader, version uint16) (*CCacheCredential, error) {
	c := &CCacheCredential{}

	// Read client principal
	client, err := readPrincipal(r, version)
	if err != nil {
		return nil, err
	}
	c.Client = *client

	// Read server principal
	server, err := readPrincipal(r, version)
	if err != nil {
		return nil, err
	}
	c.Server = *server

	// Read keyblock
	if err := binary.Read(r, binary.BigEndian, &c.Key.KeyType); err != nil {
		return nil, err
	}
	if version == CCacheVersion4 {
		if err := binary.Read(r, binary.BigEndian, &c.Key.EType); err != nil {
			return nil, err
		}
	}
	keyLen, err := readCountedBytes(r)
	if err != nil {
		return nil, err
	}
	c.Key.Key = keyLen

	// Read times
	if err := binary.Read(r, binary.BigEndian, &c.AuthTime); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.BigEndian, &c.StartTime); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.BigEndian, &c.EndTime); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.BigEndian, &c.RenewTill); err != nil {
		return nil, err
	}

	// Read is_skey
	if err := binary.Read(r, binary.BigEndian, &c.IsSKey); err != nil {
		return nil, err
	}

	// Read ticket flags
	if err := binary.Read(r, binary.BigEndian, &c.TicketFlags); err != nil {
		return nil, err
	}

	// Read addresses
	var numAddr uint32
	if err := binary.Read(r, binary.BigEndian, &numAddr); err != nil {
		return nil, err
	}
	for i := uint32(0); i < numAddr; i++ {
		addr, err := readAddress(r)
		if err != nil {
			return nil, err
		}
		c.Addresses = append(c.Addresses, *addr)
	}

	// Read authdata
	var numAuthData uint32
	if err := binary.Read(r, binary.BigEndian, &numAuthData); err != nil {
		return nil, err
	}
	for i := uint32(0); i < numAuthData; i++ {
		ad, err := readAuthData(r)
		if err != nil {
			return nil, err
		}
		c.AuthData = append(c.AuthData, *ad)
	}

	// Read ticket
	ticket, err := readCountedBytes(r)
	if err != nil {
		return nil, err
	}
	c.Ticket = ticket

	// Read second ticket
	secondTicket, err := readCountedBytes(r)
	if err != nil {
		return nil, err
	}
	c.SecondTicket = secondTicket

	return c, nil
}

func writeCredential(w io.Writer, c *CCacheCredential) error {
	// Write client and server principals
	if err := writePrincipal(w, &c.Client); err != nil {
		return err
	}
	if err := writePrincipal(w, &c.Server); err != nil {
		return err
	}

	// Write keyblock (v4 format)
	if err := binary.Write(w, binary.BigEndian, c.Key.KeyType); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, c.Key.EType); err != nil {
		return err
	}
	if err := writeCountedBytes(w, c.Key.Key); err != nil {
		return err
	}

	// Write times
	if err := binary.Write(w, binary.BigEndian, c.AuthTime); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, c.StartTime); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, c.EndTime); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, c.RenewTill); err != nil {
		return err
	}

	// Write is_skey and flags
	if err := binary.Write(w, binary.BigEndian, c.IsSKey); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, c.TicketFlags); err != nil {
		return err
	}

	// Write empty addresses and authdata
	if err := binary.Write(w, binary.BigEndian, uint32(0)); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, uint32(0)); err != nil {
		return err
	}

	// Write ticket and second ticket
	if err := writeCountedBytes(w, c.Ticket); err != nil {
		return err
	}
	if err := writeCountedBytes(w, c.SecondTicket); err != nil {
		return err
	}

	return nil
}

func readAddress(r io.Reader) (*CCacheAddress, error) {
	a := &CCacheAddress{}
	if err := binary.Read(r, binary.BigEndian, &a.AddrType); err != nil {
		return nil, err
	}
	addr, err := readCountedBytes(r)
	if err != nil {
		return nil, err
	}
	a.Address = addr
	return a, nil
}

func readAuthData(r io.Reader) (*CCacheAuthData, error) {
	ad := &CCacheAuthData{}
	if err := binary.Read(r, binary.BigEndian, &ad.ADType); err != nil {
		return nil, err
	}
	data, err := readCountedBytes(r)
	if err != nil {
		return nil, err
	}
	ad.Data = data
	return ad, nil
}

func readCountedString(r io.Reader) (string, error) {
	var length uint32
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return "", err
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		return "", err
	}
	return string(data), nil
}

func writeCountedString(w io.Writer, s string) error {
	if err := binary.Write(w, binary.BigEndian, uint32(len(s))); err != nil {
		return err
	}
	_, err := w.Write([]byte(s))
	return err
}

func readCountedBytes(r io.Reader) ([]byte, error) {
	var length uint32
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return nil, err
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, err
	}
	return data, nil
}

func writeCountedBytes(w io.Writer, data []byte) error {
	if err := binary.Write(w, binary.BigEndian, uint32(len(data))); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

// credentialToKirbi converts a ccache credential to Kirbi format.
func credentialToKirbi(cred *CCacheCredential) (*Kirbi, error) {
	// Parse the raw ticket bytes as ASN.1 Ticket
	var ticket asn1krb5.Ticket
	_, err := asn1.UnmarshalWithParams(cred.Ticket, &ticket, "application,tag:1")
	if err != nil {
		// Try without application tag
		_, err = asn1.Unmarshal(cred.Ticket, &ticket)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ticket: %w", err)
		}
	}

	// Create credential info with session key
	credInfo := &asn1krb5.EncKRBCredPart{
		TicketInfo: []asn1krb5.KRBCredInfo{
			{
				Key: asn1krb5.EncryptionKey{
					KeyType:  int32(cred.Key.KeyType),
					KeyValue: cred.Key.Key,
				},
				PRealm:    cred.Client.Realm,
				PName:     principalToASN1(cred.Client),
				AuthTime:  time.Unix(int64(cred.AuthTime), 0),
				StartTime: time.Unix(int64(cred.StartTime), 0),
				EndTime:   time.Unix(int64(cred.EndTime), 0),
				RenewTill: time.Unix(int64(cred.RenewTill), 0),
				SRealm:    cred.Server.Realm,
				SName:     principalToASN1(cred.Server),
			},
		},
	}

	// Encode EncKRBCredPart
	encPartData, err := asn1.MarshalWithParams(credInfo, "application,tag:29")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal cred info: %w", err)
	}

	// Create KRB-CRED
	krbCred := &asn1krb5.KRBCred{
		PVNO:    5,
		MsgType: asn1krb5.MsgTypeKRBCred,
		Tickets: []asn1krb5.Ticket{ticket},
		EncPart: asn1krb5.EncryptedData{
			EType:  0, // NULL encryption
			Cipher: encPartData,
		},
	}

	return &Kirbi{
		Cred:     krbCred,
		CredInfo: credInfo,
	}, nil
}

// kirbiToCredential converts a Kirbi ticket to ccache credential.
func kirbiToCredential(kirbi *Kirbi, ticketIdx int) (*CCacheCredential, error) {
	if ticketIdx >= len(kirbi.Cred.Tickets) {
		return nil, fmt.Errorf("ticket index out of range")
	}

	ticket := &kirbi.Cred.Tickets[ticketIdx]

	// Get credential info
	var info *asn1krb5.KRBCredInfo
	if kirbi.CredInfo != nil && len(kirbi.CredInfo.TicketInfo) > ticketIdx {
		info = &kirbi.CredInfo.TicketInfo[ticketIdx]
	} else {
		return nil, fmt.Errorf("no credential info for ticket")
	}

	// Marshal ticket to bytes
	ticketBytes, err := asn1.MarshalWithParams(ticket, "application,tag:1")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ticket: %w", err)
	}

	cred := &CCacheCredential{
		Client: CCachePrincipal{
			NameType:   uint32(info.PName.NameType),
			NumComp:    uint32(len(info.PName.NameString)),
			Realm:      info.PRealm,
			Components: info.PName.NameString,
		},
		Server: CCachePrincipal{
			NameType:   uint32(info.SName.NameType),
			NumComp:    uint32(len(info.SName.NameString)),
			Realm:      info.SRealm,
			Components: info.SName.NameString,
		},
		Key: CCacheKeyBlock{
			KeyType: uint16(info.Key.KeyType),
			EType:   uint16(info.Key.KeyType),
			Key:     info.Key.KeyValue,
		},
		AuthTime:    uint32(info.AuthTime.Unix()),
		StartTime:   uint32(info.StartTime.Unix()),
		EndTime:     uint32(info.EndTime.Unix()),
		RenewTill:   uint32(info.RenewTill.Unix()),
		IsSKey:      0,
		TicketFlags: 0, // TODO: convert flags
		Ticket:      ticketBytes,
	}

	return cred, nil
}

func principalToASN1(p CCachePrincipal) asn1krb5.PrincipalName {
	return asn1krb5.PrincipalName{
		NameType:   int32(p.NameType),
		NameString: p.Components,
	}
}
