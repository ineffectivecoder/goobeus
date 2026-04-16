// Package gssapi - SMB client for testing AP-REQ authentication.
// This is a minimal SMB2 client that uses our custom AP-REQ construction.
package gssapi

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/goobeus/goobeus/pkg/ticket"
)

// SMBClient is a minimal SMB2 client for testing Kerberos authentication.
type SMBClient struct {
	conn       net.Conn
	sessionID  uint64
	messageID  uint64
	sequenceID uint64
}

// SMB2 constants
const (
	SMB2_NEGOTIATE     = 0x0000
	SMB2_SESSION_SETUP = 0x0001
	SMB2_TREE_CONNECT  = 0x0003
	SMB2_IOCTL         = 0x000b
)

// SMB2 Header structure (64 bytes)
type smb2Header struct {
	ProtocolID    [4]byte // 0xFE 'S' 'M' 'B'
	StructureSize uint16  // 64
	CreditCharge  uint16
	Status        uint32
	Command       uint16
	Credits       uint16
	Flags         uint32
	NextCommand   uint32
	MessageID     uint64
	Reserved      uint32
	TreeID        uint32
	SessionID     uint64
	Signature     [16]byte
}

// SMB2 Negotiate Request
type smb2NegotiateReq struct {
	StructureSize   uint16
	DialectCount    uint16
	SecurityMode    uint16
	Reserved        uint16
	Capabilities    uint32
	ClientGUID      [16]byte
	ClientStartTime uint64
	Dialects        []uint16
}

// NewSMBClient creates a new SMB client connected to the target.
func NewSMBClient(target string, timeout time.Duration) (*SMBClient, error) {
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	conn, err := net.DialTimeout("tcp", target+":445", timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s:445: %w", target, err)
	}

	return &SMBClient{
		conn:      conn,
		messageID: 0,
	}, nil
}

// Close closes the SMB connection.
func (c *SMBClient) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// Negotiate performs SMB2 negotiation.
func (c *SMBClient) Negotiate() error {
	// Build negotiate request
	header := c.buildHeader(SMB2_NEGOTIATE, 0)

	// Negotiate request body
	body := make([]byte, 36+2*2)                 // base size + 2 dialects
	binary.LittleEndian.PutUint16(body[0:2], 36) // StructureSize
	binary.LittleEndian.PutUint16(body[2:4], 2)  // DialectCount (2 dialects)
	binary.LittleEndian.PutUint16(body[4:6], 1)  // SecurityMode (signing enabled)
	binary.LittleEndian.PutUint32(body[8:12], 0) // Capabilities
	// ClientGUID at offset 12-28 (leave as zeros for simplicity)
	// ClientStartTime at offset 28-36 (leave as zeros)
	// Dialects start at offset 36
	binary.LittleEndian.PutUint16(body[36:38], 0x0202) // SMB 2.002
	binary.LittleEndian.PutUint16(body[38:40], 0x0210) // SMB 2.1

	// Send
	if err := c.sendMessage(header, body); err != nil {
		return fmt.Errorf("failed to send negotiate: %w", err)
	}

	// Receive response
	respHeader, _, err := c.recvMessage()
	if err != nil {
		return fmt.Errorf("failed to receive negotiate response: %w", err)
	}

	if respHeader.Status != 0 {
		return fmt.Errorf("negotiate failed with status 0x%08X", respHeader.Status)
	}

	return nil
}

// SessionSetupKerberos performs SMB2 session setup using our custom AP-REQ.
func (c *SMBClient) SessionSetupKerberos(kirbi *ticket.Kirbi, realm string, username string) error {
	if kirbi == nil || kirbi.CredInfo == nil || len(kirbi.CredInfo.TicketInfo) == 0 {
		return fmt.Errorf("invalid ticket")
	}

	// Build AP-REQ using our GSSAPI package
	sessionKey := kirbi.CredInfo.TicketInfo[0].Key.KeyValue
	sessionKeyType := kirbi.CredInfo.TicketInfo[0].Key.KeyType

	apreqReq := &APREQRequest{
		Ticket:         kirbi,
		SessionKey:     sessionKey,
		SessionKeyType: sessionKeyType,
		CRealm:         realm,
		CName:          []string{username},
		GSSFlags:       DefaultFlags(),
		MutualAuth:     true,
	}

	apreqBytes, err := BuildAPREQ(apreqReq)
	if err != nil {
		return fmt.Errorf("failed to build AP-REQ: %w", err)
	}

	// Wrap in GSS-API token
	gssToken := BuildGSSAPIToken(apreqBytes)

	// Build SPNEGO wrapper (simplified - just wrap in NegTokenInit)
	spnegoToken := buildSPNEGOInit(gssToken)

	// Build session setup request
	header := c.buildHeader(SMB2_SESSION_SETUP, 0)

	// Session setup request structure (25 bytes + security buffer)
	body := make([]byte, 25-1)                                           // StructureSize includes 1 byte of buffer
	binary.LittleEndian.PutUint16(body[0:2], 25)                         // StructureSize
	body[2] = 0                                                          // Flags
	body[3] = 1                                                          // SecurityMode (signing enabled)
	binary.LittleEndian.PutUint32(body[4:8], 0)                          // Capabilities
	binary.LittleEndian.PutUint32(body[8:12], 0)                         // Channel
	binary.LittleEndian.PutUint16(body[12:14], 88)                       // SecurityBufferOffset (header=64 + fixed=24)
	binary.LittleEndian.PutUint16(body[14:16], uint16(len(spnegoToken))) // SecurityBufferLength
	binary.LittleEndian.PutUint64(body[16:24], 0)                        // PreviousSessionId

	// Append security buffer
	body = append(body, spnegoToken...)

	// Send
	if err := c.sendMessage(header, body); err != nil {
		return fmt.Errorf("failed to send session setup: %w", err)
	}

	// Receive response
	respHeader, respBody, err := c.recvMessage()
	if err != nil {
		return fmt.Errorf("failed to receive session setup response: %w", err)
	}

	// STATUS_SUCCESS or STATUS_MORE_PROCESSING_REQUIRED
	if respHeader.Status != 0 && respHeader.Status != 0xc0000016 {
		return fmt.Errorf("session setup failed with status 0x%08X", respHeader.Status)
	}

	c.sessionID = respHeader.SessionID
	fmt.Printf("[+] SMB Session established! SessionID: 0x%x\n", c.sessionID)

	_ = respBody // Response body contains security buffer with AP-REP if mutual auth

	return nil
}

// buildHeader creates an SMB2 header.
func (c *SMBClient) buildHeader(command uint16, treeID uint32) []byte {
	header := make([]byte, 64)
	copy(header[0:4], []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(header[4:6], 64)            // StructureSize
	binary.LittleEndian.PutUint16(header[6:8], 1)             // CreditCharge
	binary.LittleEndian.PutUint32(header[8:12], 0)            // Status
	binary.LittleEndian.PutUint16(header[12:14], command)     // Command
	binary.LittleEndian.PutUint16(header[14:16], 1)           // Credits
	binary.LittleEndian.PutUint32(header[16:20], 0)           // Flags
	binary.LittleEndian.PutUint32(header[20:24], 0)           // NextCommand
	binary.LittleEndian.PutUint64(header[24:32], c.messageID) // MessageID
	c.messageID++
	binary.LittleEndian.PutUint32(header[32:36], 0)           // Reserved
	binary.LittleEndian.PutUint32(header[36:40], treeID)      // TreeID
	binary.LittleEndian.PutUint64(header[40:48], c.sessionID) // SessionID
	// Signature at 48-64 (leave as zeros for now)

	return header
}

// sendMessage sends an SMB2 message with NetBIOS header.
func (c *SMBClient) sendMessage(header, body []byte) error {
	message := append(header, body...)

	// NetBIOS header (4 bytes)
	netbios := make([]byte, 4)
	netbios[0] = 0 // Message type (Session Message)
	netbios[1] = byte(len(message) >> 16)
	netbios[2] = byte(len(message) >> 8)
	netbios[3] = byte(len(message))

	_, err := c.conn.Write(append(netbios, message...))
	return err
}

// recvMessage receives an SMB2 message.
func (c *SMBClient) recvMessage() (*smb2Header, []byte, error) {
	// Read NetBIOS header
	netbios := make([]byte, 4)
	if _, err := io.ReadFull(c.conn, netbios); err != nil {
		return nil, nil, err
	}

	length := int(netbios[1])<<16 | int(netbios[2])<<8 | int(netbios[3])

	// Read message
	message := make([]byte, length)
	if _, err := io.ReadFull(c.conn, message); err != nil {
		return nil, nil, err
	}

	if length < 64 {
		return nil, nil, fmt.Errorf("message too short")
	}

	// Parse header
	header := &smb2Header{}
	copy(header.ProtocolID[:], message[0:4])
	header.StructureSize = binary.LittleEndian.Uint16(message[4:6])
	header.CreditCharge = binary.LittleEndian.Uint16(message[6:8])
	header.Status = binary.LittleEndian.Uint32(message[8:12])
	header.Command = binary.LittleEndian.Uint16(message[12:14])
	header.Credits = binary.LittleEndian.Uint16(message[14:16])
	header.Flags = binary.LittleEndian.Uint32(message[16:20])
	header.NextCommand = binary.LittleEndian.Uint32(message[20:24])
	header.MessageID = binary.LittleEndian.Uint64(message[24:32])
	header.TreeID = binary.LittleEndian.Uint32(message[36:40])
	header.SessionID = binary.LittleEndian.Uint64(message[40:48])

	return header, message[64:], nil
}

// buildSPNEGOInit wraps a mechanism token in SPNEGO NegTokenInit.
func buildSPNEGOInit(mechToken []byte) []byte {
	// SPNEGO OID: 1.3.6.1.5.5.2
	spnegoOID := []byte{0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}

	// Kerberos OID for mechTypes
	kerberosOID := []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02}

	// Build mechTypes sequence
	mechTypesSeq := wrapSequence(kerberosOID)
	mechTypes := wrapContextTag(0, mechTypesSeq)

	// Build mechToken
	mechTokenField := wrapContextTag(2, wrapOctetString(mechToken))

	// Build NegTokenInit sequence
	negTokenInitSeq := append(mechTypes, mechTokenField...)
	negTokenInit := wrapSequence(negTokenInitSeq)

	// Wrap in context tag [0] (for NegTokenInit)
	negTokenInitTagged := wrapContextTag(0, negTokenInit)

	// Wrap in APPLICATION 0 with SPNEGO OID
	inner := append(spnegoOID, negTokenInitTagged...)
	return wrapApplication0(inner)
}

func wrapSequence(data []byte) []byte {
	return wrapTag(0x30, data)
}

func wrapOctetString(data []byte) []byte {
	return wrapTag(0x04, data)
}

func wrapContextTag(tag int, data []byte) []byte {
	return wrapTag(byte(0xa0+tag), data)
}

func wrapTag(tag byte, data []byte) []byte {
	length := len(data)
	if length < 128 {
		result := make([]byte, 2+length)
		result[0] = tag
		result[1] = byte(length)
		copy(result[2:], data)
		return result
	} else if length < 256 {
		result := make([]byte, 3+length)
		result[0] = tag
		result[1] = 0x81
		result[2] = byte(length)
		copy(result[3:], data)
		return result
	}
	result := make([]byte, 4+length)
	result[0] = tag
	result[1] = 0x82
	result[2] = byte(length >> 8)
	result[3] = byte(length)
	copy(result[4:], data)
	return result
}
