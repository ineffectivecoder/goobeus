package network

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// EDUCATIONAL: Kerberos Transport Protocols
//
// Kerberos uses two transport protocols:
//
// TCP (preferred for modern systems):
//   - Port 88
//   - Messages prefixed with 4-byte length
//   - Handles arbitrarily large messages (e.g., large tickets with PAC)
//   - Used by default in Windows Vista and later
//
// UDP (legacy, still supported):
//   - Port 88
//   - No length prefix (message is entire datagram)
//   - Limited to ~1400 bytes (fragmentation issues)
//   - Still used for simple requests
//
// We prefer TCP as tickets with PAC often exceed UDP limits.

// KDCTransport handles communication with a KDC.
type KDCTransport struct {
	Address string
	Timeout time.Duration
	UseTCP  bool
	UseUDP  bool
}

// NewKDCTransport creates a new KDC transport.
func NewKDCTransport(address string) *KDCTransport {
	return &KDCTransport{
		Address: address,
		Timeout: DefaultTimeout,
		UseTCP:  true, // Prefer TCP
		UseUDP:  true, // Fallback to UDP
	}
}

// SendAndReceive sends a Kerberos message and receives the response.
//
// EDUCATIONAL: Kerberos Message Exchange
//
// The message flow is simple request-response:
//  1. Client sends AS-REQ or TGS-REQ
//  2. KDC validates and responds with AS-REP/TGS-REP or KRB-ERROR
//
// TCP messages are framed with a 4-byte big-endian length prefix.
// UDP messages are sent as raw datagrams without length.
func (t *KDCTransport) SendAndReceive(msg []byte) ([]byte, error) {
	return t.SendAndReceiveContext(context.Background(), msg)
}

// SendAndReceiveContext sends with context support.
func (t *KDCTransport) SendAndReceiveContext(ctx context.Context, msg []byte) ([]byte, error) {
	// Try TCP first
	if t.UseTCP {
		resp, err := t.sendTCP(ctx, msg)
		if err == nil {
			return resp, nil
		}
		// If TCP fails and UDP is allowed, try UDP
		if !t.UseUDP {
			return nil, fmt.Errorf("TCP failed: %w", err)
		}
	}

	// Try UDP
	if t.UseUDP {
		return t.sendUDP(ctx, msg)
	}

	return nil, fmt.Errorf("no transport available")
}

func (t *KDCTransport) sendTCP(ctx context.Context, msg []byte) ([]byte, error) {
	// Create dialer with timeout
	dialer := &net.Dialer{
		Timeout: t.Timeout,
	}

	// Connect
	conn, err := dialer.DialContext(ctx, "tcp", t.Address)
	if err != nil {
		return nil, fmt.Errorf("TCP connect failed: %w", err)
	}
	defer conn.Close()

	// Set deadline
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	} else {
		conn.SetDeadline(time.Now().Add(t.Timeout))
	}

	// Send length prefix (4 bytes, big-endian) + message
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(msg)))

	if _, err := conn.Write(lenBuf); err != nil {
		return nil, fmt.Errorf("failed to send length: %w", err)
	}
	if _, err := conn.Write(msg); err != nil {
		return nil, fmt.Errorf("failed to send message: %w", err)
	}

	// Read response length
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return nil, fmt.Errorf("failed to read response length: %w", err)
	}
	respLen := binary.BigEndian.Uint32(lenBuf)

	// Sanity check response length (max 10MB)
	if respLen > 10*1024*1024 {
		return nil, fmt.Errorf("response too large: %d bytes", respLen)
	}

	// Read response
	resp := make([]byte, respLen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return resp, nil
}

func (t *KDCTransport) sendUDP(ctx context.Context, msg []byte) ([]byte, error) {
	// Resolve address
	addr, err := net.ResolveUDPAddr("udp", t.Address)
	if err != nil {
		return nil, fmt.Errorf("UDP resolve failed: %w", err)
	}

	// Connect
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, fmt.Errorf("UDP connect failed: %w", err)
	}
	defer conn.Close()

	// Set deadline
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	} else {
		conn.SetDeadline(time.Now().Add(t.Timeout))
	}

	// Send message (no length prefix for UDP)
	if _, err := conn.Write(msg); err != nil {
		return nil, fmt.Errorf("failed to send UDP message: %w", err)
	}

	// Read response (max 65KB for UDP)
	resp := make([]byte, 65535)
	n, err := conn.Read(resp)
	if err != nil {
		return nil, fmt.Errorf("failed to read UDP response: %w", err)
	}

	return resp[:n], nil
}

// SendToKDC is a convenience function for one-shot KDC communication.
//
// EDUCATIONAL: KDC Communication
//
// This is the core function for all Kerberos operations:
//   - asktgt: Send AS-REQ, receive AS-REP or KRB-ERROR
//   - asktgs: Send TGS-REQ, receive TGS-REP or KRB-ERROR
//   - renew:  Send TGS-REQ with RENEW flag
//
// The domain is used for KDC discovery if kdcAddr is empty.
func SendToKDC(domain, kdcAddr string, msg []byte) ([]byte, error) {
	return SendToKDCWithContext(context.Background(), domain, kdcAddr, msg)
}

// SendToKDCWithContext sends to KDC with context support.
func SendToKDCWithContext(ctx context.Context, domain, kdcAddr string, msg []byte) ([]byte, error) {
	// Resolve KDC address
	addr, err := ResolveKDC(domain, kdcAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve KDC: %w", err)
	}

	// Create transport and send
	transport := NewKDCTransport(addr)
	return transport.SendAndReceiveContext(ctx, msg)
}
