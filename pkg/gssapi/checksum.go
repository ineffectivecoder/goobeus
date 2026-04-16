// Package gssapi implements GSS-API primitives for Kerberos authentication.
// This allows goobeus to construct AP-REQ messages directly, bypassing Windows SSPI.
// This is necessary to avoid the zero-filled channel binding detection in EDRs.
package gssapi

import (
	"encoding/binary"
)

// GSS-API flags (RFC 2744)
const (
	GSS_C_DELEG_FLAG    = 0x01
	GSS_C_MUTUAL_FLAG   = 0x02
	GSS_C_REPLAY_FLAG   = 0x04
	GSS_C_SEQUENCE_FLAG = 0x08
	GSS_C_CONF_FLAG     = 0x10
	GSS_C_INTEG_FLAG    = 0x20
	GSS_C_DCE_STYLE     = 0x1000
)

// Kerberos OID: 1.2.840.113554.1.2.2
var KerberosOID = []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02}

// ChecksumType for GSS-API Kerberos (RFC 4121)
const GSS_CHECKSUM_TYPE = 0x8003

// CheckSumField represents the GSS-API checksum in Kerberos Authenticator.
// RFC 4121 Section 4.1.1
//
// Structure (minimum 24 bytes):
//
//	Offset  Length  Field
//	0       4       Lgth (length of Bnd field = 16)
//	4       16      Bnd  (MD5 hash of channel bindings, all zeros if not using)
//	20      4       Flags (GSS context flags)
//	24+     var     Delegation token (optional, only if GSS_C_DELEG_FLAG set)
type CheckSumField struct {
	Lgth       uint32   // Always 16
	Bnd        [16]byte // Channel binding MD5 hash (zeros = no binding)
	Flags      uint32   // GSS flags
	Delegation []byte   // Optional delegation token
}

// NewCheckSumField creates a new GSS checksum with the specified flags.
// Channel binding is left as zeros (no TLS channel binding).
func NewCheckSumField(flags uint32) *CheckSumField {
	return &CheckSumField{
		Lgth:  16,
		Bnd:   [16]byte{}, // zeros - no channel binding
		Flags: flags,
	}
}

// NewCheckSumFieldWithDelegation creates a GSS checksum with a delegation token.
func NewCheckSumFieldWithDelegation(flags uint32, delegToken []byte) *CheckSumField {
	return &CheckSumField{
		Lgth:       16,
		Bnd:        [16]byte{},
		Flags:      flags | GSS_C_DELEG_FLAG,
		Delegation: delegToken,
	}
}

// Marshal encodes the CheckSumField to bytes.
func (c *CheckSumField) Marshal() []byte {
	// Base size: 4 (Lgth) + 16 (Bnd) + 4 (Flags) = 24
	size := 24 + len(c.Delegation)
	data := make([]byte, size)

	binary.LittleEndian.PutUint32(data[0:4], c.Lgth)
	copy(data[4:20], c.Bnd[:])
	binary.LittleEndian.PutUint32(data[20:24], c.Flags)

	if len(c.Delegation) > 0 {
		copy(data[24:], c.Delegation)
	}

	return data
}

// Unmarshal decodes a CheckSumField from bytes.
func (c *CheckSumField) Unmarshal(data []byte) error {
	if len(data) < 24 {
		return ErrChecksumTooShort
	}

	c.Lgth = binary.LittleEndian.Uint32(data[0:4])
	copy(c.Bnd[:], data[4:20])
	c.Flags = binary.LittleEndian.Uint32(data[20:24])

	if len(data) > 24 {
		c.Delegation = make([]byte, len(data)-24)
		copy(c.Delegation, data[24:])
	}

	return nil
}

// DefaultFlags returns typical GSS flags for SMB/LDAP authentication.
func DefaultFlags() uint32 {
	return GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG | GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG
}

// DCEStyleFlags returns flags for DCE-style authentication (used by DRSUAPI/DCSync).
func DCEStyleFlags() uint32 {
	return GSS_C_DCE_STYLE | GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG | GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG
}
