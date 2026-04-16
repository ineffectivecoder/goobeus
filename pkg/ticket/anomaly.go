package ticket

import (
	"fmt"
	"strings"
)

// AnomalyCheck represents a potential issue in a ticket that might
// trigger EDR detection or cause SSPI to behave differently.
type AnomalyCheck struct {
	Name        string
	Description string
	Status      string // "OK", "WARNING", "ISSUE"
	Details     string
}

// CheckForAnomalies analyzes a Kirbi ticket for potential issues that
// might cause detection or SSPI problems when used via PTT.
//
// This is specifically designed to help debug why forged tickets might
// trigger the AP_REQ_ZERO_FILLED_BIND_IN_AUTHENTICATOR_CHECKSUM detection.
func CheckForAnomalies(kirbi *Kirbi) []AnomalyCheck {
	var checks []AnomalyCheck

	if kirbi == nil {
		return []AnomalyCheck{{
			Name:    "Ticket Validity",
			Status:  "ISSUE",
			Details: "Kirbi is nil",
		}}
	}

	// Check 1: KRB-CRED structure
	checks = append(checks, checkKRBCredStructure(kirbi))

	// Check 2: CredInfo presence
	checks = append(checks, checkCredInfo(kirbi))

	// Check 3: Session key
	checks = append(checks, checkSessionKey(kirbi))

	// Check 4: Address fields (caddr)
	checks = append(checks, checkAddressFields(kirbi))

	// Check 5: Flags consistency
	checks = append(checks, checkFlagsConsistency(kirbi))

	// Check 6: Time values
	checks = append(checks, checkTimeValues(kirbi))

	// Check 7: Ticket encryption type
	checks = append(checks, checkEncryptionType(kirbi))

	// Check 8: Nonce field
	checks = append(checks, checkNonceField(kirbi))

	return checks
}

func checkKRBCredStructure(kirbi *Kirbi) AnomalyCheck {
	check := AnomalyCheck{
		Name:        "KRB-CRED Structure",
		Description: "Validates the outer KRB-CRED envelope structure",
	}

	if kirbi.Cred == nil {
		check.Status = "WARNING"
		check.Details = "No parsed Cred structure (RawBytes only mode)"
		return check
	}

	if len(kirbi.Cred.Tickets) == 0 {
		check.Status = "ISSUE"
		check.Details = "No tickets in KRB-CRED"
		return check
	}

	check.Status = "OK"
	check.Details = fmt.Sprintf("%d ticket(s) in envelope", len(kirbi.Cred.Tickets))
	return check
}

func checkCredInfo(kirbi *Kirbi) AnomalyCheck {
	check := AnomalyCheck{
		Name:        "CredInfo (KRBCredInfo)",
		Description: "Validates ticket metadata in EncKrbCredPart",
	}

	if kirbi.CredInfo == nil {
		check.Status = "WARNING"
		check.Details = "CredInfo is nil - may cause SSPI issues"
		return check
	}

	if len(kirbi.CredInfo.TicketInfo) == 0 {
		check.Status = "ISSUE"
		check.Details = "No TicketInfo entries in CredInfo"
		return check
	}

	info := &kirbi.CredInfo.TicketInfo[0]
	var issues []string

	if info.PRealm == "" {
		issues = append(issues, "PRealm empty")
	}
	if len(info.PName.NameString) == 0 {
		issues = append(issues, "PName empty")
	}
	if info.SRealm == "" {
		issues = append(issues, "SRealm empty")
	}
	if len(info.SName.NameString) == 0 {
		issues = append(issues, "SName empty")
	}

	if len(issues) > 0 {
		check.Status = "WARNING"
		check.Details = strings.Join(issues, ", ")
	} else {
		check.Status = "OK"
		check.Details = fmt.Sprintf("Client: %s@%s, Service: %s@%s",
			strings.Join(info.PName.NameString, "/"), info.PRealm,
			strings.Join(info.SName.NameString, "/"), info.SRealm)
	}
	return check
}

func checkSessionKey(kirbi *Kirbi) AnomalyCheck {
	check := AnomalyCheck{
		Name:        "Session Key",
		Description: "Validates session key in KRBCredInfo",
	}

	if kirbi.CredInfo == nil || len(kirbi.CredInfo.TicketInfo) == 0 {
		check.Status = "WARNING"
		check.Details = "Cannot check - no CredInfo"
		return check
	}

	key := kirbi.CredInfo.TicketInfo[0].Key
	if len(key.KeyValue) == 0 {
		check.Status = "ISSUE"
		check.Details = "Session key is empty - will fail authentication"
		return check
	}

	keyType := key.KeyType
	keyLen := len(key.KeyValue)

	// Validate key length matches etype
	var expectedLen int
	var etypeName string
	switch keyType {
	case 17: // AES128
		expectedLen = 16
		etypeName = "AES128"
	case 18: // AES256
		expectedLen = 32
		etypeName = "AES256"
	case 23: // RC4
		expectedLen = 16
		etypeName = "RC4"
	default:
		check.Status = "WARNING"
		check.Details = fmt.Sprintf("Unknown key type %d, length %d bytes", keyType, keyLen)
		return check
	}

	if keyLen != expectedLen {
		check.Status = "ISSUE"
		check.Details = fmt.Sprintf("%s key should be %d bytes, got %d", etypeName, expectedLen, keyLen)
		return check
	}

	check.Status = "OK"
	check.Details = fmt.Sprintf("%s key, %d bytes", etypeName, keyLen)
	return check
}

func checkAddressFields(kirbi *Kirbi) AnomalyCheck {
	check := AnomalyCheck{
		Name:        "Address Fields (caddr)",
		Description: "Checks if HostAddresses are set (may affect SSPI)",
	}

	if kirbi.CredInfo == nil || len(kirbi.CredInfo.TicketInfo) == 0 {
		check.Status = "WARNING"
		check.Details = "Cannot check - no CredInfo"
		return check
	}

	info := &kirbi.CredInfo.TicketInfo[0]

	// Check CAddr in KRBCredInfo
	if len(info.CAddr) == 0 {
		check.Status = "OK"
		check.Details = "CAddr empty (normal for modern tickets - not bound to IP)"
	} else {
		check.Status = "OK"
		check.Details = fmt.Sprintf("CAddr has %d address(es)", len(info.CAddr))
	}

	return check
}

func checkFlagsConsistency(kirbi *Kirbi) AnomalyCheck {
	check := AnomalyCheck{
		Name:        "Ticket Flags",
		Description: "Validates ticket flags are consistent",
	}

	if kirbi.CredInfo == nil || len(kirbi.CredInfo.TicketInfo) == 0 {
		check.Status = "WARNING"
		check.Details = "Cannot check - no CredInfo"
		return check
	}

	flags := kirbi.CredInfo.TicketInfo[0].Flags
	if len(flags.Bytes) < 4 {
		check.Status = "WARNING"
		check.Details = "Flags field too short"
		return check
	}

	// Parse flags
	flagVal := uint32(flags.Bytes[0])<<24 | uint32(flags.Bytes[1])<<16 |
		uint32(flags.Bytes[2])<<8 | uint32(flags.Bytes[3])

	var setFlags []string
	if flagVal&0x40000000 != 0 {
		setFlags = append(setFlags, "FORWARDABLE")
	}
	if flagVal&0x20000000 != 0 {
		setFlags = append(setFlags, "FORWARDED")
	}
	if flagVal&0x10000000 != 0 {
		setFlags = append(setFlags, "PROXIABLE")
	}
	if flagVal&0x00800000 != 0 {
		setFlags = append(setFlags, "RENEWABLE")
	}
	if flagVal&0x00400000 != 0 {
		setFlags = append(setFlags, "INITIAL")
	}
	if flagVal&0x00200000 != 0 {
		setFlags = append(setFlags, "PRE-AUTHENT")
	}

	// Check for unusual combinations
	var warnings []string
	if flagVal&0x00400000 != 0 && flagVal&0x20000000 != 0 {
		warnings = append(warnings, "INITIAL+FORWARDED is unusual")
	}

	if len(warnings) > 0 {
		check.Status = "WARNING"
		check.Details = fmt.Sprintf("Flags: 0x%08X (%s) - %s",
			flagVal, strings.Join(setFlags, ","), strings.Join(warnings, "; "))
	} else {
		check.Status = "OK"
		check.Details = fmt.Sprintf("Flags: 0x%08X (%s)", flagVal, strings.Join(setFlags, ","))
	}
	return check
}

func checkTimeValues(kirbi *Kirbi) AnomalyCheck {
	check := AnomalyCheck{
		Name:        "Time Values",
		Description: "Validates ticket time fields are reasonable",
	}

	if kirbi.CredInfo == nil || len(kirbi.CredInfo.TicketInfo) == 0 {
		check.Status = "WARNING"
		check.Details = "Cannot check - no CredInfo"
		return check
	}

	info := &kirbi.CredInfo.TicketInfo[0]
	var issues []string

	if info.AuthTime.IsZero() {
		issues = append(issues, "AuthTime is zero")
	}
	if info.StartTime.IsZero() {
		issues = append(issues, "StartTime is zero")
	}
	if info.EndTime.IsZero() {
		issues = append(issues, "EndTime is zero")
	}
	if !info.EndTime.IsZero() && info.EndTime.Before(info.StartTime) {
		issues = append(issues, "EndTime before StartTime")
	}

	if len(issues) > 0 {
		check.Status = "WARNING"
		check.Details = strings.Join(issues, ", ")
	} else {
		check.Status = "OK"
		check.Details = fmt.Sprintf("Valid until %s", info.EndTime.Format("2006-01-02 15:04:05"))
	}
	return check
}

func checkEncryptionType(kirbi *Kirbi) AnomalyCheck {
	check := AnomalyCheck{
		Name:        "Ticket Encryption",
		Description: "Validates ticket's encrypted part",
	}

	if kirbi.Cred == nil || len(kirbi.Cred.Tickets) == 0 {
		check.Status = "WARNING"
		check.Details = "Cannot check - no parsed ticket"
		return check
	}

	ticket := kirbi.Cred.Tickets[0]
	etype := ticket.EncPart.EType

	switch etype {
	case 17, 18, 23:
		check.Status = "OK"
		check.Details = fmt.Sprintf("EType %d (supported)", etype)
	default:
		check.Status = "WARNING"
		check.Details = fmt.Sprintf("EType %d (unusual)", etype)
	}
	return check
}

func checkNonceField(kirbi *Kirbi) AnomalyCheck {
	check := AnomalyCheck{
		Name:        "Nonce Field",
		Description: "Checks if EncKrbCredPart has nonce (may affect SSPI)",
	}

	if kirbi.CredInfo == nil {
		check.Status = "WARNING"
		check.Details = "Cannot check - no CredInfo"
		return check
	}

	// EncKrbCredPart has optional nonce field
	// Some tools don't set this, which might be fine
	// But let's flag it for investigation

	// Note: Our current CredInfo struct might not parse this
	// This is a placeholder for future investigation
	check.Status = "OK"
	check.Details = "Nonce field check not implemented (optional field)"
	return check
}

// FormatAnomalyChecks returns a formatted string of all anomaly checks
func FormatAnomalyChecks(checks []AnomalyCheck) string {
	var sb strings.Builder

	sb.WriteString("\n╔══════════════════════════════════════════════════════════════════════════════╗\n")
	sb.WriteString("║                          TICKET ANOMALY ANALYSIS                              ║\n")
	sb.WriteString("╠══════════════════════════════════════════════════════════════════════════════╣\n")

	for _, check := range checks {
		var icon string
		switch check.Status {
		case "OK":
			icon = "✓"
		case "WARNING":
			icon = "⚠"
		case "ISSUE":
			icon = "✗"
		default:
			icon = "?"
		}

		sb.WriteString(fmt.Sprintf("  %s %-25s : %s\n", icon, check.Name, check.Details))
	}

	sb.WriteString("╚══════════════════════════════════════════════════════════════════════════════╝\n")

	// Summary
	var issues, warnings int
	for _, check := range checks {
		switch check.Status {
		case "ISSUE":
			issues++
		case "WARNING":
			warnings++
		}
	}

	if issues > 0 {
		sb.WriteString(fmt.Sprintf("\n⚠️  Found %d issue(s) and %d warning(s) that may cause detection\n", issues, warnings))
	} else if warnings > 0 {
		sb.WriteString(fmt.Sprintf("\n⚠️  Found %d warning(s) - ticket structure looks mostly OK\n", warnings))
	} else {
		sb.WriteString("\n✅ No obvious anomalies detected in ticket structure\n")
	}

	sb.WriteString("\nNote: This checks the KRB-CRED structure, not the AP-REQ that SSPI generates.\n")
	sb.WriteString("The zero-filled channel binding issue is in SSPI's AP-REQ construction,\n")
	sb.WriteString("which happens AFTER the ticket is passed to the system.\n")

	return sb.String()
}
