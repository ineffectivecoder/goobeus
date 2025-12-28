// Package client provides Kerberos client operations.
//
// # Overview
//
// This package implements the core Kerberos operations:
//   - AskTGT: Request a Ticket Granting Ticket (AS exchange)
//   - AskTGS: Request a Service Ticket (TGS exchange)
//   - S4U: Service-for-User delegation (S4U2Self, S4U2Proxy)
//   - Renew: Renew an existing ticket
//   - ChangePw: Change password via Kerberos
//
// # Authentication Methods
//
// All operations support multiple credential types:
//   - Password: Cleartext password (derives key)
//   - NTLM Hash: 16-byte RC4 key (pass-the-hash)
//   - AES Key: 16 or 32 bytes (AES128/256)
//
// # Usage
//
//	result, err := client.AskTGT(&client.TGTRequest{
//	    Domain:   "CORP.LOCAL",
//	    Username: "jsmith",
//	    Password: "Password123!",
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Save as .kirbi
//	ticket.SaveKirbi(result.Kirbi, "jsmith.kirbi")
package client
