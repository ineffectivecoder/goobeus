// Package ticket provides Kerberos ticket format handling and analysis.
//
// # Overview
//
// This package handles the three main ticket formats used in Kerberos:
//
//   - .kirbi: Windows native format (KRB-CRED ASN.1 message)
//   - .ccache: MIT Kerberos credential cache (Linux/Unix format)
//   - Base64: Encoded .kirbi for command-line passing
//
// # Format Conversion
//
// All formats can be converted between each other:
//
//	kirbi → ccache: For use with Linux tools (Impacket, etc.)
//	ccache → kirbi: For use with Windows tools (Rubeus, etc.)
//	kirbi ↔ base64: For command-line passing and PTT
//
// # Ticket Analysis
//
// The ViewTicket function provides rich, educational ticket analysis:
//
//	view := ticket.ViewTicket(kirbi, ticket.ViewOptions{ShowPAC: true})
//	fmt.Println(view.String())
//
// This displays a beautifully formatted analysis explaining every field,
// including PAC contents, flag meanings, and security implications.
package ticket
