// Package adws provides Active Directory Web Services client functionality.
//
// # Overview
//
// ADWS (Active Directory Web Services) is a SOAP/WCF-based protocol
// for querying Active Directory on port 9389. It provides the same
// data as LDAP but through a different wire protocol.
//
// # Why ADWS Instead of LDAP?
//
// ADWS is significantly less monitored by EDR solutions:
//   - Port 9389 vs LDAP's 389/636
//   - Uses WS-Transfer/WS-Enumeration protocols
//   - Same query capabilities, different transport
//   - PowerShell's ActiveDirectory module uses ADWS
//
// # Protocol Details
//
// ADWS uses several WS-* specifications:
//   - WS-Transfer: Get, Put, Create, Delete operations
//   - WS-Enumeration: Enumerate directory objects
//   - WS-Addressing: Message routing
//
// Authentication options:
//   - Kerberos (SPNEGO) - default in domain
//   - NTLM - for pass-the-hash
//   - Certificate-based
package adws
