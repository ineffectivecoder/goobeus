// Package asn1krb5 provides ASN.1 structures for Kerberos messages.
//
// # Overview
//
// Kerberos messages are defined in RFC 4120 using ASN.1 (Abstract Syntax
// Notation One). This package provides Go structures that can be marshaled
// and unmarshaled using Go's encoding/asn1 package.
//
// # ASN.1 Basics for Kerberos
//
// ASN.1 uses tagged values. In Kerberos, most fields use EXPLICIT tagging,
// meaning each field has a context-specific tag number:
//
//	ASREQ ::= [APPLICATION 10] KDC-REQ
//	KDC-REQ ::= SEQUENCE {
//	    pvno         [0] INTEGER,     -- Always 5
//	    msg-type     [1] INTEGER,     -- 10 for AS, 12 for TGS
//	    padata       [2] SEQUENCE OF PA-DATA OPTIONAL,
//	    req-body     [3] KDC-REQ-BODY
//	}
//
// The [0], [1], [2] are context-specific tags that identify each field.
//
// # Message Types
//
//	AS-REQ  (10): Initial authentication request
//	AS-REP  (11): Initial authentication reply (contains TGT)
//	TGS-REQ (12): Ticket-granting service request
//	TGS-REP (13): Ticket-granting service reply
//	AP-REQ  (14): Application request (proves identity)
//	AP-REP  (15): Application reply
//	KRB-ERROR (30): Error message
//
// # References
//
//   - RFC 4120: The Kerberos Network Authentication Service (V5)
//   - RFC 4121: The Kerberos Version 5 GSS-API Mechanism
//   - RFC 6806: Kerberos Principal Name Canonicalization
package asn1krb5
