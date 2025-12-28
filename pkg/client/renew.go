package client

import (
	"context"
	"encoding/asn1"
	"fmt"
	"time"

	"github.com/goobeus/goobeus/pkg/asn1krb5"
	"github.com/goobeus/goobeus/pkg/crypto"
	"github.com/goobeus/goobeus/pkg/ticket"
)

// EDUCATIONAL: Ticket Renewal
//
// Renewable tickets can extend their lifetime without re-authenticating.
// This is useful for:
//   - Long-running processes
//   - Sessions that need to last longer than the max ticket lifetime
//
// Renewal sends a TGS-REQ with the RENEW flag set and the renewable ticket.
// The KDC issues a new ticket with a fresh lifetime (up to renew-till time).

// RenewRequest configures a ticket renewal request.
type RenewRequest struct {
	// Ticket to renew (must be renewable)
	Ticket     *ticket.Kirbi
	SessionKey []byte

	// Connection
	Domain string
	KDC    string
}

// RenewResult contains the renewed ticket.
type RenewResult struct {
	Kirbi  *ticket.Kirbi
	Base64 string
}

// Renew renews a renewable ticket.
func Renew(ctx context.Context, req *RenewRequest) (*RenewResult, error) {
	if req.Ticket == nil {
		return nil, fmt.Errorf("ticket is required")
	}
	if len(req.SessionKey) == 0 {
		if key := req.Ticket.SessionKey(); key != nil {
			req.SessionKey = key.KeyValue
		} else {
			return nil, fmt.Errorf("session key is required")
		}
	}

	domain := req.Domain
	if domain == "" && req.Ticket.CredInfo != nil && len(req.Ticket.CredInfo.TicketInfo) > 0 {
		domain = req.Ticket.CredInfo.TicketInfo[0].SRealm
	}

	etype := detectEtype(req.SessionKey)
	client := NewClient(domain).WithKDC(req.KDC)

	// Build TGS-REQ with RENEW flag
	tgsReq, err := buildRenewTGSREQ(req, domain, etype)
	if err != nil {
		return nil, fmt.Errorf("failed to build TGS-REQ: %w", err)
	}

	// Add PA-TGS-REQ with the renewable ticket
	paTGSReq, err := buildPATGSReq(req.Ticket.Ticket(), req.SessionKey, etype)
	if err != nil {
		return nil, fmt.Errorf("failed to build PA-TGS-REQ: %w", err)
	}
	tgsReq.PAData = append(tgsReq.PAData, paTGSReq)

	// Marshal and send
	tgsReqBytes, err := asn1.MarshalWithParams(tgsReq, "application,tag:12")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal TGS-REQ: %w", err)
	}

	respBytes, err := client.send(ctx, tgsReqBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to send TGS-REQ: %w", err)
	}

	if err := checkKRBError(respBytes); err != nil {
		return nil, err
	}

	var tgsRep asn1krb5.TGSREP
	_, err = asn1.UnmarshalWithParams(respBytes, &tgsRep, "application,tag:13")
	if err != nil {
		return nil, fmt.Errorf("failed to parse TGS-REP: %w", err)
	}

	decrypted, err := decryptEncPart(tgsRep.EncPart, req.SessionKey, etype, crypto.KeyUsageTGSRepEncPart)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt TGS-REP: %w", err)
	}

	var encPart asn1krb5.EncTGSRepPart
	_, err = asn1.UnmarshalWithParams(decrypted, &encPart, "application,tag:26")
	if err != nil {
		return nil, fmt.Errorf("failed to parse EncTGSRepPart: %w", err)
	}

	kirbi, _ := buildKirbiFromTGS(&tgsRep.Ticket, &encPart)
	b64, _ := kirbi.ToBase64()

	return &RenewResult{
		Kirbi:  kirbi,
		Base64: b64,
	}, nil
}

func buildRenewTGSREQ(req *RenewRequest, domain string, etype int32) (*asn1krb5.TGSREQ, error) {
	now := time.Now().UTC()

	// Set RENEW flag (0x00000002)
	options := asn1krb5.FlagRenewable | 0x00000002
	optionsBits := make([]byte, 4)
	optionsBits[0] = byte((options >> 24) & 0xFF)
	optionsBits[1] = byte((options >> 16) & 0xFF)
	optionsBits[2] = byte((options >> 8) & 0xFF)
	optionsBits[3] = byte(options & 0xFF)

	// Get service name from ticket
	sname := req.Ticket.Ticket().SName

	body := asn1krb5.KDCReqBody{
		KDCOptions: asn1.BitString{
			Bytes:     optionsBits,
			BitLength: 32,
		},
		Realm: domain,
		SName: sname,
		Till:  now.Add(10 * time.Hour),
		Nonce: int32(now.UnixNano() & 0x7FFFFFFF),
		EType: []int32{etype},
	}

	return &asn1krb5.TGSREQ{
		PVNO:    asn1krb5.PVNO,
		MsgType: asn1krb5.MsgTypeTGSREQ,
		ReqBody: body,
	}, nil
}
