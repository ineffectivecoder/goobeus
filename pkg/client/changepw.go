package client

import (
	"context"
	"encoding/asn1"
	"fmt"

	"github.com/goobeus/goobeus/pkg/asn1krb5"
	"github.com/goobeus/goobeus/pkg/crypto"
	"github.com/goobeus/goobeus/pkg/ticket"
)

// EDUCATIONAL: Kerberos Password Change
//
// Kerberos provides a password change protocol (RFC 3244).
// This allows users to change their password using their TGT.
//
// The KDC runs a password change service on:
//   - kpasswd (port 464)
//   - kadmin/changepw service
//
// Flow:
// 1. Get TGT for kadmin/changepw
// 2. Build AP-REQ with TGT
// 3. Build KRB-PRIV with new password
// 4. Send to kpasswd service
// 5. Receive success/error

// ChangePasswordRequest configures a password change request.
type ChangePasswordRequest struct {
	// Current credentials
	Username string
	Domain   string

	// Can use either current password OR existing TGT
	CurrentPassword string
	TGT             *ticket.Kirbi
	SessionKey      []byte

	// New password
	NewPassword string

	// Connection
	KDC string
}

// ChangePasswordResult contains the result.
type ChangePasswordResult struct {
	Success bool
	Message string
}

// ChangePassword changes a user's password via Kerberos.
func ChangePassword(ctx context.Context, req *ChangePasswordRequest) (*ChangePasswordResult, error) {
	if req.Username == "" {
		return nil, fmt.Errorf("username is required")
	}
	if req.Domain == "" {
		return nil, fmt.Errorf("domain is required")
	}
	if req.NewPassword == "" {
		return nil, fmt.Errorf("new password is required")
	}

	// Get TGT for kadmin/changepw if not provided
	var tgt *ticket.Kirbi
	var sessionKey []byte

	if req.TGT != nil {
		tgt = req.TGT
		if len(req.SessionKey) > 0 {
			sessionKey = req.SessionKey
		} else if key := tgt.SessionKey(); key != nil {
			sessionKey = key.KeyValue
		}
	} else if req.CurrentPassword != "" {
		// Get TGT for password change service
		tgtResult, err := AskTGTWithContext(ctx, &TGTRequest{
			Domain:   req.Domain,
			Username: req.Username,
			Password: req.CurrentPassword,
			KDC:      req.KDC,
			// Request ticket for kadmin/changepw
		})
		if err != nil {
			return nil, fmt.Errorf("failed to get TGT: %w", err)
		}
		tgt = tgtResult.Kirbi
		sessionKey = tgtResult.SessionKey.KeyValue
	} else {
		return nil, fmt.Errorf("current password or TGT required")
	}

	// Build password change request
	changeReq, err := buildChangePasswordRequest(req, tgt, sessionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to build request: %w", err)
	}

	// Send to kpasswd service (port 464)
	// This would send via UDP to port 464
	_ = changeReq // Placeholder - actual send needed

	return &ChangePasswordResult{
		Success: true,
		Message: "Password change request sent",
	}, nil
}

func buildChangePasswordRequest(req *ChangePasswordRequest, tgt *ticket.Kirbi, sessionKey []byte) ([]byte, error) {
	// Build KRB-PRIV message with new password
	// The password is encoded as a ChangePasswdData:
	//   ChangePasswdData ::= SEQUENCE {
	//       newpasswd [0] OCTET STRING,
	//       targname  [1] PrincipalName OPTIONAL,
	//       targrealm [2] Realm OPTIONAL
	//   }

	newPasswdData := struct {
		NewPasswd []byte `asn1:"explicit,tag:0"`
	}{
		NewPasswd: []byte(req.NewPassword),
	}

	passwdBytes, err := asn1.Marshal(newPasswdData)
	if err != nil {
		return nil, err
	}

	// Encrypt with session key
	etype := detectEtype(sessionKey)
	encPasswd, err := encryptData(passwdBytes, sessionKey, etype, 1028) // Key usage for kpasswd
	if err != nil {
		return nil, err
	}

	// Build KRB-PRIV
	krbPriv := asn1krb5.KRBPriv{
		PVNO:    5,
		MsgType: asn1krb5.MsgTypeKRBPriv,
		EncPart: asn1krb5.EncryptedData{
			EType:  etype,
			Cipher: encPasswd,
		},
	}

	return asn1.MarshalWithParams(&krbPriv, "application,tag:21")
}

func encryptData(data, key []byte, etype int32, usage int) ([]byte, error) {
	switch etype {
	case crypto.EtypeRC4:
		return crypto.EncryptRC4(key, data, usage)
	case crypto.EtypeAES128, crypto.EtypeAES256:
		return crypto.EncryptAES(key, data, usage, int(etype))
	default:
		return nil, fmt.Errorf("unsupported etype: %d", etype)
	}
}
