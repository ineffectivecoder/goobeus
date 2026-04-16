package gssapi

import "errors"

// Errors for GSSAPI package
var (
	ErrChecksumTooShort    = errors.New("gssapi: checksum data too short")
	ErrInvalidAPREQ        = errors.New("gssapi: invalid AP-REQ structure")
	ErrMissingSessionKey   = errors.New("gssapi: session key required")
	ErrUnsupportedEtype    = errors.New("gssapi: unsupported encryption type")
	ErrAuthenticatorFailed = errors.New("gssapi: failed to build authenticator")
)
