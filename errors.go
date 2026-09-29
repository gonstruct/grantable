package grantable

import (
	"errors"
	"net/http"
)

var (
	// ErrNotFound is what a Store answers for a row it does not hold, or no
	// longer holds in the state asked for.
	ErrNotFound = errors.New("grantable: not found")

	// ErrRequestUnavailable means the authorization request is unknown,
	// expired, or already answered. The consent page shows it as gone.
	ErrRequestUnavailable = errors.New("grantable: the authorization request is unavailable")

	// ErrInvalidToken means a bearer token is unknown, expired, revoked,
	// issued for another resource, or grants nothing any more. Callers must
	// not tell the client which.
	ErrInvalidToken = errors.New("grantable: invalid token")

	ErrMissingStore  = errors.New("grantable: a Store is required")
	ErrMissingIssuer = errors.New("grantable: an issuer is required")
)

// The error codes of RFC 6749 section 5.2 and 4.1.2.1, RFC 7591 section 3.2.2
// and RFC 8707 section 2.
const (
	CodeInvalidRequest          = "invalid_request"
	CodeInvalidClient           = "invalid_client"
	CodeInvalidGrant            = "invalid_grant"
	CodeInvalidScope            = "invalid_scope"
	CodeInvalidTarget           = "invalid_target"
	CodeUnauthorizedClient      = "unauthorized_client"
	CodeUnsupportedGrantType    = "unsupported_grant_type"
	CodeUnsupportedResponseType = "unsupported_response_type"
	CodeAccessDenied            = "access_denied"
	CodeInvalidRedirectURI      = "invalid_redirect_uri"
	CodeInvalidClientMetadata   = "invalid_client_metadata"
	CodeServerError             = "server_error"
)

// Error is a refusal in the shape the OAuth specifications give it: a code
// a client acts on, a description a developer reads, and the HTTP status it
// travels with.
type Error struct {
	Status      int
	Code        string
	Description string
}

func (self *Error) Error() string {
	return "grantable: " + self.Code + ": " + self.Description
}

func refuse(status int, code, description string) *Error {
	return &Error{Status: status, Code: code, Description: description}
}

func invalidRequest(description string) *Error {
	return refuse(http.StatusBadRequest, CodeInvalidRequest, description)
}

func invalidClient(description string) *Error {
	return refuse(http.StatusUnauthorized, CodeInvalidClient, description)
}

func invalidGrant(description string) *Error {
	return refuse(http.StatusBadRequest, CodeInvalidGrant, description)
}

func invalidScope(description string) *Error {
	return refuse(http.StatusBadRequest, CodeInvalidScope, description)
}

func invalidTarget(description string) *Error {
	return refuse(http.StatusBadRequest, CodeInvalidTarget, description)
}

func invalidRedirectURI(description string) *Error {
	return refuse(http.StatusBadRequest, CodeInvalidRedirectURI, description)
}

func invalidClientMetadata(description string) *Error {
	return refuse(http.StatusBadRequest, CodeInvalidClientMetadata, description)
}
