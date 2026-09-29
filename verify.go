package grantable

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// AccessToken is a verified bearer token: who it is for and what it may do
// now, already narrowed to what its grant allows.
type AccessToken struct {
	ID        string
	ClientID  string
	Subject   string
	Scopes    []string
	Resource  string
	ExpiresAt time.Time
}

// Can is whether the token carries every one of the scopes.
func (self AccessToken) Can(scopes ...string) bool {
	return covers(self.Scopes, scopes)
}

// Verify checks a bearer token presented to resource: one this server
// issued, for that resource, live, and still allowed something by its
// grant. Any failure is ErrInvalidToken, but the grant's own error.
func (self *Server) Verify(context context.Context, bearer string, resource string) (*AccessToken, error) {
	store, err := self.store()
	if err != nil {
		return nil, err
	}
	if bearer == "" {
		return nil, ErrInvalidToken
	}

	token, err := store.FindAccessToken(context, Hash(bearer))
	if errors.Is(err, ErrNotFound) {
		return nil, ErrInvalidToken
	}
	if err != nil {
		return nil, err
	}
	if !token.accessible(self.now()) || canonical(token.Resource) != canonical(resource) {
		return nil, ErrInvalidToken
	}

	scopes, err := self.grantedScopes(context, token.Subject, token.Scopes)
	if err != nil {
		return nil, err
	}
	if len(scopes) == 0 {
		return nil, ErrInvalidToken
	}

	return &AccessToken{
		ID:        token.ID,
		ClientID:  token.ClientID,
		Subject:   token.Subject,
		Scopes:    scopes,
		Resource:  token.Resource,
		ExpiresAt: token.AccessExpiresAt,
	}, nil
}

// BearerToken is the token in a request's Authorization header, the only
// place RFC 6750 lets a resource read it from here.
func BearerToken(request *http.Request) string {
	scheme, token, found := strings.Cut(request.Header.Get("Authorization"), " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}

	return strings.TrimSpace(token)
}

// Challenge is what a resource tells a client it turned away, in the
// WWW-Authenticate header.
type Challenge struct {
	// Error is empty for a request without a token, invalid_token for one
	// it would not take, insufficient_scope for one that may not do this.
	Error       string
	Scopes      []string
	Description string
}

// Challenge is the WWW-Authenticate value for resource: where its metadata
// is, so a client can find this server and start over, and what went
// wrong.
func (self *Server) Challenge(resource string, challenge Challenge) string {
	parameters := []string{fmt.Sprintf("resource_metadata=%q", ResourceMetadataURL(resource))}

	if challenge.Error != "" {
		parameters = append(parameters, fmt.Sprintf("error=%q", challenge.Error))
	}
	if len(challenge.Scopes) > 0 {
		parameters = append(parameters, fmt.Sprintf("scope=%q", strings.Join(challenge.Scopes, " ")))
	}
	if challenge.Description != "" {
		parameters = append(parameters, fmt.Sprintf("error_description=%q", challenge.Description))
	}

	return "Bearer " + strings.Join(parameters, ", ")
}
