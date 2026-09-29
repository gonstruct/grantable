package grantable

import (
	"context"
	"errors"
	"net/url"
	"slices"
	"time"
)

// ErrScopes means an approval grants nothing, or something the server does
// not offer.
var ErrScopes = errors.New("grantable: approve at least one scope, and only offered ones")

// Pending is an authorization request waiting on the person, what the
// consent page shows: who asks, for what, and where the answer goes.
type Pending struct {
	ID          string
	Client      Client
	RedirectURI string
	Scopes      []string
	Resource    string
	ExpiresAt   time.Time
}

// RedirectHost is where the answer goes, which the consent page must show:
// the one thing a client cannot fake.
func (self Pending) RedirectHost() string {
	parsed, err := url.Parse(self.RedirectURI)
	if err != nil {
		return self.RedirectURI
	}
	if parsed.Host == "" {
		return parsed.Scheme + ":"
	}

	return parsed.Host
}

// Loopback is whether the answer goes to this computer. A metadata document
// cannot prove a local client is the one it names, so the consent page
// says so.
func (self Pending) Loopback() bool {
	parsed, err := url.Parse(self.RedirectURI)

	return err == nil && parsed.Scheme == "http" && loopback(parsed.Hostname())
}

// DocumentHost is the host a metadata document client was read from, the
// domain it proved; empty for a registered client, which proved nothing.
func (self Pending) DocumentHost() string {
	if !self.Client.Document {
		return ""
	}

	parsed, err := url.Parse(self.Client.ID)
	if err != nil {
		return ""
	}

	return parsed.Host
}

// Pending finds a request waiting on the person. ErrRequestUnavailable when
// there is none: never made, expired, or answered.
func (self *Server) Pending(context context.Context, id string) (*Pending, error) {
	request, err := self.pendingRequest(context, id)
	if err != nil {
		return nil, err
	}

	client, err := self.settings().Store.FindClient(context, request.ClientID)
	if err != nil {
		return nil, err
	}
	client.SecretHash = ""

	return &Pending{
		ID:          request.ID,
		Client:      *client,
		RedirectURI: request.RedirectURI,
		Scopes:      request.Scopes,
		Resource:    request.Resource,
		ExpiresAt:   request.ExpiresAt,
	}, nil
}

// Approve answers yes: the request is for subject, the application's
// grant, and may do scopes, which need not be the ones asked for. It
// answers the URL to send the browser to, the client's redirect with a
// code.
func (self *Server) Approve(context context.Context, id string, subject string, scopes []string) (string, error) {
	settings := self.settings()
	if len(scopes) == 0 || !covers(settings.Scopes, scopes) {
		return "", ErrScopes
	}

	request, err := self.pendingRequest(context, id)
	if err != nil {
		return "", err
	}

	now := self.now()
	code := secret(settings.Prefix, codeKind)

	err = settings.Store.Approve(context, request.ID, approval{
		Subject:       subject,
		GrantedScopes: slices.Clone(scopes),
		CodeHash:      Hash(code),
		ExpiresAt:     now.Add(settings.Lifetimes.Code),
	}, now)
	if errors.Is(err, ErrNotFound) {
		return "", ErrRequestUnavailable
	}
	if err != nil {
		return "", err
	}

	return self.redirect(request.RedirectURI, url.Values{"code": {code}}, request.State), nil
}

// Deny answers no, and the URL to send the browser back to the client with.
func (self *Server) Deny(context context.Context, id string) (string, error) {
	request, err := self.pendingRequest(context, id)
	if err != nil {
		return "", err
	}

	err = self.settings().Store.Deny(context, request.ID, self.now())
	if errors.Is(err, ErrNotFound) {
		return "", ErrRequestUnavailable
	}
	if err != nil {
		return "", err
	}

	return self.redirect(request.RedirectURI, url.Values{
		"error":             {CodeAccessDenied},
		"error_description": {"The person did not allow it."},
	}, request.State), nil
}

func (self *Server) pendingRequest(context context.Context, id string) (*Request, error) {
	store, err := self.store()
	if err != nil {
		return nil, err
	}

	request, err := store.FindRequest(context, id)
	if errors.Is(err, ErrNotFound) {
		return nil, ErrRequestUnavailable
	}
	if err != nil {
		return nil, err
	}
	if !request.pending(self.now()) {
		return nil, ErrRequestUnavailable
	}

	return request, nil
}
