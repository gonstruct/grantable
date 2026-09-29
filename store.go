package grantable

import (
	"context"
	"time"
)

// Store keeps the clients, the authorization requests and the tokens.
// SQL is the one an application uses; Memory is for tests.
//
// Every method that changes a row in a way two requests could race on is
// conditional and says whether it made the change, so the store is the
// place that decides who won: approving a request, spending a code,
// rotating a refresh token.
type Store interface { //nolint:interfacebloat // every row the protocol keeps, and every way it changes one.
	// SaveClient inserts the client, or replaces the one with its ID: a
	// metadata document fetched again.
	SaveClient(context context.Context, client *Client) error
	FindClient(context context.Context, id string) (*Client, error)

	CreateRequest(context context.Context, request *Request) error
	FindRequest(context context.Context, id string) (*Request, error)
	FindRequestByCode(context context.Context, codeHash string) (*Request, error)

	// Approve answers a pending request with who it is for, what it may do
	// and the code's hash, and moves its expiry to the code's. ErrNotFound
	// when it was not pending: answered, or expired at now.
	Approve(context context.Context, id string, approval approval, now time.Time) error

	// Deny answers a pending request with no. ErrNotFound when it was not
	// pending.
	Deny(context context.Context, id string, now time.Time) error

	// Consume spends an approved code. ErrNotFound when it was already
	// spent or expired at now.
	Consume(context context.Context, id string, now time.Time) error

	CreateToken(context context.Context, token *Token) error
	FindAccessToken(context context.Context, hash string) (*Token, error)
	FindRefreshToken(context context.Context, hash string) (*Token, error)

	// Rotate marks a live token as replaced by a refresh. ErrNotFound when
	// it was already rotated or revoked: its refresh token is being used a
	// second time.
	Rotate(context context.Context, id string, now time.Time) error

	RevokeToken(context context.Context, id string, now time.Time) error
	RevokeFamily(context context.Context, family string, now time.Time) error
	RevokeSubject(context context.Context, subject string, now time.Time) error
}

// Client is an application that may ask for tokens: registered here, or
// described by a metadata document at the URL that is its ID.
type Client struct {
	ID           string
	Name         string
	URI          string
	LogoURI      string
	RedirectURIs []string
	GrantTypes   []string

	// AuthMethod is how it authenticates at the token endpoint: none for a
	// public client, client_secret_basic or client_secret_post.
	AuthMethod string
	SecretHash string

	// Document is whether the client is its metadata document, and
	// DocumentExpiresAt when it is read again.
	Document          bool
	DocumentExpiresAt time.Time

	CreatedAt time.Time
}

// Request is one authorization request, from the redirect to the consent
// page to the code and the tokens. Its ID names every token issued from its
// code, so a code spent twice revokes them.
type Request struct {
	ID            string
	ClientID      string
	RedirectURI   string
	Scopes        []string
	State         string
	CodeChallenge string
	Resource      string
	ExpiresAt     time.Time

	Subject       string
	GrantedScopes []string
	CodeHash      string
	ApprovedAt    time.Time
	DeniedAt      time.Time
	ConsumedAt    time.Time

	CreatedAt time.Time
}

// Token is one access token and, when the client may refresh, the refresh
// token issued beside it. Family is the authorization request it descends
// from, through every rotation.
type Token struct {
	ID       string
	Family   string
	ClientID string
	Subject  string
	Scopes   []string
	Resource string

	AccessHash       string
	AccessExpiresAt  time.Time
	RefreshHash      string
	RefreshExpiresAt time.Time

	RotatedAt time.Time
	RevokedAt time.Time
	CreatedAt time.Time
}

type approval struct {
	Subject       string
	GrantedScopes []string
	CodeHash      string
	ExpiresAt     time.Time
}

func (self *Request) pending(now time.Time) bool {
	return self.ApprovedAt.IsZero() && self.DeniedAt.IsZero() && now.Before(self.ExpiresAt)
}

// accessible is whether its access token is still good. A rotation leaves
// it be until it expires: a call already on its way with it should not fail
// because the client refreshed meanwhile.
func (self *Token) accessible(now time.Time) bool {
	return self.RevokedAt.IsZero() && now.Before(self.AccessExpiresAt)
}

func (self *Token) refreshable(now time.Time) bool {
	return self.RefreshHash != "" && self.RevokedAt.IsZero() && self.RotatedAt.IsZero() && now.Before(self.RefreshExpiresAt)
}
