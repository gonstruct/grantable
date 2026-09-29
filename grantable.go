// Package grantable is an OAuth 2.1 authorization server on net/http, for an
// API that hands tokens to applications a person connects: an MCP client, a
// script, another product.
//
// It owns the protocol: metadata, client registration and metadata
// documents, the authorization request, PKCE, codes, tokens, refresh
// rotation and revocation. The application owns the person: it signs them
// in, shows the consent page, and decides what a grant is, the subject
// every token names.
package grantable

import (
	"context"
	"sync"
	"time"
)

// Server is a configured authorization server. An application makes one at
// boot and hands its handlers to its router; a test makes its own on a
// Memory store.
type Server struct {
	mutex  sync.RWMutex
	config config
}

// New makes a server from the environment and the options.
func New(options ...option) *Server {
	server := &Server{}
	server.Configure(options...)

	return server
}

// Configure sets the server up from scratch: the environment first, then
// the options over it.
func (self *Server) Configure(options ...option) {
	self.mutex.Lock()
	defer self.mutex.Unlock()

	self.config = configure()

	for _, option := range options {
		option(&self.config)
	}
}

func (self *Server) settings() config {
	self.mutex.RLock()
	defer self.mutex.RUnlock()

	return self.config
}

// store is the configured one, refusing to go on without it: every
// handler reads or writes a row.
func (self *Server) store() (Store, error) {
	settings := self.settings()
	if settings.Store == nil {
		return nil, ErrMissingStore
	}

	return settings.Store, nil
}

func (self *Server) now() time.Time {
	return time.Now().UTC()
}

// grantedScopes is what a subject's grant allows now, intersected with what
// the token was issued with. The application's Grants answers the first;
// without one, a grant never narrows.
func (self *Server) grantedScopes(context context.Context, subject string, issued []string) ([]string, error) {
	grants := self.settings().Grants
	if grants == nil {
		return issued, nil
	}

	allowed, err := grants(context, subject)
	if err != nil {
		return nil, err
	}

	return intersect(issued, allowed), nil
}
