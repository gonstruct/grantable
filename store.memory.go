package grantable

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// Memory is a Store in a map, for tests: nothing to migrate, nothing
// shared between two servers.
func Memory() Store {
	return &memoryStore{
		clients:  map[string]Client{},
		requests: map[string]Request{},
		tokens:   map[string]Token{},
	}
}

type memoryStore struct {
	mutex    sync.Mutex
	clients  map[string]Client
	requests map[string]Request
	tokens   map[string]Token
}

func (self *memoryStore) SaveClient(_ context.Context, client *Client) error {
	self.mutex.Lock()
	defer self.mutex.Unlock()

	if existing, ok := self.clients[client.ID]; ok {
		client.CreatedAt = existing.CreatedAt
	}
	if client.CreatedAt.IsZero() {
		client.CreatedAt = time.Now()
	}
	self.clients[client.ID] = *client

	return nil
}

func (self *memoryStore) FindClient(_ context.Context, id string) (*Client, error) {
	self.mutex.Lock()
	defer self.mutex.Unlock()

	client, ok := self.clients[id]
	if !ok {
		return nil, ErrNotFound
	}

	return &client, nil
}

func (self *memoryStore) CreateRequest(_ context.Context, request *Request) error {
	self.mutex.Lock()
	defer self.mutex.Unlock()

	request.ID = memoryID()
	request.CreatedAt = time.Now()
	self.requests[request.ID] = *request

	return nil
}

func (self *memoryStore) FindRequest(_ context.Context, id string) (*Request, error) {
	self.mutex.Lock()
	defer self.mutex.Unlock()

	request, ok := self.requests[id]
	if !ok {
		return nil, ErrNotFound
	}

	return &request, nil
}

func (self *memoryStore) FindRequestByCode(_ context.Context, codeHash string) (*Request, error) {
	self.mutex.Lock()
	defer self.mutex.Unlock()

	for _, request := range self.requests {
		if request.CodeHash != "" && request.CodeHash == codeHash {
			return &request, nil
		}
	}

	return nil, ErrNotFound
}

func (self *memoryStore) Approve(_ context.Context, id string, approval approval, now time.Time) error {
	self.mutex.Lock()
	defer self.mutex.Unlock()

	request, ok := self.requests[id]
	if !ok || !request.pending(now) {
		return ErrNotFound
	}

	request.Subject = approval.Subject
	request.GrantedScopes = approval.GrantedScopes
	request.CodeHash = approval.CodeHash
	request.ExpiresAt = approval.ExpiresAt
	request.ApprovedAt = now
	self.requests[id] = request

	return nil
}

func (self *memoryStore) Deny(_ context.Context, id string, now time.Time) error {
	self.mutex.Lock()
	defer self.mutex.Unlock()

	request, ok := self.requests[id]
	if !ok || !request.pending(now) {
		return ErrNotFound
	}

	request.DeniedAt = now
	self.requests[id] = request

	return nil
}

func (self *memoryStore) Consume(_ context.Context, id string, now time.Time) error {
	self.mutex.Lock()
	defer self.mutex.Unlock()

	request, ok := self.requests[id]
	if !ok || request.ApprovedAt.IsZero() || !request.ConsumedAt.IsZero() || !now.Before(request.ExpiresAt) {
		return ErrNotFound
	}

	request.ConsumedAt = now
	self.requests[id] = request

	return nil
}

func (self *memoryStore) CreateToken(_ context.Context, token *Token) error {
	self.mutex.Lock()
	defer self.mutex.Unlock()

	token.ID = memoryID()
	token.CreatedAt = time.Now()
	self.tokens[token.ID] = *token

	return nil
}

func (self *memoryStore) FindAccessToken(_ context.Context, hash string) (*Token, error) {
	return self.findToken(func(token Token) bool { return token.AccessHash == hash })
}

func (self *memoryStore) FindRefreshToken(_ context.Context, hash string) (*Token, error) {
	return self.findToken(func(token Token) bool { return token.RefreshHash != "" && token.RefreshHash == hash })
}

func (self *memoryStore) findToken(match func(Token) bool) (*Token, error) {
	self.mutex.Lock()
	defer self.mutex.Unlock()

	for _, token := range self.tokens {
		if match(token) {
			return &token, nil
		}
	}

	return nil, ErrNotFound
}

func (self *memoryStore) Rotate(_ context.Context, id string, now time.Time) error {
	self.mutex.Lock()
	defer self.mutex.Unlock()

	token, ok := self.tokens[id]
	if !ok || !token.RotatedAt.IsZero() || !token.RevokedAt.IsZero() {
		return ErrNotFound
	}

	token.RotatedAt = now
	self.tokens[id] = token

	return nil
}

func (self *memoryStore) RevokeToken(_ context.Context, id string, now time.Time) error {
	return self.revoke(func(token Token) bool { return token.ID == id }, now)
}

func (self *memoryStore) RevokeFamily(_ context.Context, family string, now time.Time) error {
	return self.revoke(func(token Token) bool { return token.Family == family }, now)
}

func (self *memoryStore) RevokeSubject(_ context.Context, subject string, now time.Time) error {
	return self.revoke(func(token Token) bool { return token.Subject == subject }, now)
}

func (self *memoryStore) revoke(match func(Token) bool, now time.Time) error {
	self.mutex.Lock()
	defer self.mutex.Unlock()

	for id, token := range self.tokens {
		if match(token) && token.RevokedAt.IsZero() {
			token.RevokedAt = now
			self.tokens[id] = token
		}
	}

	return nil
}

func memoryID() string {
	random := make([]byte, 16)
	_, _ = rand.Read(random)

	return hex.EncodeToString(random)
}
