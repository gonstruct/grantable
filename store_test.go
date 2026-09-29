package grantable

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

// stores are the stores the contract runs against: memory always, and SQL
// when GRANTABLE_DATABASE_URL names a PostgreSQL to make a schema in.
func stores(t *testing.T) map[string]Store {
	t.Helper()

	stores := map[string]Store{"memory": Memory()}

	dsn := os.Getenv("GRANTABLE_DATABASE_URL")
	if dsn == "" {
		return stores
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)

	schemaName := fmt.Sprintf("grantable_test_%d", time.Now().UnixNano())
	schema, err := os.ReadFile("schema.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{"CREATE SCHEMA " + schemaName, "SET search_path TO " + schemaName, string(schema)} {
		if _, err := db.ExecContext(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Exec("DROP SCHEMA " + schemaName + " CASCADE")
		_ = db.Close()
	})

	stores["sql"] = SQL(func() DB { return db })

	return stores
}

func TestTheStoresKeepTheSameContract(t *testing.T) {
	t.Parallel()

	for name, store := range stores(t) {
		t.Run(name, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Microsecond)

			client := clientContract(t, store)
			request := requestContract(t, store, client, now)
			tokenContract(t, store, client, request, now)
		})
	}
}

func clientContract(t *testing.T, store Store) *Client {
	t.Helper()

	client := &Client{
		ID:           "https://claude.example/client.json",
		Name:         "Claude",
		RedirectURIs: []string{testRedirect},
		GrantTypes:   []string{grantCode},
		AuthMethod:   authNone,
		Document:     true,
	}
	if err := store.SaveClient(t.Context(), client); err != nil {
		t.Fatal(err)
	}

	client.Name = "Claude, renamed"
	if err := store.SaveClient(t.Context(), client); err != nil {
		t.Fatal(err)
	}

	found, err := store.FindClient(t.Context(), client.ID)
	if err != nil || found.Name != "Claude, renamed" || len(found.RedirectURIs) != 1 || !found.Document {
		t.Fatalf("FindClient = %+v, %v", found, err)
	}
	if _, err := store.FindClient(t.Context(), "nobody"); !errors.Is(err, ErrNotFound) {
		t.Errorf("FindClient(nobody) = %v", err)
	}

	return client
}

func requestContract(t *testing.T, store Store, client *Client, now time.Time) *Request {
	t.Helper()

	request := &Request{
		ClientID:      client.ID,
		RedirectURI:   testRedirect,
		Scopes:        []string{"read", "build"},
		CodeChallenge: challenge(testVerifier),
		Resource:      testResource,
		ExpiresAt:     now.Add(time.Minute),
	}
	if err := store.CreateRequest(t.Context(), request); err != nil || request.ID == "" {
		t.Fatalf("CreateRequest = %v, %q", err, request.ID)
	}
	if _, err := store.FindRequest(t.Context(), "not-an-id"); !errors.Is(err, ErrNotFound) {
		t.Errorf("FindRequest(not-an-id) = %v", err)
	}

	approved := approval{Subject: "connection-1", GrantedScopes: []string{"read"}, CodeHash: Hash("code"), ExpiresAt: now.Add(time.Minute)}
	if err := store.Approve(t.Context(), request.ID, approved, now); err != nil {
		t.Fatal(err)
	}
	if err := store.Approve(t.Context(), request.ID, approval{Subject: "connection-2", CodeHash: Hash("other")}, now); !errors.Is(err, ErrNotFound) {
		t.Errorf("approving twice = %v", err)
	}
	if err := store.Deny(t.Context(), request.ID, now); !errors.Is(err, ErrNotFound) {
		t.Errorf("denying an approved request = %v", err)
	}

	found, err := store.FindRequestByCode(t.Context(), Hash("code"))
	if err != nil || found.Subject != "connection-1" || len(found.GrantedScopes) != 1 || found.ApprovedAt.IsZero() {
		t.Fatalf("FindRequestByCode = %+v, %v", found, err)
	}
	if err := store.Consume(t.Context(), request.ID, now); err != nil {
		t.Fatal(err)
	}
	if err := store.Consume(t.Context(), request.ID, now); !errors.Is(err, ErrNotFound) {
		t.Errorf("consuming twice = %v", err)
	}

	return request
}

func tokenContract(t *testing.T, store Store, client *Client, request *Request, now time.Time) {
	t.Helper()

	token := &Token{
		Family:           request.ID,
		ClientID:         client.ID,
		Subject:          "connection-1",
		Scopes:           []string{"read"},
		Resource:         testResource,
		AccessHash:       Hash("access"),
		AccessExpiresAt:  now.Add(time.Hour),
		RefreshHash:      Hash("refresh"),
		RefreshExpiresAt: now.Add(time.Hour),
	}
	if err := store.CreateToken(t.Context(), token); err != nil || token.ID == "" {
		t.Fatalf("CreateToken = %v", err)
	}
	if found, err := store.FindAccessToken(t.Context(), Hash("access")); err != nil || found.ID != token.ID || !found.accessible(now) {
		t.Errorf("FindAccessToken = %+v, %v", found, err)
	}

	if err := store.Rotate(t.Context(), token.ID, now); err != nil {
		t.Fatal(err)
	}
	if err := store.Rotate(t.Context(), token.ID, now); !errors.Is(err, ErrNotFound) {
		t.Errorf("rotating twice = %v", err)
	}
	if found, _ := store.FindRefreshToken(t.Context(), Hash("refresh")); found.refreshable(now) {
		t.Error("a rotated refresh token is still refreshable")
	}

	if err := store.RevokeSubject(t.Context(), "connection-1", now); err != nil {
		t.Fatal(err)
	}
	if found, _ := store.FindAccessToken(t.Context(), Hash("access")); found.accessible(now) {
		t.Error("a revoked access token is still accessible")
	}
}
