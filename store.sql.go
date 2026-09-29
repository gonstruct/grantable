package grantable

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// DB is what the SQL store needs of a database: a *sql.DB, a *sql.Tx, or
// an application's executor that wraps one.
type DB interface {
	ExecContext(context context.Context, query string, args ...any) (sql.Result, error)
	QueryRowContext(context context.Context, query string, args ...any) *sql.Row
}

// SQL is the Store on PostgreSQL, in the tables of schema.sql. db is a
// function because an application registers grantable before it binds its
// database, the way core's session driver takes it.
//
// Every statement stands alone: the ones that decide a race are single
// conditional updates, so the store needs no transaction.
func SQL(db func() DB) Store {
	return sqlStore{db: db}
}

type sqlStore struct {
	db func() DB
}

const clientColumns = `id, name, uri, logo_uri, redirect_uris, grant_types, auth_method, secret_hash, document, document_expires_at, created_at`

func (self sqlStore) SaveClient(context context.Context, client *Client) error {
	redirectURIs, err := json.Marshal(client.RedirectURIs)
	if err != nil {
		return err
	}
	grantTypes, err := json.Marshal(client.GrantTypes)
	if err != nil {
		return err
	}

	return self.db().QueryRowContext(context, `
		INSERT INTO oauth_clients (id, name, uri, logo_uri, redirect_uris, grant_types, auth_method, secret_hash, document, document_expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (id) DO UPDATE SET
			name = EXCLUDED.name,
			uri = EXCLUDED.uri,
			logo_uri = EXCLUDED.logo_uri,
			redirect_uris = EXCLUDED.redirect_uris,
			grant_types = EXCLUDED.grant_types,
			auth_method = EXCLUDED.auth_method,
			secret_hash = EXCLUDED.secret_hash,
			document = EXCLUDED.document,
			document_expires_at = EXCLUDED.document_expires_at,
			updated_at = NOW()
		RETURNING created_at`,
		client.ID, client.Name, nullString(client.URI), nullString(client.LogoURI), redirectURIs, grantTypes,
		client.AuthMethod, nullString(client.SecretHash), client.Document, nullTime(client.DocumentExpiresAt),
	).Scan(&client.CreatedAt)
}

func (self sqlStore) FindClient(context context.Context, id string) (*Client, error) {
	client := &Client{}
	var uri, logoURI, secretHash sql.NullString
	var redirectURIs, grantTypes []byte
	var documentExpiresAt sql.NullTime

	err := self.db().QueryRowContext(context, `SELECT `+clientColumns+` FROM oauth_clients WHERE id = $1`, id).Scan(
		&client.ID, &client.Name, &uri, &logoURI, &redirectURIs, &grantTypes,
		&client.AuthMethod, &secretHash, &client.Document, &documentExpiresAt, &client.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(redirectURIs, &client.RedirectURIs); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(grantTypes, &client.GrantTypes); err != nil {
		return nil, err
	}
	client.URI = uri.String
	client.LogoURI = logoURI.String
	client.SecretHash = secretHash.String
	client.DocumentExpiresAt = documentExpiresAt.Time

	return client, nil
}

const requestColumns = `id, client_id, redirect_uri, scopes, state, code_challenge, resource, expires_at,
	subject, granted_scopes, code_hash, approved_at, denied_at, consumed_at, created_at`

func (self sqlStore) CreateRequest(context context.Context, request *Request) error {
	return self.db().QueryRowContext(context, `
		INSERT INTO oauth_authorization_requests (client_id, redirect_uri, scopes, state, code_challenge, resource, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, created_at`,
		request.ClientID, request.RedirectURI, strings.Join(request.Scopes, " "), nullString(request.State),
		request.CodeChallenge, request.Resource, request.ExpiresAt,
	).Scan(&request.ID, &request.CreatedAt)
}

func (self sqlStore) FindRequest(context context.Context, id string) (*Request, error) {
	if !uuidShaped(id) {
		return nil, ErrNotFound
	}

	return self.findRequest(context, `SELECT `+requestColumns+` FROM oauth_authorization_requests WHERE id = $1`, id)
}

func (self sqlStore) FindRequestByCode(context context.Context, codeHash string) (*Request, error) {
	return self.findRequest(context, `SELECT `+requestColumns+` FROM oauth_authorization_requests WHERE code_hash = $1`, codeHash)
}

func (self sqlStore) findRequest(context context.Context, query string, argument string) (*Request, error) {
	request := &Request{}
	var scopes string
	var state, subject, grantedScopes, codeHash sql.NullString
	var approvedAt, deniedAt, consumedAt sql.NullTime

	err := self.db().QueryRowContext(context, query, argument).Scan(
		&request.ID, &request.ClientID, &request.RedirectURI, &scopes, &state, &request.CodeChallenge, &request.Resource,
		&request.ExpiresAt, &subject, &grantedScopes, &codeHash, &approvedAt, &deniedAt, &consumedAt, &request.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	request.Scopes = strings.Fields(scopes)
	request.State = state.String
	request.Subject = subject.String
	request.GrantedScopes = strings.Fields(grantedScopes.String)
	request.CodeHash = codeHash.String
	request.ApprovedAt = approvedAt.Time
	request.DeniedAt = deniedAt.Time
	request.ConsumedAt = consumedAt.Time

	return request, nil
}

func (self sqlStore) Approve(context context.Context, id string, approval approval, now time.Time) error {
	if !uuidShaped(id) {
		return ErrNotFound
	}

	return self.change(context, `
		UPDATE oauth_authorization_requests
		SET subject = $2, granted_scopes = $3, code_hash = $4, expires_at = $5, approved_at = $6, updated_at = $6
		WHERE id = $1 AND approved_at IS NULL AND denied_at IS NULL AND expires_at > $6`,
		id, approval.Subject, strings.Join(approval.GrantedScopes, " "), approval.CodeHash, approval.ExpiresAt, now,
	)
}

func (self sqlStore) Deny(context context.Context, id string, now time.Time) error {
	if !uuidShaped(id) {
		return ErrNotFound
	}

	return self.change(context, `
		UPDATE oauth_authorization_requests
		SET denied_at = $2, updated_at = $2
		WHERE id = $1 AND approved_at IS NULL AND denied_at IS NULL AND expires_at > $2`,
		id, now,
	)
}

func (self sqlStore) Consume(context context.Context, id string, now time.Time) error {
	return self.change(context, `
		UPDATE oauth_authorization_requests
		SET consumed_at = $2, updated_at = $2
		WHERE id = $1 AND approved_at IS NOT NULL AND consumed_at IS NULL AND expires_at > $2`,
		id, now,
	)
}

const tokenColumns = `id, family, client_id, subject, scopes, resource, access_hash, access_expires_at,
	refresh_hash, refresh_expires_at, rotated_at, revoked_at, created_at`

func (self sqlStore) CreateToken(context context.Context, token *Token) error {
	return self.db().QueryRowContext(context, `
		INSERT INTO oauth_tokens (family, client_id, subject, scopes, resource, access_hash, access_expires_at, refresh_hash, refresh_expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id, created_at`,
		token.Family, token.ClientID, token.Subject, strings.Join(token.Scopes, " "), token.Resource,
		token.AccessHash, token.AccessExpiresAt, nullString(token.RefreshHash), nullTime(token.RefreshExpiresAt),
	).Scan(&token.ID, &token.CreatedAt)
}

func (self sqlStore) FindAccessToken(context context.Context, hash string) (*Token, error) {
	return self.findToken(context, `SELECT `+tokenColumns+` FROM oauth_tokens WHERE access_hash = $1`, hash)
}

func (self sqlStore) FindRefreshToken(context context.Context, hash string) (*Token, error) {
	return self.findToken(context, `SELECT `+tokenColumns+` FROM oauth_tokens WHERE refresh_hash = $1`, hash)
}

func (self sqlStore) findToken(context context.Context, query string, hash string) (*Token, error) {
	token := &Token{}
	var scopes string
	var refreshHash sql.NullString
	var refreshExpiresAt, rotatedAt, revokedAt sql.NullTime

	err := self.db().QueryRowContext(context, query, hash).Scan(
		&token.ID, &token.Family, &token.ClientID, &token.Subject, &scopes, &token.Resource, &token.AccessHash,
		&token.AccessExpiresAt, &refreshHash, &refreshExpiresAt, &rotatedAt, &revokedAt, &token.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	token.Scopes = strings.Fields(scopes)
	token.RefreshHash = refreshHash.String
	token.RefreshExpiresAt = refreshExpiresAt.Time
	token.RotatedAt = rotatedAt.Time
	token.RevokedAt = revokedAt.Time

	return token, nil
}

func (self sqlStore) Rotate(context context.Context, id string, now time.Time) error {
	return self.change(context, `
		UPDATE oauth_tokens SET rotated_at = $2, updated_at = $2
		WHERE id = $1 AND rotated_at IS NULL AND revoked_at IS NULL`,
		id, now,
	)
}

func (self sqlStore) RevokeToken(context context.Context, id string, now time.Time) error {
	return self.revoke(context, `id = $1`, id, now)
}

func (self sqlStore) RevokeFamily(context context.Context, family string, now time.Time) error {
	return self.revoke(context, `family = $1`, family, now)
}

func (self sqlStore) RevokeSubject(context context.Context, subject string, now time.Time) error {
	return self.revoke(context, `subject = $1`, subject, now)
}

func (self sqlStore) revoke(context context.Context, where string, argument string, now time.Time) error {
	_, err := self.db().ExecContext(context,
		`UPDATE oauth_tokens SET revoked_at = $2, updated_at = $2 WHERE `+where+` AND revoked_at IS NULL`,
		argument, now,
	)

	return err
}

// change runs a conditional update and turns "no row matched" into
// ErrNotFound, which is how a store says another request got there first.
func (self sqlStore) change(context context.Context, query string, args ...any) error {
	result, err := self.db().ExecContext(context, query, args...)
	if err != nil {
		return err
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrNotFound
	}

	return nil
}

func nullString(value string) sql.NullString {
	return sql.NullString{String: value, Valid: value != ""}
}

func nullTime(value time.Time) sql.NullTime {
	return sql.NullTime{Time: value, Valid: !value.IsZero()}
}

// uuidShaped keeps an id a person typed into a URL from reaching a uuid
// column, where PostgreSQL would refuse it as an error rather than find
// nothing.
func uuidShaped(value string) bool {
	if len(value) != 36 {
		return false
	}
	for index, character := range value {
		switch index {
		case 8, 13, 18, 23:
			if character != '-' {
				return false
			}
		default:
			if !strings.ContainsRune("0123456789abcdefABCDEF", character) {
				return false
			}
		}
	}

	return true
}
