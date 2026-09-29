package grantable

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// TokenResponse is RFC 6749 section 5.1's answer.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope"`
}

// Token is the token endpoint: a code for tokens, or a refresh token for
// new ones.
func (self *Server) Token() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			writeError(writer, refuse(http.StatusMethodNotAllowed, CodeInvalidRequest, "Ask for tokens with POST."))
			return
		}
		if err := request.ParseForm(); err != nil {
			writeError(writer, invalidRequest("The body is not a form."))
			return
		}

		client, err := self.authenticate(request)
		if err != nil {
			self.fail(writer, request, err)
			return
		}

		var tokens TokenResponse
		switch request.PostForm.Get("grant_type") {
		case grantCode:
			tokens, err = self.exchange(request, client)
		case grantRefresh:
			tokens, err = self.refresh(request, client)
		default:
			err = refuse(http.StatusBadRequest, CodeUnsupportedGrantType, "The grant_type is authorization_code or refresh_token.")
		}
		if err != nil {
			self.fail(writer, request, err)
			return
		}

		writeJSON(writer, http.StatusOK, tokens)
	})
}

// exchange spends a code. A code spent twice is a code someone else has,
// so the second time also revokes every token the first one gave.
func (self *Server) exchange(request *http.Request, client *Client) (TokenResponse, error) {
	form := request.PostForm
	context := request.Context()
	store := self.settings().Store
	now := self.now()

	code := form.Get("code")
	if code == "" || form.Get("code_verifier") == "" {
		return TokenResponse{}, invalidRequest("The code and the code_verifier are required.")
	}

	approved, err := store.FindRequestByCode(context, Hash(code))
	if errors.Is(err, ErrNotFound) {
		return TokenResponse{}, invalidGrant("The code is not one this server issued.")
	}
	if err != nil {
		return TokenResponse{}, err
	}

	if !approved.ConsumedAt.IsZero() {
		if err := store.RevokeFamily(context, approved.ID, now); err != nil {
			return TokenResponse{}, err
		}

		return TokenResponse{}, invalidGrant("The code was already used.")
	}

	if err := redeemable(approved, client, form, now); err != nil {
		return TokenResponse{}, err
	}

	if err := store.Consume(context, approved.ID, now); errors.Is(err, ErrNotFound) {
		return TokenResponse{}, invalidGrant("The code was already used.")
	} else if err != nil {
		return TokenResponse{}, err
	}

	scopes, err := self.grantedScopes(context, approved.Subject, approved.GrantedScopes)
	if err != nil {
		return TokenResponse{}, err
	}
	if len(scopes) == 0 {
		return TokenResponse{}, invalidGrant("The connection no longer allows anything.")
	}

	return self.issue(context, &Token{
		Family:   approved.ID,
		ClientID: client.ID,
		Subject:  approved.Subject,
		Scopes:   scopes,
		Resource: approved.Resource,
	}, client.allowsGrant(grantRefresh), now)
}

// refresh trades a refresh token for a new pair and spends it. One
// presented after it was spent is a copy someone else holds: the whole
// family is revoked, the client's own tokens with it.
func (self *Server) refresh(request *http.Request, client *Client) (TokenResponse, error) {
	form := request.PostForm
	context := request.Context()
	store := self.settings().Store
	now := self.now()

	if !client.allowsGrant(grantRefresh) {
		return TokenResponse{}, refuse(http.StatusBadRequest, CodeUnauthorizedClient, "The client may not use refresh tokens.")
	}

	presented := form.Get("refresh_token")
	if presented == "" {
		return TokenResponse{}, invalidRequest("The refresh_token is required.")
	}

	current, err := store.FindRefreshToken(context, Hash(presented))
	if errors.Is(err, ErrNotFound) {
		return TokenResponse{}, invalidGrant("The refresh token is not one this server issued.")
	}
	if err != nil {
		return TokenResponse{}, err
	}
	if current.ClientID != client.ID {
		return TokenResponse{}, invalidGrant("The refresh token was issued to another client.")
	}
	if !current.RotatedAt.IsZero() {
		return TokenResponse{}, self.reused(context, current.Family, now)
	}
	if !current.refreshable(now) {
		return TokenResponse{}, invalidGrant("The refresh token has expired or was revoked.")
	}
	if form.Get("resource") != "" && canonical(form.Get("resource")) != canonical(current.Resource) {
		return TokenResponse{}, invalidTarget("The resource is not the one the refresh token was issued for.")
	}

	scopes, err := self.refreshedScopes(context, current, form.Get("scope"))
	if err != nil {
		return TokenResponse{}, err
	}

	if err := store.Rotate(context, current.ID, now); errors.Is(err, ErrNotFound) {
		return TokenResponse{}, self.reused(context, current.Family, now)
	} else if err != nil {
		return TokenResponse{}, err
	}

	return self.issue(context, &Token{
		Family:   current.Family,
		ClientID: client.ID,
		Subject:  current.Subject,
		Scopes:   scopes,
		Resource: current.Resource,
	}, true, now)
}

// redeemable is whether the code may be exchanged by this client with this
// form: its own, in time, for the redirect and the resource it was issued
// for, and with the verifier its challenge was made from.
func redeemable(approved *Request, client *Client, form url.Values, now time.Time) error {
	switch {
	case approved.ClientID != client.ID:
		return invalidGrant("The code was issued to another client.")
	case !now.Before(approved.ExpiresAt):
		return invalidGrant("The code has expired.")
	case form.Get("redirect_uri") != "" && form.Get("redirect_uri") != approved.RedirectURI:
		return invalidGrant("The redirect_uri is not the one the code was sent to.")
	case form.Get("resource") != "" && canonical(form.Get("resource")) != canonical(approved.Resource):
		return invalidTarget("The resource is not the one the code was issued for.")
	case !verifyChallenge(form.Get("code_verifier"), approved.CodeChallenge):
		return invalidGrant("The code_verifier does not match the code_challenge.")
	default:
		return nil
	}
}

// refreshedScopes is what a refresh gives: what the token had and its grant
// still allows, or the fewer the client asks for.
func (self *Server) refreshedScopes(context context.Context, current *Token, requested string) ([]string, error) {
	scopes, err := self.grantedScopes(context, current.Subject, current.Scopes)
	if err != nil {
		return nil, err
	}

	if narrower := strings.Fields(requested); len(narrower) > 0 {
		if !covers(scopes, narrower) {
			return nil, invalidScope("A refresh cannot add scopes.")
		}
		scopes = narrower
	}
	if len(scopes) == 0 {
		return nil, invalidGrant("The connection no longer allows anything.")
	}

	return scopes, nil
}

func (self *Server) reused(context context.Context, family string, now time.Time) error {
	if err := self.settings().Store.RevokeFamily(context, family, now); err != nil {
		return err
	}

	return invalidGrant("The refresh token was already used.")
}

func (self *Server) issue(context context.Context, token *Token, withRefresh bool, now time.Time) (TokenResponse, error) {
	settings := self.settings()

	access := secret(settings.Prefix, accessTokenKind)
	token.AccessHash = Hash(access)
	token.AccessExpiresAt = now.Add(settings.Lifetimes.Access)

	refresh := ""
	if withRefresh {
		refresh = secret(settings.Prefix, refreshTokenKind)
		token.RefreshHash = Hash(refresh)
		token.RefreshExpiresAt = now.Add(settings.Lifetimes.Refresh)
	}

	if err := settings.Store.CreateToken(context, token); err != nil {
		return TokenResponse{}, err
	}

	return TokenResponse{
		AccessToken:  access,
		TokenType:    "Bearer",
		ExpiresIn:    int64(settings.Lifetimes.Access.Seconds()),
		RefreshToken: refresh,
		Scope:        strings.Join(token.Scopes, " "),
	}, nil
}
