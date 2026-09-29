package grantable

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestACodeIsExchangedOnlyWithItsVerifier(t *testing.T) {
	t.Parallel()

	fixture := newFixture(t)
	clientID := fixture.publicClient(t)
	form := exchangeForm(clientID, fixture.code(t, clientID, "connection-1", "read"))
	form.Set("code_verifier", strings.Repeat("x", 64))

	status, answer := fixture.token(t, form)
	if status != http.StatusBadRequest || answer["error"] != CodeInvalidGrant {
		t.Errorf("exchange with the wrong verifier answered %d: %v", status, answer)
	}
}

func TestACodeIsForTheClientItWasIssuedTo(t *testing.T) {
	t.Parallel()

	fixture := newFixture(t)
	code := fixture.code(t, fixture.publicClient(t), "connection-1", "read")

	status, answer := fixture.token(t, exchangeForm(fixture.publicClient(t), code))
	if status != http.StatusBadRequest || answer["error"] != CodeInvalidGrant {
		t.Errorf("another client's exchange answered %d: %v", status, answer)
	}
}

func TestACodeUsedTwiceRevokesWhatTheFirstUseGave(t *testing.T) {
	t.Parallel()

	fixture := newFixture(t)
	clientID := fixture.publicClient(t)
	form := exchangeForm(clientID, fixture.code(t, clientID, "connection-1", "read"))

	status, answer := fixture.token(t, form)
	if status != http.StatusOK {
		t.Fatalf("first exchange answered %d: %v", status, answer)
	}

	if status, again := fixture.token(t, form); status != http.StatusBadRequest || again["error"] != CodeInvalidGrant {
		t.Errorf("second exchange answered %d: %v", status, again)
	}
	if _, err := fixture.server.Verify(t.Context(), answer["access_token"].(string), testResource); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("the first exchange's token survived: %v", err)
	}
}

func TestARefreshGivesANewPairAndSpendsTheOld(t *testing.T) {
	t.Parallel()

	fixture := newFixture(t)
	clientID := fixture.publicClient(t)
	access, refresh := fixture.tokens(t, clientID, "connection-1", "read", "build")

	status, answer := fixture.token(t, refreshForm(clientID, refresh))
	if status != http.StatusOK || answer["refresh_token"] == refresh || answer["scope"] != "read build" {
		t.Fatalf("refresh answered %d: %v", status, answer)
	}

	if _, err := fixture.server.Verify(t.Context(), access, testResource); err != nil {
		t.Errorf("the old access token died with the refresh: %v", err)
	}
	if _, err := fixture.server.Verify(t.Context(), answer["access_token"].(string), testResource); err != nil {
		t.Errorf("the new access token: %v", err)
	}
}

func TestARefreshTokenUsedTwiceRevokesTheWholeFamily(t *testing.T) {
	t.Parallel()

	fixture := newFixture(t)
	clientID := fixture.publicClient(t)
	_, refresh := fixture.tokens(t, clientID, "connection-1", "read")

	_, rotated := fixture.token(t, refreshForm(clientID, refresh))

	if status, answer := fixture.token(t, refreshForm(clientID, refresh)); status != http.StatusBadRequest || answer["error"] != CodeInvalidGrant {
		t.Errorf("reusing a spent refresh token answered %d: %v", status, answer)
	}
	if _, err := fixture.server.Verify(t.Context(), rotated["access_token"].(string), testResource); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("the rotated access token survived the reuse: %v", err)
	}
	if status, _ := fixture.token(t, refreshForm(clientID, rotated["refresh_token"].(string))); status != http.StatusBadRequest {
		t.Errorf("the rotated refresh token survived the reuse: %d", status)
	}
}

func TestARefreshMayNarrowButNeverWiden(t *testing.T) {
	t.Parallel()

	fixture := newFixture(t)
	clientID := fixture.publicClient(t)
	_, refresh := fixture.tokens(t, clientID, "connection-1", "read")

	form := refreshForm(clientID, refresh)
	form.Set("scope", "read build")
	if status, answer := fixture.token(t, form); status != http.StatusBadRequest || answer["error"] != CodeInvalidScope {
		t.Errorf("widening answered %d: %v", status, answer)
	}
}

func TestARefreshFollowsTheGrant(t *testing.T) {
	t.Parallel()

	fixture := newFixture(t)
	clientID := fixture.publicClient(t)
	_, refresh := fixture.tokens(t, clientID, "connection-1", "read", "build")

	fixture.grants.set("connection-1", "read")
	status, answer := fixture.token(t, refreshForm(clientID, refresh))
	if status != http.StatusOK || answer["scope"] != "read" {
		t.Errorf("refresh after narrowing answered %d: %v", status, answer)
	}
}

func TestAConfidentialClientAuthenticatesWithItsSecret(t *testing.T) {
	t.Parallel()

	fixture := newFixture(t)
	registered := fixture.register(t, map[string]any{
		"client_name":                "Server app",
		"redirect_uris":              []string{testRedirect},
		"token_endpoint_auth_method": "client_secret_basic",
	})
	clientID, secret := registered["client_id"].(string), registered["client_secret"].(string)
	if !strings.HasPrefix(secret, "tp_cs_") || registered["client_secret_expires_at"] != float64(0) {
		t.Fatalf("registered = %v", registered)
	}

	code := fixture.code(t, clientID, "connection-1", "read")
	form := exchangeForm(clientID, code)
	form.Del("client_id")

	request := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth(url.QueryEscape(clientID), "wrong")
	if recorder := fixture.serve(fixture.server.Token(), request); recorder.Code != http.StatusUnauthorized {
		t.Errorf("the wrong secret answered %d", recorder.Code)
	}

	request = httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(secret))
	if recorder := fixture.serve(fixture.server.Token(), request); recorder.Code != http.StatusOK {
		t.Errorf("the right secret answered %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestRevokingARefreshTokenEndsItsFamily(t *testing.T) {
	t.Parallel()

	fixture := newFixture(t)
	clientID := fixture.publicClient(t)
	access, refresh := fixture.tokens(t, clientID, "connection-1", "read")

	form := url.Values{"client_id": {clientID}, "token": {refresh}}
	request := httptest.NewRequest(http.MethodPost, "/oauth/revoke", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if recorder := fixture.serve(fixture.server.Revoke(), request); recorder.Code != http.StatusOK {
		t.Fatalf("revoke answered %d: %s", recorder.Code, recorder.Body.String())
	}
	if _, err := fixture.server.Verify(t.Context(), access, testResource); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("the access token survived: %v", err)
	}
}

func TestRegistrationRefusesWhatItCannotServe(t *testing.T) {
	t.Parallel()

	cases := map[string]map[string]any{
		"no redirect":       {"client_name": "A"},
		"an http redirect":  {"redirect_uris": []string{"http://client.example/cb"}},
		"a bare scheme":     {"redirect_uris": []string{"myapp:/cb"}},
		"implicit":          {"redirect_uris": []string{testRedirect}, "grant_types": []string{"implicit"}},
		"a private key":     {"redirect_uris": []string{testRedirect}, "token_endpoint_auth_method": "private_key_jwt"},
		"a javascript logo": {"redirect_uris": []string{testRedirect}, "logo_uri": "javascript:alert(1)"},
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fixture := newFixture(t)
			request := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(encode(body)))

			if recorder := fixture.serve(fixture.server.Register(), request); recorder.Code != http.StatusBadRequest {
				t.Errorf("register answered %d: %s", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestANativeAppRegistersItsOwnScheme(t *testing.T) {
	t.Parallel()

	fixture := newFixture(t)
	registered := fixture.register(t, map[string]any{"client_name": "Desktop", "redirect_uris": []string{"com.example.desktop:/oauth/callback"}})

	if registered["token_endpoint_auth_method"] != "none" || registered["client_secret"] != nil {
		t.Errorf("registered = %v", registered)
	}
}
