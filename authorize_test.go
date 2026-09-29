package grantable

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func newGet(target string) *http.Request {
	return httptest.NewRequest(http.MethodGet, target, nil)
}

func TestAnUnknownClientIsToldNotRedirected(t *testing.T) {
	t.Parallel()

	fixture := newFixture(t)
	recorder := fixture.authorize(t, authorizeQuery("tp_c_nobody"))

	if recorder.Code != http.StatusBadRequest || recorder.Header().Get("Location") != "" {
		t.Errorf("authorize answered %d to %q", recorder.Code, recorder.Header().Get("Location"))
	}
}

func TestARedirectTheClientDidNotRegisterIsToldNotRedirected(t *testing.T) {
	t.Parallel()

	fixture := newFixture(t)
	query := authorizeQuery(fixture.publicClient(t))
	query.Set("redirect_uri", "https://attacker.example/callback")

	recorder := fixture.authorize(t, query)
	if recorder.Code != http.StatusBadRequest || recorder.Header().Get("Location") != "" {
		t.Errorf("authorize answered %d to %q", recorder.Code, recorder.Header().Get("Location"))
	}
}

func TestWhatIsWrongWithARequestGoesBackToTheClient(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		change func(url.Values)
		code   string
	}{
		"no PKCE":                {func(query url.Values) { query.Del("code_challenge") }, CodeInvalidRequest},
		"plain PKCE":             {func(query url.Values) { query.Set("code_challenge_method", "plain") }, CodeInvalidRequest},
		"a token response":       {func(query url.Values) { query.Set("response_type", "token") }, CodeUnsupportedResponseType},
		"another resource":       {func(query url.Values) { query.Set("resource", "https://elsewhere.example/mcp") }, CodeInvalidTarget},
		"a scope not offered":    {func(query url.Values) { query.Set("scope", "read admin") }, CodeInvalidScope},
		"a short PKCE challenge": {func(query url.Values) { query.Set("code_challenge", "short") }, CodeInvalidRequest},
	}

	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fixture := newFixture(t)
			query := authorizeQuery(fixture.publicClient(t))
			testCase.change(query)

			recorder := fixture.authorize(t, query)
			location, _ := url.Parse(recorder.Header().Get("Location"))

			if recorder.Code != http.StatusFound || location.Host != "client.example" {
				t.Fatalf("authorize answered %d to %s", recorder.Code, location)
			}
			if location.Query().Get("error") != testCase.code || location.Query().Get("state") != "the-state" || location.Query().Get("iss") != testIssuer {
				t.Errorf("redirect = %s", location)
			}
		})
	}
}

func TestARequestWithoutScopesAsksForAllOfThem(t *testing.T) {
	t.Parallel()

	fixture := newFixture(t)
	query := authorizeQuery(fixture.publicClient(t))
	query.Del("scope")
	query.Del("resource")

	pending, err := fixture.server.Pending(t.Context(), fixture.pending(t, query))
	if err != nil {
		t.Fatal(err)
	}
	if len(pending.Scopes) != 3 || pending.Resource != testResource {
		t.Errorf("pending = %+v", pending)
	}
}

func TestALoopbackRedirectMayComeBackOnAnyPort(t *testing.T) {
	t.Parallel()

	fixture := newFixture(t)
	clientID := fixture.register(t, map[string]any{"client_name": "CLI", "redirect_uris": []string{"http://127.0.0.1/callback"}})["client_id"].(string)

	query := authorizeQuery(clientID)
	query.Set("redirect_uri", "http://127.0.0.1:53682/callback")

	pending, err := fixture.server.Pending(t.Context(), fixture.pending(t, query))
	if err != nil {
		t.Fatal(err)
	}
	if !pending.Loopback() || pending.RedirectURI != "http://127.0.0.1:53682/callback" {
		t.Errorf("pending = %+v", pending)
	}

	query.Set("redirect_uri", "http://127.0.0.1:53682/elsewhere")
	if recorder := fixture.authorize(t, query); recorder.Code != http.StatusBadRequest {
		t.Errorf("another path on loopback answered %d", recorder.Code)
	}
}

func TestARequestIsAnsweredOnce(t *testing.T) {
	t.Parallel()

	fixture := newFixture(t)
	id := fixture.pending(t, authorizeQuery(fixture.publicClient(t)))

	if _, err := fixture.server.Approve(t.Context(), id, "connection-1", []string{"read"}); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.server.Approve(t.Context(), id, "connection-1", []string{"read"}); !errors.Is(err, ErrRequestUnavailable) {
		t.Errorf("approving twice = %v", err)
	}
	if _, err := fixture.server.Deny(t.Context(), id); !errors.Is(err, ErrRequestUnavailable) {
		t.Errorf("denying an approved request = %v", err)
	}
	if _, err := fixture.server.Pending(t.Context(), id); !errors.Is(err, ErrRequestUnavailable) {
		t.Errorf("an approved request is still pending: %v", err)
	}
}

func TestApprovingGrantsOnlyOfferedScopes(t *testing.T) {
	t.Parallel()

	fixture := newFixture(t)
	id := fixture.pending(t, authorizeQuery(fixture.publicClient(t)))

	if _, err := fixture.server.Approve(t.Context(), id, "connection-1", nil); !errors.Is(err, ErrScopes) {
		t.Errorf("approving nothing = %v", err)
	}
	if _, err := fixture.server.Approve(t.Context(), id, "connection-1", []string{"read", "admin"}); !errors.Is(err, ErrScopes) {
		t.Errorf("approving a scope not offered = %v", err)
	}
}

func TestDenyingSendsTheClientAccessDenied(t *testing.T) {
	t.Parallel()

	fixture := newFixture(t)
	redirect, err := fixture.server.Deny(t.Context(), fixture.pending(t, authorizeQuery(fixture.publicClient(t))))
	if err != nil {
		t.Fatal(err)
	}

	location, _ := url.Parse(redirect)
	if location.Query().Get("error") != CodeAccessDenied || location.Query().Get("state") != "the-state" {
		t.Errorf("redirect = %s", redirect)
	}
}
