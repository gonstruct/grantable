package grantable

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

const (
	testIssuer   = "https://api.example"
	testResource = "https://api.example/mcp"
	testRedirect = "https://client.example/callback"
	testVerifier = "a-verifier-that-is-long-enough-to-be-a-real-pkce-verifier-0123"
)

// grants is an application's grants in a map: what each subject allows.
type grants struct {
	mutex   sync.Mutex
	allowed map[string][]string
}

func (self *grants) set(subject string, scopes ...string) {
	self.mutex.Lock()
	defer self.mutex.Unlock()

	self.allowed[subject] = scopes
}

func (self *grants) scopes(_ context.Context, subject string) ([]string, error) {
	self.mutex.Lock()
	defer self.mutex.Unlock()

	return self.allowed[subject], nil
}

type fixture struct {
	server *Server
	grants *grants
}

func newFixture(t *testing.T, options ...option) *fixture {
	t.Helper()

	allowed := &grants{allowed: map[string][]string{}}

	server := New(append([]option{
		WithIssuer(testIssuer),
		WithStore(Memory()),
		WithResource(Resource{URL: testResource, Name: "Test MCP"}),
		WithScopes("read", "build", "run"),
		WithConsentURL(func(id string) string { return "https://app.example/oauth/authorize?request=" + id }),
		WithGrants(allowed.scopes),
		WithPrefix("tp_"),
	}, options...)...)

	return &fixture{server: server, grants: allowed}
}

func (self *fixture) serve(handler http.Handler, request *http.Request) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	return recorder
}

// register makes a public client through dynamic registration.
func (self *fixture) register(t *testing.T, body map[string]any) map[string]any {
	t.Helper()

	request := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(encode(body)))

	recorder := self.serve(self.server.Register(), request)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("register answered %d: %s", recorder.Code, recorder.Body.String())
	}

	answer := map[string]any{}
	_ = json.Unmarshal(recorder.Body.Bytes(), &answer)

	return answer
}

func (self *fixture) publicClient(t *testing.T) string {
	t.Helper()

	return self.register(t, map[string]any{"client_name": "Test client", "redirect_uris": []string{testRedirect}})["client_id"].(string)
}

func challenge(verifier string) string {
	digest := sha256.Sum256([]byte(verifier))

	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func authorizeQuery(clientID string) url.Values {
	return url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {testRedirect},
		"code_challenge":        {challenge(testVerifier)},
		"code_challenge_method": {"S256"},
		"resource":              {testResource},
		"state":                 {"the-state"},
		"scope":                 {"read build"},
	}
}

func (self *fixture) authorize(t *testing.T, query url.Values) *httptest.ResponseRecorder {
	t.Helper()

	return self.serve(self.server.Authorize(), httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+query.Encode(), nil))
}

// pending authorizes and answers the id of the request waiting on consent.
func (self *fixture) pending(t *testing.T, query url.Values) string {
	t.Helper()

	recorder := self.authorize(t, query)
	if recorder.Code != http.StatusFound {
		t.Fatalf("authorize answered %d: %s", recorder.Code, recorder.Body.String())
	}

	location, _ := url.Parse(recorder.Header().Get("Location"))
	id := location.Query().Get("request")
	if location.Host != "app.example" || id == "" {
		t.Fatalf("authorize went to %s, not the consent page", location)
	}

	return id
}

// code runs the flow up to an approved code for subject.
func (self *fixture) code(t *testing.T, clientID, subject string, scopes ...string) string {
	t.Helper()

	self.grants.set(subject, "read", "build", "run")

	redirect, err := self.server.Approve(t.Context(), self.pending(t, authorizeQuery(clientID)), subject, scopes)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}

	location, _ := url.Parse(redirect)

	return location.Query().Get("code")
}

func (self *fixture) token(t *testing.T, form url.Values) (int, map[string]any) {
	t.Helper()

	request := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	recorder := self.serve(self.server.Token(), request)
	answer := map[string]any{}
	_ = json.Unmarshal(recorder.Body.Bytes(), &answer)

	return recorder.Code, answer
}

func exchangeForm(clientID, code string) url.Values {
	return url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {clientID},
		"code":          {code},
		"code_verifier": {testVerifier},
		"redirect_uri":  {testRedirect},
		"resource":      {testResource},
	}
}

// tokens runs the whole flow and answers the access and refresh tokens.
func (self *fixture) tokens(t *testing.T, clientID, subject string, scopes ...string) (string, string) {
	t.Helper()

	status, answer := self.token(t, exchangeForm(clientID, self.code(t, clientID, subject, scopes...)))
	if status != http.StatusOK {
		t.Fatalf("exchange answered %d: %v", status, answer)
	}

	refresh, _ := answer["refresh_token"].(string)

	return answer["access_token"].(string), refresh
}

func refreshForm(clientID, refresh string) url.Values {
	return url.Values{"grant_type": {"refresh_token"}, "client_id": {clientID}, "refresh_token": {refresh}}
}

func encode(body any) string {
	encoded, _ := json.Marshal(body)

	return string(encoded)
}
