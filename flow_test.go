package grantable

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
)

func TestTheWholeFlowEndsInATokenTheResourceTakes(t *testing.T) {
	t.Parallel()

	fixture := newFixture(t)
	clientID := fixture.publicClient(t)
	id := fixture.pending(t, authorizeQuery(clientID))

	pending, err := fixture.server.Pending(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	if pending.Client.Name != "Test client" || pending.RedirectHost() != "client.example" || !slices.Equal(pending.Scopes, []string{"read", "build"}) {
		t.Errorf("pending = %+v", pending)
	}

	fixture.grants.set("connection-1", "read", "build", "run")
	redirect, err := fixture.server.Approve(t.Context(), id, "connection-1", []string{"read", "run"})
	if err != nil {
		t.Fatal(err)
	}

	location, _ := url.Parse(redirect)
	if location.Host != "client.example" || location.Query().Get("state") != "the-state" || location.Query().Get("iss") != testIssuer {
		t.Errorf("redirect = %s", redirect)
	}
	if !strings.HasPrefix(location.Query().Get("code"), "tp_ac_") {
		t.Errorf("code = %q", location.Query().Get("code"))
	}

	status, answer := fixture.token(t, exchangeForm(clientID, location.Query().Get("code")))
	if status != http.StatusOK {
		t.Fatalf("exchange answered %d: %v", status, answer)
	}
	if answer["token_type"] != "Bearer" || answer["scope"] != "read run" || answer["expires_in"] != float64(3600) {
		t.Errorf("tokens = %v", answer)
	}

	access := answer["access_token"].(string)
	verified, err := fixture.server.Verify(t.Context(), access, testResource)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Subject != "connection-1" || !verified.Can("read", "run") || verified.Can("build") {
		t.Errorf("verified = %+v", verified)
	}
}

func TestATokenIsForItsResourceOnly(t *testing.T) {
	t.Parallel()

	fixture := newFixture(t)
	access, _ := fixture.tokens(t, fixture.publicClient(t), "connection-1", "read")

	if _, err := fixture.server.Verify(t.Context(), access, "https://api.example/other"); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("verify for another resource = %v", err)
	}
	if _, err := fixture.server.Verify(t.Context(), access, "HTTPS://API.EXAMPLE/mcp/"); err != nil {
		t.Errorf("verify for the same resource, written differently = %v", err)
	}
}

func TestAGrantNarrowedNarrowsItsTokensAtOnce(t *testing.T) {
	t.Parallel()

	fixture := newFixture(t)
	access, _ := fixture.tokens(t, fixture.publicClient(t), "connection-1", "read", "build")

	fixture.grants.set("connection-1", "read")
	verified, err := fixture.server.Verify(t.Context(), access, testResource)
	if err != nil || !slices.Equal(verified.Scopes, []string{"read"}) {
		t.Errorf("verified = %+v, %v", verified, err)
	}

	fixture.grants.set("connection-1")
	if _, err := fixture.server.Verify(t.Context(), access, testResource); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("verify with a grant that allows nothing = %v", err)
	}
}

func TestRevokingASubjectRevokesItsTokens(t *testing.T) {
	t.Parallel()

	fixture := newFixture(t)
	clientID := fixture.publicClient(t)
	access, refresh := fixture.tokens(t, clientID, "connection-1", "read")
	other, _ := fixture.tokens(t, clientID, "connection-2", "read")

	if err := fixture.server.RevokeSubject(t.Context(), "connection-1"); err != nil {
		t.Fatal(err)
	}

	if _, err := fixture.server.Verify(t.Context(), access, testResource); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("verify after revoking = %v", err)
	}
	if status, _ := fixture.token(t, refreshForm(clientID, refresh)); status != http.StatusBadRequest {
		t.Errorf("refresh after revoking answered %d", status)
	}
	if _, err := fixture.server.Verify(t.Context(), other, testResource); err != nil {
		t.Errorf("another subject's token = %v", err)
	}
}

func TestTheMetadataSaysWhatTheServerDoes(t *testing.T) {
	t.Parallel()

	fixture := newFixture(t)
	metadata := fixture.server.Metadata()

	if metadata.Issuer != testIssuer || metadata.TokenEndpoint != testIssuer+"/oauth/token" || metadata.RegistrationEndpoint != testIssuer+"/oauth/register" {
		t.Errorf("metadata = %+v", metadata)
	}
	if !metadata.ClientIDMetadataDocumentSupported || !metadata.AuthorizationResponseIssParameterSupported {
		t.Errorf("metadata = %+v", metadata)
	}
	if !slices.Equal(metadata.CodeChallengeMethodsSupported, []string{"S256"}) {
		t.Errorf("metadata = %+v", metadata)
	}

	closed := newFixture(t, WithoutRegistration())
	if closed.server.Metadata().RegistrationEndpoint != "" {
		t.Error("a closed registration is advertised")
	}
}

func TestTheResourceMetadataLivesUnderTheResourcePath(t *testing.T) {
	t.Parallel()

	if got := ResourceMetadataURL(testResource); got != "https://api.example/.well-known/oauth-protected-resource/mcp" {
		t.Errorf("ResourceMetadataURL = %s", got)
	}

	fixture := newFixture(t)
	recorder := fixture.serve(fixture.server.ResourceMetadataHandler(testResource), newGet("/.well-known/oauth-protected-resource/mcp"))

	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"authorization_servers":["https://api.example"]`) {
		t.Errorf("resource metadata answered %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestAChallengeNamesTheMetadataAndTheScope(t *testing.T) {
	t.Parallel()

	fixture := newFixture(t)
	got := fixture.server.Challenge(testResource, Challenge{Error: "insufficient_scope", Scopes: []string{"build"}})

	want := `Bearer resource_metadata="https://api.example/.well-known/oauth-protected-resource/mcp", error="insufficient_scope", scope="build"`
	if got != want {
		t.Errorf("challenge = %s", got)
	}
}

func TestABearerTokenIsReadFromTheHeaderOnly(t *testing.T) {
	t.Parallel()

	request := newGet("/mcp?access_token=nope")
	if BearerToken(request) != "" {
		t.Error("read a token from the query")
	}

	request.Header.Set("Authorization", "bearer the-token")
	if BearerToken(request) != "the-token" {
		t.Errorf("BearerToken = %q", BearerToken(request))
	}
}
