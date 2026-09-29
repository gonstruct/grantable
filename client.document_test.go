package grantable

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

// documentServer serves a client metadata document over TLS, and counts how
// often it was read.
func documentServer(t *testing.T, cacheControl string, describe func(id string) map[string]any) (*httptest.Server, *atomic.Int32) {
	t.Helper()

	var reads atomic.Int32
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		reads.Add(1)
		if cacheControl != "" {
			writer.Header().Set("Cache-Control", cacheControl)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(encode(describe(server.URL + "/client.json"))))
	}))
	t.Cleanup(server.Close)

	return server, &reads
}

func claude(id string) map[string]any {
	return map[string]any{
		"client_id":     id,
		"client_name":   "Claude",
		"client_uri":    "https://claude.example",
		"redirect_uris": []string{testRedirect},
		"grant_types":   []string{"authorization_code", "refresh_token"},
	}
}

func TestAClientIsItsMetadataDocument(t *testing.T) {
	t.Parallel()

	server, reads := documentServer(t, "", claude)
	fixture := newFixture(t, WithDocumentClient(server.Client()))
	clientID := server.URL + "/client.json"

	pending, err := fixture.server.Pending(t.Context(), fixture.pending(t, authorizeQuery(clientID)))
	if err != nil {
		t.Fatal(err)
	}
	if pending.Client.Name != "Claude" || !pending.Client.Document || pending.DocumentHost() == "" {
		t.Errorf("pending = %+v", pending)
	}

	access, refresh := fixture.tokens(t, clientID, "connection-1", "read")
	if access == "" || refresh == "" {
		t.Errorf("tokens = %q, %q", access, refresh)
	}
	if reads.Load() != 1 {
		t.Errorf("the document was read %d times, not kept", reads.Load())
	}
}

func TestADocumentThatSaysNoStoreIsReadEveryTime(t *testing.T) {
	t.Parallel()

	server, reads := documentServer(t, "no-store", claude)
	fixture := newFixture(t, WithDocumentClient(server.Client()))
	clientID := server.URL + "/client.json"

	fixture.pending(t, authorizeQuery(clientID))
	fixture.pending(t, authorizeQuery(clientID))

	if reads.Load() != 2 {
		t.Errorf("the document was read %d times", reads.Load())
	}
}

func TestADocumentMustNameItself(t *testing.T) {
	t.Parallel()

	cases := map[string]func(id string) map[string]any{
		"another client_id": func(string) map[string]any { return claude("https://elsewhere.example/client.json") },
		"a secret": func(id string) map[string]any {
			document := claude(id)
			document["client_secret"] = "s3cret"

			return document
		},
		"no name": func(id string) map[string]any {
			document := claude(id)
			delete(document, "client_name")

			return document
		},
		"a private key": func(id string) map[string]any {
			document := claude(id)
			document["token_endpoint_auth_method"] = "private_key_jwt"

			return document
		},
	}

	for name, describe := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			server, _ := documentServer(t, "", describe)
			fixture := newFixture(t, WithDocumentClient(server.Client()))

			if recorder := fixture.authorize(t, authorizeQuery(server.URL+"/client.json")); recorder.Code != http.StatusBadRequest {
				t.Errorf("authorize answered %d", recorder.Code)
			}
		})
	}
}

func TestADocumentIsNotFetchedFromThisNetwork(t *testing.T) {
	t.Parallel()

	server, reads := documentServer(t, "", claude)
	fixture := newFixture(t)

	if recorder := fixture.authorize(t, authorizeQuery(server.URL+"/client.json")); recorder.Code != http.StatusBadRequest {
		t.Errorf("authorize answered %d", recorder.Code)
	}
	if reads.Load() != 0 {
		t.Error("a loopback document was fetched")
	}
}

func TestOnlyAnHTTPSURLWithAPathIsADocument(t *testing.T) {
	t.Parallel()

	for id, want := range map[string]bool{
		"https://claude.example/oauth/client.json": true,
		"https://claude.example":                   false,
		"https://claude.example/":                  false,
		"http://claude.example/client.json":        false,
		"https://user@claude.example/client.json":  false,
		"https://claude.example/a/../client.json":  false,
		"https://claude.example/client.json#x":     false,
		"tp_c_0123":                                false,
	} {
		if documentID(id) != want {
			t.Errorf("documentID(%q) = %v", id, !want)
		}
	}
}

func TestTheCacheHeaderBoundsHowLongADocumentIsKept(t *testing.T) {
	t.Parallel()

	for header, want := range map[string]time.Duration{
		"":                       24 * time.Hour,
		"max-age=600":            10 * time.Minute,
		"public, max-age=999999": 24 * time.Hour,
		"no-store":               0,
		"no-cache, max-age=600":  0,
	} {
		if got := documentLifetime(header, 24*time.Hour); got != want {
			t.Errorf("documentLifetime(%q) = %s, want %s", header, got, want)
		}
	}
}

func TestOnlyPublicAddressesArePublic(t *testing.T) {
	t.Parallel()

	for address, want := range map[string]bool{
		"93.184.216.34":    true,
		"127.0.0.1":        false,
		"10.1.2.3":         false,
		"192.168.1.1":      false,
		"169.254.169.254":  false,
		"100.64.0.1":       false,
		"0.0.0.0":          false,
		"::1":              false,
		"fd00::1":          false,
		"::ffff:127.0.0.1": false,
		"2606:4700::1111":  true,
	} {
		if got := public(netip.MustParseAddr(address)); got != want {
			t.Errorf("public(%s) = %v", address, got)
		}
	}
}
