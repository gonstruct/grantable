package grantable

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

const (
	authNone      = "none"
	authBasic     = "client_secret_basic"
	authPost      = "client_secret_post"
	grantCode     = "authorization_code"
	grantRefresh  = "refresh_token"
	responseCode  = "code"
	loopbackLocal = "localhost"
)

// client finds the client a request names: a registered one by its id, or
// the one a metadata document describes, read now when it was never read
// or has gone stale.
func (self *Server) client(context context.Context, id string) (*Client, error) {
	if id == "" {
		return nil, invalidClient("A client_id is required.")
	}

	store, err := self.store()
	if err != nil {
		return nil, err
	}

	client, err := store.FindClient(context, id)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}

	if !documentID(id) {
		if client == nil {
			return nil, invalidClient("The client is not registered.")
		}

		return client, nil
	}

	if client != nil && self.now().Before(client.DocumentExpiresAt) {
		return client, nil
	}

	return self.fetchDocument(context, id)
}

// authenticate is the token and revocation endpoints' check that the
// caller is the client it says: a public client by its id alone, a
// confidential one by its secret, in the header or the form, the way it
// registered.
func (self *Server) authenticate(request *http.Request) (*Client, error) {
	id := request.PostForm.Get("client_id")
	secret := request.PostForm.Get("client_secret")
	method := authPost

	if username, password, ok := request.BasicAuth(); ok {
		decodedID, idErr := url.QueryUnescape(username)
		decodedSecret, secretErr := url.QueryUnescape(password)
		if idErr != nil || secretErr != nil {
			return nil, invalidClient("The Authorization header is malformed.")
		}
		if id != "" && id != decodedID {
			return nil, invalidRequest("The client_id does not match the Authorization header.")
		}
		id, secret, method = decodedID, decodedSecret, authBasic
	}

	client, err := self.client(request.Context(), id)
	if err != nil {
		return nil, err
	}

	if client.AuthMethod == authNone {
		if secret != "" {
			return nil, invalidClient("The client is public and has no secret.")
		}

		return client, nil
	}

	if client.AuthMethod != method || secret == "" || !equalHash(secret, client.SecretHash) {
		return nil, invalidClient("The client credentials are invalid.")
	}

	return client, nil
}

// allowsRedirect is exact matching of the redirect URI, but for a loopback
// one, where the port is whatever the native client found free (RFC 8252
// section 7.3).
func (self *Client) allowsRedirect(candidate string) bool {
	if slices.Contains(self.RedirectURIs, candidate) {
		return true
	}

	asked, err := url.Parse(candidate)
	if err != nil || asked.Scheme != "http" || !loopback(asked.Hostname()) {
		return false
	}

	for _, registered := range self.RedirectURIs {
		allowed, err := url.Parse(registered)
		if err != nil || allowed.Scheme != "http" || !loopback(allowed.Hostname()) {
			continue
		}
		if allowed.Hostname() == asked.Hostname() && allowed.Path == asked.Path && allowed.RawQuery == asked.RawQuery {
			return true
		}
	}

	return false
}

func (self *Client) allowsGrant(grant string) bool {
	return slices.Contains(self.GrantTypes, grant)
}

// validRedirectURI is what a client may register as a redirect: HTTPS, a
// loopback address over HTTP, or a native app's private-use scheme, in
// reverse domain notation (RFC 8252 section 7.1). Never a fragment.
func validRedirectURI(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || !parsed.IsAbs() || parsed.Fragment != "" || strings.TrimSpace(raw) != raw {
		return invalidRedirectURI("A redirect URI is absolute and has no fragment: " + raw)
	}

	switch scheme := strings.ToLower(parsed.Scheme); {
	case scheme == "https":
		if parsed.Host == "" {
			return invalidRedirectURI("An HTTPS redirect URI needs a host: " + raw)
		}

		return nil
	case scheme == "http":
		if !loopback(parsed.Hostname()) {
			return invalidRedirectURI("An HTTP redirect URI must be a loopback address: " + raw)
		}

		return nil
	case slices.Contains([]string{"javascript", "data", "file", "vbscript", "blob", "about"}, scheme):
		return invalidRedirectURI("This redirect URI scheme is not allowed: " + raw)
	case !strings.Contains(scheme, "."):
		return invalidRedirectURI("A private-use redirect URI scheme is a reverse domain name, such as com.example.app: " + raw)
	default:
		return nil
	}
}

func loopback(hostname string) bool {
	if strings.EqualFold(hostname, loopbackLocal) {
		return true
	}

	address := net.ParseIP(hostname)

	return address != nil && address.IsLoopback()
}
