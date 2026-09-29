package grantable

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"syscall"
	"time"
)

// maxDocumentBytes is the most of a metadata document read. The draft
// suggests 5 kilobytes; a document is a handful of fields.
const maxDocumentBytes = 5 * 1024

// document is the part of a client metadata document grantable reads
// (draft-ietf-oauth-client-id-metadata-document, section 3).
type document struct {
	ClientID                string   `json:"client_id"`
	ClientName              string   `json:"client_name"`
	ClientURI               string   `json:"client_uri"`
	LogoURI                 string   `json:"logo_uri"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	ClientSecret            string   `json:"client_secret"`
}

// documentID is whether a client_id is the URL of a metadata document:
// HTTPS, with a path, and nothing a URL could hide behind, no user, no
// fragment, no dot segments.
func documentID(id string) bool {
	parsed, err := url.Parse(id)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return false
	}
	if parsed.Path == "" || parsed.Path == "/" {
		return false
	}

	return !slices.ContainsFunc(strings.Split(parsed.Path, "/"), func(segment string) bool {
		return segment == "." || segment == ".."
	})
}

// fetchDocument reads the document at id and keeps it as the client, for
// as long as its response allows and at most the configured lifetime.
func (self *Server) fetchDocument(context context.Context, id string) (*Client, error) {
	settings := self.settings()

	fetched, expiresAt, err := self.readDocument(context, id, settings)
	if err != nil {
		return nil, invalidClient("The client's metadata document could not be used: " + err.Error())
	}

	client := &Client{
		ID:                id,
		Name:              fetched.ClientName,
		URI:               fetched.ClientURI,
		LogoURI:           fetched.LogoURI,
		RedirectURIs:      fetched.RedirectURIs,
		GrantTypes:        fetched.GrantTypes,
		AuthMethod:        authNone,
		Document:          true,
		DocumentExpiresAt: expiresAt,
	}

	if err := settings.Store.SaveClient(context, client); err != nil {
		return nil, err
	}

	return client, nil
}

func (self *Server) readDocument(context context.Context, id string, settings config) (*document, time.Time, error) {
	httpClient := settings.Documents
	if httpClient == nil {
		httpClient = documentClient()
	}

	request, err := http.NewRequestWithContext(context, http.MethodGet, id, nil)
	if err != nil {
		return nil, time.Time{}, err
	}
	request.Header.Set("Accept", "application/json")

	response, err := httpClient.Do(request)
	if err != nil {
		return nil, time.Time{}, errors.New("it could not be fetched")
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, time.Time{}, fmt.Errorf("it answered %d", response.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, maxDocumentBytes+1))
	if err != nil {
		return nil, time.Time{}, errors.New("it could not be read")
	}
	if len(body) > maxDocumentBytes {
		return nil, time.Time{}, errors.New("it is larger than 5 kilobytes")
	}

	fetched := &document{}
	if err := json.Unmarshal(body, fetched); err != nil {
		return nil, time.Time{}, errors.New("it is not a JSON object")
	}
	if err := fetched.validate(id); err != nil {
		return nil, time.Time{}, err
	}

	return fetched, self.now().Add(documentLifetime(response.Header.Get("Cache-Control"), settings.Lifetimes.Document)), nil
}

func (self *document) validate(id string) error {
	switch {
	case self.ClientID != id:
		return errors.New("its client_id is not its own URL")
	case strings.TrimSpace(self.ClientName) == "":
		return errors.New("it has no client_name")
	case len(self.RedirectURIs) == 0:
		return errors.New("it has no redirect_uris")
	case self.ClientSecret != "":
		return errors.New("it carries a client_secret, which a document must not")
	case self.TokenEndpointAuthMethod != "" && self.TokenEndpointAuthMethod != authNone:
		return errors.New("it authenticates with " + self.TokenEndpointAuthMethod + ", and only none is supported")
	}

	for _, uri := range self.RedirectURIs {
		if err := validRedirectURI(uri); err != nil {
			return errors.New("it lists a redirect URI that is not allowed: " + uri)
		}
	}
	for _, uri := range []string{self.ClientURI, self.LogoURI} {
		if uri != "" && !strings.HasPrefix(uri, "https://") {
			return errors.New("its client_uri and logo_uri must be HTTPS")
		}
	}

	return self.grants()
}

// grants keeps the grants grantable serves of those the document lists,
// which must include the authorization code, and none if it lists none.
func (self *document) grants() error {
	if len(self.GrantTypes) == 0 {
		self.GrantTypes = []string{grantCode}
	}
	if !slices.Contains(self.GrantTypes, grantCode) {
		return errors.New("it does not use the authorization code grant")
	}
	self.GrantTypes = slices.DeleteFunc(self.GrantTypes, func(grant string) bool {
		return grant != grantCode && grant != grantRefresh
	})

	if len(self.ResponseTypes) > 0 && !slices.Equal(self.ResponseTypes, []string{responseCode}) {
		return errors.New("it asks for a response type other than code")
	}

	return nil
}

// documentLifetime is how long a response's Cache-Control lets a document be
// kept, capped at the configured lifetime. no-store and no-cache keep it
// for none: it is read again the next time it is used.
func documentLifetime(cacheControl string, most time.Duration) time.Duration {
	for directive := range strings.SplitSeq(cacheControl, ",") {
		directive = strings.ToLower(strings.TrimSpace(directive))
		if directive == "no-store" || directive == "no-cache" {
			return 0
		}

		seconds, found := strings.CutPrefix(directive, "max-age=")
		if !found {
			continue
		}

		var age int64
		if _, err := fmt.Sscanf(seconds, "%d", &age); err != nil || age < 0 {
			continue
		}

		return min(time.Duration(age)*time.Second, most)
	}

	return most
}

// documentClient fetches documents without being turned against the
// network it runs in: public addresses only, checked on the address it
// actually dials, no proxy, no redirects, and quick.
func documentClient() *http.Client {
	dialer := &net.Dialer{
		Timeout: 3 * time.Second,
		Control: func(_ string, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			parsed, err := netip.ParseAddr(host)
			if err != nil || !public(parsed) {
				return errors.New("grantable: refusing to fetch a document from " + host)
			}

			return nil
		},
	}

	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy:                  nil,
			DialContext:            dialer.DialContext,
			TLSHandshakeTimeout:    3 * time.Second,
			ResponseHeaderTimeout:  3 * time.Second,
			MaxResponseHeaderBytes: 16 * 1024,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// sharedAddressSpace is carrier-grade NAT, RFC 6598, which netip does not
// count as private.
var sharedAddressSpace = netip.MustParsePrefix("100.64.0.0/10")

func public(address netip.Addr) bool {
	address = address.Unmap()

	return address.IsGlobalUnicast() &&
		!address.IsPrivate() &&
		!address.IsLoopback() &&
		!address.IsLinkLocalUnicast() &&
		!sharedAddressSpace.Contains(address)
}
