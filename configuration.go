package grantable

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type config struct {
	// Issuer is the server's own URL, the API's: every endpoint and both
	// metadata documents hang off it.
	Issuer string

	Store Store

	// Resources are the protected resources a token may be issued for, by
	// their canonical URL, each with the name and documentation its
	// metadata document gives.
	Resources []Resource

	// Scopes are what a token may carry. A request that names none asks for
	// all of them; the consent page decides what is granted.
	Scopes []string

	// ConsentURL is where the browser goes with a request to approve: the
	// application's own page, which signs the person in and asks.
	ConsentURL func(requestID string) string

	// Grants answers what a subject's grant allows now. A token carries the
	// scopes it was issued with; each use intersects them with this, so a
	// grant narrowed or revoked narrows every token at once. Empty is a
	// grant that allows nothing.
	Grants func(context context.Context, subject string) ([]string, error)

	// Prefix goes in front of every secret grantable makes, "cp_" for
	// "cp_at_...", so a leaked one names where it came from.
	Prefix string

	Paths     Paths
	Lifetimes Lifetimes

	// Registration is whether dynamic client registration is open. It is
	// deprecated for MCP in favour of metadata documents, and on by default
	// for the clients that still use it.
	Registration bool

	// Documents fetches client metadata documents. nil is a client that
	// refuses private addresses, redirects, slow servers and large bodies.
	Documents *http.Client

	// Report hears every error that is the server's own fault, the ones a
	// client is only told were server_error.
	Report func(context context.Context, err error)
}

// Resource is one protected resource a token may be for.
type Resource struct {
	URL           string
	Name          string
	Documentation string
}

// Paths are where the endpoints are mounted, under the issuer.
type Paths struct {
	Authorize string
	Token     string
	Register  string
	Revoke    string
}

// Lifetimes bound what grantable issues.
type Lifetimes struct {
	// Request is how long a person has to answer the consent page.
	Request time.Duration

	// Code is how long an approved code may be exchanged.
	Code time.Duration

	Access  time.Duration
	Refresh time.Duration

	// Document is how long a metadata document is kept when its response
	// says nothing, and the most it is kept when it does.
	Document time.Duration
}

func configure() config {
	return config{
		Issuer: os.Getenv("API_URL"),
		Paths: Paths{
			Authorize: "/oauth/authorize",
			Token:     "/oauth/token",
			Register:  "/oauth/register",
			Revoke:    "/oauth/revoke",
		},
		Lifetimes: Lifetimes{
			Request:  10 * time.Minute,
			Code:     5 * time.Minute,
			Access:   time.Hour,
			Refresh:  30 * 24 * time.Hour,
			Document: 24 * time.Hour,
		},
		Registration: true,
	}
}

type option func(*config)

func WithIssuer(issuer string) option {
	return func(config *config) {
		config.Issuer = issuer
	}
}

func WithStore(store Store) option {
	return func(config *config) {
		config.Store = store
	}
}

// WithResource adds a protected resource tokens may be issued for.
func WithResource(resource Resource) option {
	return func(config *config) {
		config.Resources = append(config.Resources, resource)
	}
}

func WithScopes(scopes ...string) option {
	return func(config *config) {
		config.Scopes = scopes
	}
}

func WithConsentURL(consentURL func(requestID string) string) option {
	return func(config *config) {
		config.ConsentURL = consentURL
	}
}

func WithGrants(grants func(context context.Context, subject string) ([]string, error)) option {
	return func(config *config) {
		config.Grants = grants
	}
}

func WithPrefix(prefix string) option {
	return func(config *config) {
		config.Prefix = prefix
	}
}

// WithPaths mounts the endpoints elsewhere. An empty path keeps its default.
func WithPaths(paths Paths) option {
	return func(config *config) {
		config.Paths = Paths{
			Authorize: fallback(paths.Authorize, config.Paths.Authorize),
			Token:     fallback(paths.Token, config.Paths.Token),
			Register:  fallback(paths.Register, config.Paths.Register),
			Revoke:    fallback(paths.Revoke, config.Paths.Revoke),
		}
	}
}

// WithLifetimes changes how long things live. A zero keeps its default.
func WithLifetimes(lifetimes Lifetimes) option {
	return func(config *config) {
		config.Lifetimes = Lifetimes{
			Request:  fallback(lifetimes.Request, config.Lifetimes.Request),
			Code:     fallback(lifetimes.Code, config.Lifetimes.Code),
			Access:   fallback(lifetimes.Access, config.Lifetimes.Access),
			Refresh:  fallback(lifetimes.Refresh, config.Lifetimes.Refresh),
			Document: fallback(lifetimes.Document, config.Lifetimes.Document),
		}
	}
}

// WithoutRegistration closes dynamic client registration: only metadata
// documents then.
func WithoutRegistration() option {
	return func(config *config) {
		config.Registration = false
	}
}

// WithReport sets what hears the server's own errors: a logger, a tracer.
func WithReport(report func(context context.Context, err error)) option {
	return func(config *config) {
		config.Report = report
	}
}

// WithDocumentClient sets the client metadata documents are fetched with.
// A test serving a document from httptest needs one that reaches loopback.
func WithDocumentClient(client *http.Client) option {
	return func(config *config) {
		config.Documents = client
	}
}

func (self config) issuer() string {
	return strings.TrimRight(self.Issuer, "/")
}

func (self config) endpoint(path string) string {
	return self.issuer() + path
}

// resource finds the configured resource a request names. An empty one is
// the only resource there is, for a client that sends none; with several,
// it must be named.
func (self config) resource(requested string) (Resource, bool) {
	if requested == "" {
		if len(self.Resources) == 1 {
			return self.Resources[0], true
		}

		return Resource{}, false
	}

	for _, resource := range self.Resources {
		if canonical(resource.URL) == canonical(requested) {
			return resource, true
		}
	}

	return Resource{}, false
}

// canonical is a resource URL compared the way RFC 8707 asks: scheme and
// host without regard to case, no trailing slash, no fragment.
func canonical(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return raw
	}

	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.Host = strings.ToLower(parsed.Host)
	parsed.Fragment = ""
	parsed.Path = strings.TrimRight(parsed.Path, "/")

	return parsed.String()
}

func fallback[T comparable](value, otherwise T) T {
	var zero T
	if value == zero {
		return otherwise
	}

	return value
}
