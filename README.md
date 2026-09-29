# grantable

An OAuth 2.1 authorization server on `net/http`. It is what an API needs to
let a person connect an application to it: an MCP client, a script, another
product. It speaks the MCP authorization spec of 2026-07-28, which is plain
OAuth with the parts that matter written down.

grantable owns the protocol. The application owns the person: it signs them
in, shows the consent page, and decides what a grant is. Every token names
the application's grant as its subject.

```go
server := grantable.New(
    grantable.WithIssuer("https://api.example"),
    grantable.WithStore(grantable.SQL(func() grantable.DB { return db })),
    grantable.WithResource(grantable.Resource{URL: "https://api.example/mcp", Name: "Example MCP"}),
    grantable.WithScopes("read", "write"),
    grantable.WithConsentURL(func(id string) string { return "https://app.example/oauth/authorize?request=" + id }),
    grantable.WithGrants(func(ctx context.Context, subject string) ([]string, error) {
        return connections.Scopes(ctx, subject) // what the grant allows now; none once it is gone
    }),
    grantable.WithPrefix("ex_"),
)
```

```go
http.Handle("GET /.well-known/oauth-authorization-server", server.ServerMetadataHandler())
http.Handle("GET /.well-known/oauth-protected-resource/mcp", server.ResourceMetadataHandler("https://api.example/mcp"))
http.Handle("GET /oauth/authorize", server.Authorize())
http.Handle("POST /oauth/token", server.Token())
http.Handle("POST /oauth/register", server.Register())
http.Handle("POST /oauth/revoke", server.Revoke())
```

## The consent page

`Authorize` checks the request and sends the browser to the consent URL with
the request's id. The page is the application's: it signs the person in,
shows what `Pending` says, and answers.

```go
pending, err := server.Pending(ctx, id)  // grantable.ErrRequestUnavailable: expired or answered

pending.Client.Name, pending.Client.LogoURI
pending.RedirectHost()   // where the answer goes: show it, always
pending.Loopback()       // to this computer: say a local app could be anyone
pending.DocumentHost()   // the domain a metadata document client proved
pending.Scopes           // what it asks for

redirect, err := server.Approve(ctx, id, grant.ID, []string{"read"}) // may grant more or less than asked
redirect, err := server.Deny(ctx, id)
```

Send the browser to `redirect`.

## At the resource

```go
token, err := server.Verify(ctx, grantable.BearerToken(r), "https://api.example/mcp")
if errors.Is(err, grantable.ErrInvalidToken) {
    w.Header().Set("WWW-Authenticate", server.Challenge(resource, grantable.Challenge{}))
    w.WriteHeader(http.StatusUnauthorized)
    return
}

token.Subject        // the application's grant
token.Can("write")   // false: 403 with Challenge{Error: "insufficient_scope", Scopes: []string{"write"}}
```

A token carries the scopes it was issued with; every `Verify` and every
refresh intersects them with what `WithGrants` answers for its subject. Narrow
a grant and its tokens narrow; end it and they stop. `RevokeSubject` also
revokes them outright.

## Clients

- **Metadata documents.** A client whose `client_id` is an HTTPS URL with a
  path is the JSON document there. grantable reads it when it is first used,
  checks it names itself, and keeps it for as long as its `Cache-Control`
  says and at most a day. It is fetched from public addresses only, without
  redirects, in five seconds and five kilobytes.
- **Dynamic registration**, RFC 7591, for clients from before documents.
  `WithoutRegistration()` closes it.
- Redirect URIs are HTTPS, HTTP on a loopback address (any port when it
  comes back), or a native app's reverse-domain scheme.

## What is on by default

PKCE with S256 on every request; tokens bound to the resource they were
asked for; the issuer on every redirect back; codes spent once, and a code
spent twice revoking what the first use gave; refresh tokens rotated on
every use, and one used twice revoking its whole family; only hashes of
secrets stored. Codes live five minutes, access tokens an hour, refresh
tokens thirty days: `WithLifetimes` changes them.

## Storage

`SQL` works on PostgreSQL in the tables of [`schema.sql`](./schema.sql),
which the application copies into a migration. `Memory` is for tests. A
store of your own implements `Store`.

## Tests

The contract runs against `Memory`, and against PostgreSQL when
`GRANTABLE_DATABASE_URL` is set:

```sh
GRANTABLE_DATABASE_URL="postgres://user:pass@localhost:5432/db?sslmode=disable" go test ./...
```
