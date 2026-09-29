package grantable

import (
	"errors"
	"net/http"
	"net/url"
)

// Authorize is the authorization endpoint. It checks the request, keeps it,
// and sends the browser to the application's consent page with its id. A
// request that names no client it knows, or a redirect the client did not
// register, is refused here, since sending the browser there is what an
// attacker would want; anything else goes back to the client as an error
// on its redirect.
func (self *Server) Authorize() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			http.Error(writer, "Authorize with GET.", http.StatusMethodNotAllowed)
			return
		}

		query := request.URL.Query()

		client, err := self.client(request.Context(), query.Get("client_id"))
		if err != nil {
			self.refuseAuthorization(writer, request, err)
			return
		}

		redirectURI := query.Get("redirect_uri")
		if redirectURI == "" && len(client.RedirectURIs) == 1 {
			redirectURI = client.RedirectURIs[0]
		}
		if !client.allowsRedirect(redirectURI) {
			http.Error(writer, "The redirect_uri is not one this client registered.", http.StatusBadRequest)
			return
		}

		state := query.Get("state")

		pending, refusal := self.asked(client, query)
		if refusal != nil {
			http.Redirect(writer, request, self.redirect(redirectURI, url.Values{
				"error":             {refusal.Code},
				"error_description": {refusal.Description},
			}, state), http.StatusFound)
			return
		}

		pending.ClientID = client.ID
		pending.RedirectURI = redirectURI
		pending.State = state
		pending.ExpiresAt = self.now().Add(self.settings().Lifetimes.Request)

		consentURL := self.settings().ConsentURL
		if consentURL == nil {
			self.fail(writer, request, errors.New("grantable: no consent URL is configured"))
			return
		}
		if err := self.settings().Store.CreateRequest(request.Context(), pending); err != nil {
			self.fail(writer, request, err)
			return
		}

		http.Redirect(writer, request, consentURL(pending.ID), http.StatusFound)
	})
}

// asked reads what the client asks for: a code, with PKCE by S256, for a
// resource this server protects, within the scopes it offers.
func (self *Server) asked(client *Client, query url.Values) (*Request, *Error) {
	settings := self.settings()

	if query.Get("response_type") != responseCode {
		return nil, refuse(http.StatusBadRequest, CodeUnsupportedResponseType, "Only the code response type is supported.")
	}
	if !client.allowsGrant(grantCode) {
		return nil, refuse(http.StatusBadRequest, CodeUnauthorizedClient, "The client may not use the authorization code grant.")
	}

	challenge := query.Get("code_challenge")
	if challenge == "" {
		return nil, invalidRequest("PKCE is required: send a code_challenge.")
	}
	if query.Get("code_challenge_method") != "S256" {
		return nil, invalidRequest("The code_challenge_method must be S256.")
	}
	if len(challenge) != 43 {
		return nil, invalidRequest("An S256 code_challenge is 43 characters.")
	}

	resource, ok := settings.resource(query.Get("resource"))
	if !ok {
		return nil, invalidTarget("The resource is not one this server issues tokens for.")
	}

	scopes, err := settings.requestedScopes(query.Get("scope"))
	if err != nil {
		var refusal *Error
		errors.As(err, &refusal)

		return nil, refusal
	}

	return &Request{
		Scopes:        scopes,
		CodeChallenge: challenge,
		Resource:      resource.URL,
	}, nil
}

// refuseAuthorization is a refusal that cannot go back to the client: the
// browser is told, not redirected.
func (self *Server) refuseAuthorization(writer http.ResponseWriter, request *http.Request, err error) {
	var refusal *Error
	if !errors.As(err, &refusal) {
		self.fail(writer, request, err)
		return
	}

	http.Error(writer, refusal.Description, http.StatusBadRequest)
}

// redirect is the client's redirect URI with the answer on it, its state,
// and the issuer, so the client can tell which server answered (RFC 9207).
func (self *Server) redirect(redirectURI string, values url.Values, state string) string {
	if state != "" {
		values.Set("state", state)
	}
	values.Set("iss", self.settings().issuer())

	parsed, err := url.Parse(redirectURI)
	if err != nil {
		return redirectURI
	}

	query := parsed.Query()
	for key, list := range values {
		query[key] = list
	}
	parsed.RawQuery = query.Encode()

	return parsed.String()
}
