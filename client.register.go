package grantable

import (
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strings"
)

// registration is the part of RFC 7591's client metadata grantable reads.
type registration struct {
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name"`
	ClientURI               string   `json:"client_uri"`
	LogoURI                 string   `json:"logo_uri"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

type registered struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	ClientSecretExpiresAt   *int64   `json:"client_secret_expires_at,omitempty"`
	ClientName              string   `json:"client_name"`
	ClientURI               string   `json:"client_uri,omitempty"`
	LogoURI                 string   `json:"logo_uri,omitempty"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

// Register is dynamic client registration, RFC 7591: POST a client's
// metadata, get back its id and, for a confidential client, its secret,
// shown this once. Anyone may register; the person still consents to every
// connection, and the application rate limits the route.
func (self *Server) Register() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			writeError(writer, refuse(http.StatusMethodNotAllowed, CodeInvalidRequest, "Register with POST."))
			return
		}
		if !self.settings().Registration {
			writeError(writer, refuse(http.StatusNotFound, CodeInvalidRequest, "Dynamic client registration is closed."))
			return
		}

		body := registration{}
		if err := json.NewDecoder(io.LimitReader(request.Body, 64*1024)).Decode(&body); err != nil {
			writeError(writer, invalidClientMetadata("The body is not a JSON object."))
			return
		}

		client, secret, err := self.register(body)
		if err == nil {
			err = self.settings().Store.SaveClient(request.Context(), client)
		}
		if err != nil {
			self.fail(writer, request, err)
			return
		}

		writeJSON(writer, http.StatusCreated, registered{
			ClientID:                client.ID,
			ClientSecret:            secret,
			ClientIDIssuedAt:        client.CreatedAt.Unix(),
			ClientSecretExpiresAt:   secretExpiry(secret),
			ClientName:              client.Name,
			ClientURI:               client.URI,
			LogoURI:                 client.LogoURI,
			RedirectURIs:            client.RedirectURIs,
			GrantTypes:              client.GrantTypes,
			ResponseTypes:           []string{responseCode},
			TokenEndpointAuthMethod: client.AuthMethod,
		})
	})
}

func (self *Server) register(body registration) (*Client, string, error) {
	if self.settings().Store == nil {
		return nil, "", ErrMissingStore
	}
	if len(body.RedirectURIs) == 0 {
		return nil, "", invalidRedirectURI("At least one redirect_uri is required.")
	}
	for _, uri := range body.RedirectURIs {
		if err := validRedirectURI(uri); err != nil {
			return nil, "", err
		}
	}

	grants, err := body.grants()
	if err != nil {
		return nil, "", err
	}

	method := fallback(body.TokenEndpointAuthMethod, authNone)
	if !slices.Contains([]string{authNone, authBasic, authPost}, method) {
		return nil, "", invalidClientMetadata("The token endpoint authentication method " + method + " is not supported.")
	}
	for _, uri := range []string{body.ClientURI, body.LogoURI} {
		if uri != "" && !strings.HasPrefix(uri, "https://") {
			return nil, "", invalidClientMetadata("The client_uri and logo_uri must be HTTPS.")
		}
	}

	prefix := self.settings().Prefix
	client := &Client{
		ID:           clientID(prefix),
		Name:         fallback(strings.TrimSpace(body.ClientName), "Unnamed client"),
		URI:          body.ClientURI,
		LogoURI:      body.LogoURI,
		RedirectURIs: body.RedirectURIs,
		GrantTypes:   grants,
		AuthMethod:   method,
	}

	clientSecret := ""
	if method != authNone {
		clientSecret = secret(prefix, clientSecretKind)
		client.SecretHash = Hash(clientSecret)
	}

	return client, clientSecret, nil
}

// grants are the grants a registration asks for, both when it names none,
// and only the ones grantable serves.
func (self registration) grants() ([]string, error) {
	grants := self.GrantTypes
	if len(grants) == 0 {
		grants = []string{grantCode, grantRefresh}
	}
	if !slices.Contains(grants, grantCode) {
		return nil, invalidClientMetadata("The authorization_code grant type is required.")
	}
	for _, grant := range grants {
		if grant != grantCode && grant != grantRefresh {
			return nil, invalidClientMetadata("The grant type " + grant + " is not supported.")
		}
	}
	if len(self.ResponseTypes) > 0 && !slices.Equal(self.ResponseTypes, []string{responseCode}) {
		return nil, invalidClientMetadata("Only the code response type is supported.")
	}

	return grants, nil
}

// secretExpiry is 0, never, for a client with a secret, and absent for one
// without, the way RFC 7591 section 3.2.1 asks.
func secretExpiry(secret string) *int64 {
	if secret == "" {
		return nil
	}

	var never int64

	return &never
}
