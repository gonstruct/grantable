package grantable

import (
	"net/http"
	"net/url"
	"strings"
)

// ServerMetadata is RFC 8414's authorization server metadata, with what the
// MCP authorization spec asks to be advertised: PKCE, metadata documents
// and the iss parameter.
type ServerMetadata struct {
	Issuer                                     string   `json:"issuer"`
	AuthorizationEndpoint                      string   `json:"authorization_endpoint"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	RegistrationEndpoint                       string   `json:"registration_endpoint,omitempty"`
	RevocationEndpoint                         string   `json:"revocation_endpoint"`
	ScopesSupported                            []string `json:"scopes_supported"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	ResponseModesSupported                     []string `json:"response_modes_supported"`
	GrantTypesSupported                        []string `json:"grant_types_supported"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported"`
	RevocationEndpointAuthMethodsSupported     []string `json:"revocation_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported              []string `json:"code_challenge_methods_supported"`
	ClientIDMetadataDocumentSupported          bool     `json:"client_id_metadata_document_supported"`
	AuthorizationResponseIssParameterSupported bool     `json:"authorization_response_iss_parameter_supported"`
}

// ResourceMetadata is RFC 9728's protected resource metadata: which
// authorization server issues its tokens, and what they may carry.
type ResourceMetadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	ScopesSupported        []string `json:"scopes_supported"`
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
	ResourceName           string   `json:"resource_name,omitempty"`
	ResourceDocumentation  string   `json:"resource_documentation,omitempty"`
}

// Metadata is the server's metadata as it is served.
func (self *Server) Metadata() ServerMetadata {
	settings := self.settings()
	methods := []string{authNone, authBasic, authPost}

	metadata := ServerMetadata{
		Issuer:                                     settings.issuer(),
		AuthorizationEndpoint:                      settings.endpoint(settings.Paths.Authorize),
		TokenEndpoint:                              settings.endpoint(settings.Paths.Token),
		RevocationEndpoint:                         settings.endpoint(settings.Paths.Revoke),
		ScopesSupported:                            settings.Scopes,
		ResponseTypesSupported:                     []string{responseCode},
		ResponseModesSupported:                     []string{"query"},
		GrantTypesSupported:                        []string{grantCode, grantRefresh},
		TokenEndpointAuthMethodsSupported:          methods,
		RevocationEndpointAuthMethodsSupported:     methods,
		CodeChallengeMethodsSupported:              []string{"S256"},
		ClientIDMetadataDocumentSupported:          true,
		AuthorizationResponseIssParameterSupported: true,
	}
	if settings.Registration {
		metadata.RegistrationEndpoint = settings.endpoint(settings.Paths.Register)
	}

	return metadata
}

// ServerMetadataHandler serves Metadata at
// /.well-known/oauth-authorization-server.
func (self *Server) ServerMetadataHandler() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		readableAnywhere(writer)
		writeJSON(writer, http.StatusOK, self.Metadata())
	})
}

// ResourceMetadataHandler serves the metadata of a configured resource, at
// the path ResourceMetadataURL gives it.
func (self *Server) ResourceMetadataHandler(resourceURL string) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		settings := self.settings()

		resource, ok := settings.resource(resourceURL)
		if !ok {
			writeError(writer, refuse(http.StatusNotFound, CodeInvalidTarget, "No such resource."))
			return
		}

		readableAnywhere(writer)
		writeJSON(writer, http.StatusOK, ResourceMetadata{
			Resource:               resource.URL,
			AuthorizationServers:   []string{settings.issuer()},
			ScopesSupported:        settings.Scopes,
			BearerMethodsSupported: []string{"header"},
			ResourceName:           resource.Name,
			ResourceDocumentation:  resource.Documentation,
		})
	})
}

// ResourceMetadataURL is where a resource's metadata lives, RFC 9728
// section 3.1: the well-known path inserted between its host and its path,
// https://api.example/.well-known/oauth-protected-resource/mcp for
// https://api.example/mcp.
func ResourceMetadataURL(resourceURL string) string {
	parsed, err := url.Parse(resourceURL)
	if err != nil {
		return resourceURL
	}

	parsed.Path = "/.well-known/oauth-protected-resource" + strings.TrimRight(parsed.Path, "/")
	parsed.RawQuery = ""
	parsed.Fragment = ""

	return parsed.String()
}

// readableAnywhere lets a browser-based client read metadata from anywhere: it is the
// description of the server, and holds nothing.
func readableAnywhere(writer http.ResponseWriter) {
	writer.Header().Set("Access-Control-Allow-Origin", "*")
}
