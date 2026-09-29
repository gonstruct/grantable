package grantable

import (
	"encoding/json"
	"errors"
	"net/http"
)

type errorBody struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// fail answers a refusal, and reports an error that is not one.
func (self *Server) fail(writer http.ResponseWriter, request *http.Request, err error) {
	var refusal *Error
	if report := self.settings().Report; report != nil && !errors.As(err, &refusal) {
		report(request.Context(), err)
	}

	writeError(writer, err)
}

// writeError answers a refusal as RFC 6749 section 5.2 does: the code and
// the description as JSON, never cached. Anything that is not an *Error is
// the server's own fault and says nothing more than server_error.
func writeError(writer http.ResponseWriter, err error) {
	var refusal *Error
	if !errors.As(err, &refusal) {
		refusal = refuse(http.StatusInternalServerError, CodeServerError, "The request could not be completed.")
	}

	if refusal.Status == http.StatusUnauthorized {
		writer.Header().Set("WWW-Authenticate", `Basic realm="oauth", error="invalid_client"`)
	}

	writeJSON(writer, refusal.Status, errorBody{Error: refusal.Code, ErrorDescription: refusal.Description})
}

func writeJSON(writer http.ResponseWriter, status int, body any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Pragma", "no-cache")
	writer.WriteHeader(status)

	_ = json.NewEncoder(writer).Encode(body)
}
