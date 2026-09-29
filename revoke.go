package grantable

import (
	"context"
	"errors"
	"net/http"
)

// Revoke is RFC 7009's revocation endpoint. A refresh token takes its
// whole family with it; an access token, itself and its refresh token. An
// unknown token, or another client's, is answered the same as a revoked
// one, so the endpoint tells nobody what exists.
func (self *Server) Revoke() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			writeError(writer, refuse(http.StatusMethodNotAllowed, CodeInvalidRequest, "Revoke with POST."))
			return
		}
		if err := request.ParseForm(); err != nil {
			writeError(writer, invalidRequest("The body is not a form."))
			return
		}

		client, err := self.authenticate(request)
		if err != nil {
			self.fail(writer, request, err)
			return
		}

		presented := request.PostForm.Get("token")
		if presented == "" {
			writeError(writer, invalidRequest("The token is required."))
			return
		}

		if err := self.revoke(request.Context(), client, presented); err != nil {
			self.fail(writer, request, err)
			return
		}

		writer.Header().Set("Cache-Control", "no-store")
		writer.WriteHeader(http.StatusOK)
	})
}

func (self *Server) revoke(context context.Context, client *Client, presented string) error {
	store := self.settings().Store
	now := self.now()

	if token, err := store.FindRefreshToken(context, Hash(presented)); err == nil {
		if token.ClientID != client.ID {
			return nil
		}

		return store.RevokeFamily(context, token.Family, now)
	} else if !errors.Is(err, ErrNotFound) {
		return err
	}

	token, err := store.FindAccessToken(context, Hash(presented))
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if token.ClientID != client.ID {
		return nil
	}

	return store.RevokeToken(context, token.ID, now)
}

// RevokeSubject revokes every token issued for a subject, the moment the
// application ends its grant: a connection disconnected, a person removed.
func (self *Server) RevokeSubject(context context.Context, subject string) error {
	store, err := self.store()
	if err != nil {
		return err
	}

	return store.RevokeSubject(context, subject, self.now())
}
