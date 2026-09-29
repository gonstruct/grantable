package grantable

import (
	"slices"
	"strings"
)

// requestedScopes reads a scope parameter against what the server offers.
// None is all of them: the consent page is where they are narrowed.
func (self config) requestedScopes(raw string) ([]string, error) {
	requested := strings.Fields(raw)
	if len(requested) == 0 {
		return slices.Clone(self.Scopes), nil
	}

	scopes := make([]string, 0, len(requested))
	for _, scope := range requested {
		if !slices.Contains(self.Scopes, scope) {
			return nil, invalidScope("The scope " + scope + " is not offered.")
		}
		if !slices.Contains(scopes, scope) {
			scopes = append(scopes, scope)
		}
	}

	return scopes, nil
}

// intersect keeps the scopes of issued that allowed also has, in issued's
// order.
func intersect(issued, allowed []string) []string {
	kept := make([]string, 0, len(issued))
	for _, scope := range issued {
		if slices.Contains(allowed, scope) {
			kept = append(kept, scope)
		}
	}

	return kept
}

func covers(granted, requested []string) bool {
	for _, scope := range requested {
		if !slices.Contains(granted, scope) {
			return false
		}
	}

	return true
}
