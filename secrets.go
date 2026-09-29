package grantable

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"strings"
)

// What each secret starts with, after the configured prefix, so a leaked
// one says what it is and a scanner can find it.
const (
	accessTokenKind  = "at_"
	refreshTokenKind = "rt_"
	codeKind         = "ac_"
	clientIDKind     = "c_"
	clientSecretKind = "cs_"
)

// secret is 32 random bytes under a prefix. Only its hash is ever stored.
func secret(prefix, kind string) string {
	random := make([]byte, 32)
	_, _ = rand.Read(random) // cannot fail since Go 1.24

	return prefix + kind + base64.RawURLEncoding.EncodeToString(random)
}

func clientID(prefix string) string {
	random := make([]byte, 16)
	_, _ = rand.Read(random)

	return prefix + clientIDKind + hex.EncodeToString(random)
}

// Hash is how a secret is stored and looked up: SHA-256, hex. The secrets
// are random, so there is nothing for a slow hash to protect.
func Hash(value string) string {
	digest := sha256.Sum256([]byte(value))

	return hex.EncodeToString(digest[:])
}

func equalHash(value, hash string) bool {
	return subtle.ConstantTimeCompare([]byte(Hash(value)), []byte(hash)) == 1
}

// verifyChallenge is PKCE's S256, RFC 7636 section 4.6: the verifier is 43
// to 128 unreserved characters, and its SHA-256 is the challenge.
func verifyChallenge(verifier, challenge string) bool {
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	if strings.IndexFunc(verifier, func(character rune) bool { return !unreserved(character) }) >= 0 {
		return false
	}

	digest := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(digest[:])

	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}

func unreserved(character rune) bool {
	switch {
	case character >= 'A' && character <= 'Z', character >= 'a' && character <= 'z', character >= '0' && character <= '9':
		return true
	case character == '-', character == '.', character == '_', character == '~':
		return true
	default:
		return false
	}
}
