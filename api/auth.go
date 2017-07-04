// cartio - A e-commerce api.
// Copyright (C) 2017 Eric Bittleman

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.

// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/ebittleman/cartio/authn"
	"github.com/ebittleman/cartio/authz"
)

// AuthParser parses a request and returns authn.Credential
type AuthParser func(r *http.Request) (authn.Credential, error)

// JWTParser parses a *http.Request for a JWT
func JWTParser(r *http.Request) (authn.Credential, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, http.ErrNotSupported
	}

	tokenStr, ok := parseBearerAuth(authHeader)
	if !ok {
		return nil, http.ErrNotSupported
	}

	return authn.NewJWTCredential(tokenStr)
}

// BasicParser parses a *http.Request for a Basic credentials
func BasicParser(r *http.Request) (authn.Credential, error) {
	user, password, ok := r.BasicAuth()
	if !ok {
		return nil, http.ErrNotSupported
	}

	return authn.NewPlainTextCredential(user, password), nil
}

// AuthPair pairs a auth.CredStore with a Parser that can extract credentials
// from a *http.Request
type AuthPair struct {
	Store  authn.CredStore
	Parser AuthParser
}

// AuthNegotiator returns an authn.Authenticator as per request parameters
type AuthNegotiator func(r *http.Request) (authn.Authenticator, authn.Credential, error)

// AuthenticatorNegotiationFactory parses a request to instantiate a
// contextual authenticator populated with its required parameters
func AuthenticatorNegotiationFactory(authPairs map[string]AuthPair) AuthNegotiator {
	return func(r *http.Request) (auth authn.Authenticator, cred authn.Credential, err error) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			return nil, nil, http.ErrNotSupported
		}

		authKey := strings.Split(authHeader, " ")[0]
		pair, ok := authPairs[authKey]
		if !ok {
			return nil, nil, http.ErrNotSupported
		}

		if cred, err = pair.Parser(r); err != nil {
			return
		}

		auth = authn.NewAuthenticator(pair.Store)

		return auth, cred, nil
	}
}

func parseBearerAuth(auth string) (token string, ok bool) {
	const prefix = "Bearer "

	if !strings.HasPrefix(auth, prefix) {
		return
	}

	return auth[len(prefix):], true
}

// AuthenticationRequired wraps http requests with authentication step
func AuthenticationRequired(authNegotiator AuthNegotiator, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authenticator, credential, err := authNegotiator(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		ok, err := authenticator.Authenticate(credential)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if !ok {
			http.Error(w, "Unauthorized - Authentication Failed", http.StatusUnauthorized)
			return
		}

		newR := r.WithContext(context.WithValue(
			r.Context(),
			userKey,
			credential.UserID(),
		))

		next.ServeHTTP(w, newR)
	})
}

// HasPermission protects an endpoint with some basic rbac
func HasPermission(rules authz.Rules, action string, subject authz.Subject, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := r.Context().Value(userKey).(authn.UserID)
		if !ok || user == nil {
			http.Error(w, "Unauthenticated - Credentials Required", http.StatusUnauthorized)
			return
		}

		if !rules.IsAllowed(user.String(), action, subject) {
			http.Error(w, "Unauthorized - Permission Denied", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// JWTGenerator http handler that will generate JWT tokens
type JWTGenerator struct {
	method jwt.SigningMethod
	secret []byte
}

// NewTokenHandler creates a new http handler that we swap creds for a token
func NewTokenHandler(secret []byte, method jwt.SigningMethod) http.Handler {
	return JWTGenerator{
		method: method,
		secret: secret,
	}
}

func (j JWTGenerator) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	user, ok := r.Context().Value(userKey).(authn.UserID)
	if !ok || user == nil {
		http.Error(w, "Unauthenticated - Credentials Required", http.StatusUnauthorized)
		return
	}

	token := jwt.NewWithClaims(j.method, &jwt.StandardClaims{
		Subject:   user.String(),
		ExpiresAt: time.Now().Add(600 * time.Second).Unix(),
	})

	ss, err := token.SignedString(j.secret)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Fprintln(w, ss)
}
