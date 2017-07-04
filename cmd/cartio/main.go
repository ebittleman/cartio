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

package main

import (
	"log"
	"net/http"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/ebittleman/cartio/api"
	"github.com/ebittleman/cartio/authn"
	"github.com/ebittleman/cartio/authz"
)

func main() {
	method := jwt.SigningMethodHS256
	secret, err := authn.GenerateKey("supersecretpassword")
	if err != nil {
		panic(err)
	}

	authPairs := authPairs(secret, method)
	rules := localRules()

	authNegotiator := api.AuthenticatorNegotiationFactory(authPairs)

	rootHandler := http.HandlerFunc(api.HelloWorld)

	authorizedRootHandler := api.AuthenticationRequired(
		authNegotiator,
		api.HasPermission(rules, "makehello", nil, rootHandler),
	)

	tokenHandler := api.AuthenticationRequired(
		authNegotiator,
		api.NewTokenHandler(secret, method),
	)

	cmdHandler := api.AuthenticationRequired(
		authNegotiator,
		api.NewCommandHandler(rules),
	)

	http.Handle("/", rootHandler)
	http.Handle("/secure", authorizedRootHandler)
	http.Handle("/command", cmdHandler)
	http.Handle("/auth/token", tokenHandler)
	log.Fatal(http.ListenAndServe("127.0.0.1:8080", nil))
}

func authPairs(secret []byte, method jwt.SigningMethod) map[string]api.AuthPair {
	return map[string]api.AuthPair{
		"Basic": {
			Store:  localUsers(),
			Parser: api.BasicParser,
		},
		"Bearer": {
			Store:  jwtStore(secret, method),
			Parser: api.JWTParser,
		},
	}
}

func jwtStore(secret []byte, method jwt.SigningMethod) authn.CredStore {
	return authn.NewJWTCredStore(secret, method)
}

func localUsers() authn.CredStore {
	store, err := authn.NewHashedMapStore(map[string]string{
		"eric": "pass2",
		"kate": "pass2",
		"nola": "pass2",
	})
	if err != nil {
		panic(err)
	}
	return store
}

func localRules() authz.Rules {
	rules := authz.NewRules("root")

	rules.Allow("eric", "makehello", nil)
	rules.Allow("eric", "create_cart", nil)
	rules.Allow("kate", "makehello", nil)

	return rules
}
