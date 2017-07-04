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

	"github.com/ebittleman/cartio/api"
	"github.com/ebittleman/cartio/authn"
	"github.com/ebittleman/cartio/authz"
)

func main() {
	store := LocalUsers()
	rules := LocalRules()

	rootHandler := http.HandlerFunc(api.HelloWorld)

	permHandler := api.HasPermission(rules, "makehello", "", rootHandler)

	authHandler := api.AuthenticationRequired(
		api.AuthenticatorNegotiationFactory([]authn.CredStore{store}),
		permHandler,
	)

	cmdHandler := api.AuthenticationRequired(
		api.AuthenticatorNegotiationFactory([]authn.CredStore{store}),
		api.NewCommandHandler(),
	)

	http.Handle("/", rootHandler)
	http.Handle("/secure", authHandler)
	http.Handle("/command", cmdHandler)
	log.Fatal(http.ListenAndServe("127.0.0.1:8080", nil))
}

func LocalUsers() authn.CredStore {
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

func LocalRules() authz.Rules {
	rules := authz.NewRules("eric")

	rules.Allow("kate", "makehello", "")

	return rules
}
