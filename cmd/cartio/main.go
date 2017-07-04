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
