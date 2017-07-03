package authz

import (
	"fmt"
	"net/url"
)

type Rule struct {
	Principal string
	Action    string
	Subject   string
}

type Rules struct {
	superUser string
	denied    map[string]struct{}
	allowed   map[string]struct{}
}

func NewRules(superUser string) Rules {
	return Rules{
		superUser: superUser,
		denied:    make(map[string]struct{}),
		allowed:   make(map[string]struct{}),
	}
}

func (r *Rules) Allow(principal string, action string, subject string) {
	address := formatRule(principal, action, subject)
	r.allowed[address] = struct{}{}
}

func (r *Rules) Deny(principal string, action string, subject string) {
	address := formatRule(principal, action, subject)
	r.denied[address] = struct{}{}
}

func (r Rules) IsAllowed(principal string, action string, subject string) bool {
	if r.superUser == principal {
		return true
	}

	address := formatRule(principal, action, subject)
	if _, notOK := r.denied[address]; notOK {
		return false
	}

	_, ok := r.allowed[address]

	return ok
}

func formatRule(principal string, action string, subject string) string {
	return fmt.Sprintf(
		"%s/%s/%s",
		url.PathEscape(principal),
		url.PathEscape(action),
		url.PathEscape(subject),
	)
}
