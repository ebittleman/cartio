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

package authz

import (
	"fmt"
	"net/url"
)

// Rule describes if a user can or cannot do an action on a subject
type Rule struct {
	Principal string
	Action    string
	Subject   string
}

// Rules basic rule set for determining access rights
type Rules struct {
	superUser string
	denied    map[string]struct{}
	allowed   map[string]struct{}
}

// Subject a resouce that can be procted by system rules
type Subject interface {
	ID() string
	Owner() string
}

// NewRules instantiates a new Rules struct
func NewRules(superUser string) Rules {
	return Rules{
		superUser: superUser,
		denied:    make(map[string]struct{}),
		allowed:   make(map[string]struct{}),
	}
}

// Allow adds a rule to allow a user to act on a subject
func (r *Rules) Allow(principal string, action string, subject Subject) {
	var subjectID string
	if subject != nil {
		subjectID = subject.ID()
	}
	address := formatRule(principal, action, subjectID)
	r.allowed[address] = struct{}{}
}

// Allow adds a rule to denay a user to act on a subject
func (r *Rules) Deny(principal string, action string, subject Subject) {
	var subjectID string
	if subject != nil {
		subjectID = subject.ID()
	}
	address := formatRule(principal, action, subjectID)
	r.denied[address] = struct{}{}
}

// IsAllowed checks to see if a user is allowed to act on the subject as per
// the defined rules. If the user owns the subject or is the super user of the
// system, rules are not checked and the user is allowed to act on the subject.
func (r Rules) IsAllowed(principal string, action string, subject Subject) bool {
	var subjectID string

	if subject != nil {
		if principal == subject.Owner() {
			return true
		}

		subjectID = subject.ID()
	}

	if r.superUser == principal {
		return true
	}

	address := formatRule(principal, action, subjectID)
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
