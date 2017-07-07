// cartio - An e-commerce API.
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

package authn

import (
	"errors"
	"fmt"
)

var (
	// ErrUserNotFound used when we fail to retrieve a user
	ErrUserNotFound = errors.New("User Not Found")
	// ErrInvalidCredential used with attempting to compare mismatched
	// credential types
	ErrInvalidCredential = errors.New("Invlaid Credential")
)

type userID string

func (u userID) String() string {
	return string(u)
}

// UserID basic user identifier
type UserID interface {
	fmt.Stringer
}

// Credential used for authentication
type Credential interface {
	UserID() UserID
	Check(Credential) (bool, error)
}

// Authenticator interface used authenticate a request
type Authenticator interface {
	Authenticate(credential Credential) (bool, error)
}

// CredStore abstraction for credential lookup
type CredStore interface {
	RetrieveCredential(id UserID) (Credential, error)
}

// NewAuthenticator instantiates a new authenticator
func NewAuthenticator(credStore CredStore) Authenticator {
	a := new(authenticator)

	a.credStore = credStore

	return a
}

type authenticator struct {
	credStore CredStore
}

func (b *authenticator) Authenticate(credential Credential) (bool, error) {
	foundCred, err := b.credStore.RetrieveCredential(credential.UserID())
	if err != nil {
		return false, err
	}

	if foundCred == nil {
		return false, nil
	}

	ok, err := foundCred.Check(credential)
	if err != nil {
		return false, err
	}

	return ok, nil
}

// PlainTextCredential plain text username/password
type PlainTextCredential struct {
	user     userID
	password string
}

// NewPlainTextCredential creates a simple credential using a user id and
// password
func NewPlainTextCredential(user string, password string) Credential {
	return PlainTextCredential{
		user:     userID(user),
		password: password,
	}
}

// UserID returns the user id
func (b PlainTextCredential) UserID() UserID {
	return b.user
}

// Check checks the plain text credential against another
func (b PlainTextCredential) Check(other Credential) (bool, error) {
	otherCred, ok := other.(PlainTextCredential)
	if !ok {
		return false, ErrInvalidCredential
	}

	if b.user != otherCred.user {
		return false, nil
	}

	if b.password != otherCred.password {
		return false, nil
	}

	return true, nil
}
