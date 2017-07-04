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

package authn

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	jwt "github.com/dgrijalva/jwt-go"

	"golang.org/x/crypto/scrypt"
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

type HashedMapStore struct {
	data map[UserID]scryptHashedCredential
}

func NewHashedMapStore(data map[string]string) (*HashedMapStore, error) {
	creds := make(map[UserID]scryptHashedCredential)
	for user, password := range data {
		hash, err := protect(password)
		if err != nil {
			return nil, err
		}
		cred := scryptHashedCredential{
			user: userID(user),
			hash: hash,
		}
		creds[cred.UserID()] = cred
	}
	return &HashedMapStore{
		data: creds,
	}, nil
}

func (m *HashedMapStore) RetrieveCredential(userID UserID) (Credential, error) {
	cred, ok := m.data[userID]
	if !ok {
		return nil, nil
	}

	return cred, nil
}

// PlainTextCredential plain text username/password
type PlainTextCredential struct {
	user     userID
	password string
}

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

// JWTCredential javascript web token
type JWTCredential struct {
	tokenStr string

	token  *jwt.Token
	claims *jwt.StandardClaims
}

// NewJWTCredential creates a new JWTCredential
func NewJWTCredential(tokenStr string) (Credential, error) {
	return &JWTCredential{
		tokenStr: tokenStr,
	}, nil
}

func (j *JWTCredential) verify(secret []byte, method jwt.SigningMethod) (bool, error) {
	claims := new(jwt.StandardClaims)

	token, err := jwt.ParseWithClaims(j.tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if token.Method != method {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return secret, nil
	})

	if !token.Valid {
		return false, err
	}

	j.token = token
	j.claims = claims

	return true, nil
}

// UserID returns the user id
func (j *JWTCredential) UserID() UserID {
	if j.claims == nil {
		return nil
	}

	return userID(j.claims.Subject)
}

// Check cant really verify against itself, so this is not implemented
func (j *JWTCredential) Check(other Credential) (bool, error) {
	return false, errors.New("Not Implemented")
}

// jwtSecretCredential server side javascript web token
type jwtSecretCredential struct {
	method jwt.SigningMethod
	secret []byte
}

// NewJWTCredStore instantiates a cred store for checking jwts
func NewJWTCredStore(secret []byte, method jwt.SigningMethod) CredStore {
	return jwtSecretCredential{
		method: method,
		secret: secret,
	}
}

// UserID returns the user id
func (j jwtSecretCredential) UserID() UserID {
	return userID("")
}

// Check verifies a JWTCredential
func (j jwtSecretCredential) Check(other Credential) (bool, error) {
	otherCred, ok := other.(*JWTCredential)
	if !ok {
		return false, ErrInvalidCredential
	}

	return otherCred.verify(j.secret, j.method)
}

func (j jwtSecretCredential) RetrieveCredential(userID UserID) (Credential, error) {
	return j, nil
}

type scryptHashedCredential struct {
	user userID
	hash string
}

func (s scryptHashedCredential) UserID() UserID {
	return s.user
}

func (s scryptHashedCredential) Check(other Credential) (bool, error) {
	otherCred, ok := other.(PlainTextCredential)
	if !ok {
		return false, ErrInvalidCredential
	}

	if s.user != otherCred.user {
		return false, nil
	}

	ok, err := authenticate(otherCred.password, s.hash)
	if err != nil {
		return false, err
	}

	return ok, nil
}

const (
	saltBytes = 32

	scryptN = 65536
	scryptR = 8
	scryptP = 1

	keyBytes = 32
)

func protect(password string) (string, error) {
	salt := make([]byte, saltBytes)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}

	key, err := scrypt.Key(
		[]byte(password),
		salt,
		scryptN, scryptR, scryptP, keyBytes,
	)

	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(append(key, salt...)), nil
}

// GenerateKey derives an encryption key/password hash from a password
func GenerateKey(password string) ([]byte, error) {
	salt := make([]byte, saltBytes)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	key, err := scrypt.Key(
		[]byte(password),
		salt,
		scryptN, scryptR, scryptP, keyBytes,
	)

	return key, err
}

func authenticate(password, hash string) (bool, error) {
	data, err := base64.StdEncoding.DecodeString(hash)
	if err != nil {
		return false, err
	}

	key1 := data[:32]
	salt := data[32:]

	key2, err := scrypt.Key(
		[]byte(password),
		salt,
		scryptN, scryptR, scryptP, keyBytes,
	)

	if err != nil {
		return false, err
	}

	if subtle.ConstantTimeCompare(
		key1,
		key2,
	) != 1 {
		return false, nil
	}

	return true, nil
}
