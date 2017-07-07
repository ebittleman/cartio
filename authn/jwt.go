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

	jwt "github.com/dgrijalva/jwt-go"
)

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
	return nil
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
