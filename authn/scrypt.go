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
	"io"

	"golang.org/x/crypto/scrypt"
)

const (
	saltBytes = 32
	keyBytes  = 32

	scryptN = 65536
	scryptR = 8
	scryptP = 1
)

// GenerateKey derives an encryption key from a password
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

// HashedMapStore simple in memory credstore
type HashedMapStore struct {
	data map[UserID]scryptHashedCredential
}

// NewHashedMapStore takes a map of user ids as keys and plain text passwords
// as values, salts and hashes them, and indexes them by user ids and creates
// a HashedMapStore/CredStore for authentication
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

// RetrieveCredential looksup a credential by userID
func (m *HashedMapStore) RetrieveCredential(userID UserID) (Credential, error) {
	cred, ok := m.data[userID]
	if !ok {
		return nil, nil
	}

	return cred, nil
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

func authenticate(password, hash string) (bool, error) {
	data, err := base64.StdEncoding.DecodeString(hash)
	if err != nil {
		return false, err
	}

	key1 := data[:keyBytes]
	salt := data[keyBytes:]

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
