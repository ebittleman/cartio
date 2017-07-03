package authn

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"

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
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		log.Fatal(err)
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
