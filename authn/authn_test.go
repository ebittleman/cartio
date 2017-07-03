package authn

import "testing"

func Test_protect(t *testing.T) {
	password := "testpass"

	hash, err := protect(password)
	if err != nil {
		t.Fatal(err)
	}

	ok, err := authenticate(password, hash)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Hash: %s", hash)
	t.Logf("OK: %v", ok)
}
