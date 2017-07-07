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
