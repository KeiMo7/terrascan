/*
    Copyright (C) 2022 Tenable, Inc.

	Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

		http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
*/

package commons

import "testing"

func TestParseVarOverride(t *testing.T) {
	cases := []struct {
		in      string
		wantN   string
		wantV   string
		wantErr bool
	}{
		{"k=some=value", "k", "some=value", false},
		{"name=42", "name", "42", false},
		{"noequals", "", "", true},
		{"=value", "", "", true},
	}
	for _, c := range cases {
		n, v, err := ParseVarOverride(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("%q: expected error", c.in)
			}
			continue
		}
		if err != nil || n != c.wantN || v != c.wantV {
			t.Errorf("%q: got (%q,%q,%v) want (%q,%q,nil)", c.in, n, v, err, c.wantN, c.wantV)
		}
	}
}
