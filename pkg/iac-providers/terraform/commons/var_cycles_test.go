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

import (
	"path/filepath"
	"testing"

	"github.com/tenable/terrascan/pkg/iac-providers/terraform/commons/varscope"
)

// TestCircularVariableReferencesDoNotCrash ensures mutually referencing
// variable defaults neither panic nor get silently treated as concrete values:
// any attribute that still carries a reference is reported as pending.
func TestCircularVariableReferencesDoNotCrash(t *testing.T) {
	dir := filepath.Join("testdata", "var-cycles")
	loader := NewTerraformDirectoryLoader(dir, "0.15.0", map[string]interface{}{
		"nonRecursive":     true,
		optionEnvVars:      map[string]varscope.ExternalValue{},
		optionAutoVarFiles: false,
	})

	all, err := loader.LoadIacDir()
	// a parse/load diagnostic is acceptable for a cycle, but it must not panic
	_ = err

	rc := findResource(t, all, "null_resource.cyclic")

	// both cyclic attributes must be explicitly pending, never fabricated
	paths := map[string]bool{}
	for _, p := range rc.PendingAttributes {
		paths[p.Path] = true
	}
	if !paths["triggers.from_a"] || !paths["triggers.from_b"] {
		t.Fatalf("cyclic attributes must be pending, got %#v", rc.PendingAttributes)
	}
}
