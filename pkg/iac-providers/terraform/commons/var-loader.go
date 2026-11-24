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
	"fmt"
	"sort"
	"strings"

	hclConfigs "github.com/hashicorp/terraform/configs"
	"github.com/tenable/terrascan/pkg/iac-providers/terraform/commons/varscope"
)

// option keys consumed by the terraform directory loader for external
// variable values. They are additive: existing callers that never set them
// keep the previous default-only behavior.
const (
	// optionVarFiles carries explicit -var-file paths (HCL or JSON).
	optionVarFiles = "tfVarFiles"
	// optionVars carries parsed -var key=value overrides.
	optionVars = "tfVars"
	// optionEnvVars carries TF_VAR_* values; when nil the loader reads the
	// process environment itself.
	optionEnvVars = "tfEnvVars"
	// optionAutoVarFiles toggles automatic discovery of terraform.tfvars and
	// *.auto.tfvars-style files in the scanned module directory.
	optionAutoVarFiles = "tfAutoVarFiles"
)

// VariableInputs is the fully assembled set of external variable sources for
// one root module directory.
type VariableInputs struct {
	RootInput    varscope.RootInput
	OrderedFiles []string
	Errors       []error
}

// buildVariableInputs assembles every external variable source for the given
// module directory and returns a RootInput plus non-fatal errors.
//
// Precedence, lowest to highest:
//
//	default < environment < values files (ordered) < cli overrides
//
// A single corrupt values file does not abort the others: it contributes a
// named, location-aware error and poisons only the variables it tried to set.
func (t TerraformDirectoryLoader) buildVariableInputs(dir string,
	variables map[string]*hclConfigs.Variable) VariableInputs {

	vi := VariableInputs{
		RootInput: varscope.RootInput{
			Variables:    variables,
			PoisonedVars: map[string]string{},
		},
	}

	// 1. environment variables (lowest external precedence)
	vi.RootInput.EnvValues = t.resolveEnvValues()

	// 2. values files: auto-discovered first, then explicit files in order
	filePaths := t.orderedVarFiles(dir)
	parsedFiles := make([]*varscope.FileValues, 0, len(filePaths))
	for _, path := range filePaths {
		fv, err := varscope.LoadValuesFile(path)
		if err != nil {
			// record the failure and continue with the remaining files
			vi.Errors = append(vi.Errors, err)
			// when the parser still recovered partial attributes, poison those
			// names so an intended override is never silently replaced by a
			// default; otherwise poison nothing and other sources still apply
			if fv != nil {
				for name := range fv.Values {
					vi.RootInput.PoisonedVars[name] = err.Error()
				}
			}
			continue
		}
		if fv != nil {
			parsedFiles = append(parsedFiles, fv)
		}
	}
	vi.OrderedFiles = filePaths
	vi.RootInput.FileValues, _ = varscope.MergeValuesFiles(parsedFiles)

	// 3. command line overrides (highest precedence)
	vi.RootInput.CLIValues = t.resolveCLIOverrides()

	return vi
}

// orderedVarFiles returns the values files to apply for dir, in deterministic
// order: auto-discovered files first, then explicitly supplied files.
func (t TerraformDirectoryLoader) orderedVarFiles(dir string) []string {
	var ordered []string
	if t.autoVarFiles {
		ordered = append(ordered, varscope.DiscoverValuesFiles(dir)...)
	}
	ordered = append(ordered, t.varFiles...)
	return dedupe(ordered)
}

// resolveEnvValues returns environment supplied values, allowing tests to
// inject a deterministic environment through loader options.
func (t TerraformDirectoryLoader) resolveEnvValues() map[string]varscope.ExternalValue {
	if t.envValues != nil {
		return t.envValues
	}
	return varscope.EnvFromOS()
}

// resolveCLIOverrides returns the parsed -var overrides carried by the loader.
func (t TerraformDirectoryLoader) resolveCLIOverrides() map[string]varscope.ExternalValue {
	out := make(map[string]varscope.ExternalValue, len(t.cliVars))
	keys := make([]string, 0, len(t.cliVars))
	for k := range t.cliVars {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out[k] = varscope.NewTextValue(t.cliVars[k], varscope.OriginCLI, "-var")
	}
	return out
}

// ParseVarOverride splits a "name=value" command line override. It returns an
// error rather than guessing when the separator is missing.
func ParseVarOverride(assignment string) (name, value string, err error) {
	idx := strings.IndexByte(assignment, '=')
	if idx <= 0 {
		return "", "", fmt.Errorf("invalid variable override %q: expected name=value", assignment)
	}
	name = strings.TrimSpace(assignment[:idx])
	if name == "" {
		return "", "", fmt.Errorf("invalid variable override %q: variable name is empty", assignment)
	}
	return name, assignment[idx+1:], nil
}

// dedupe returns paths with duplicates removed, preserving first occurrence.
func dedupe(paths []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}
