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

package varscope

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2"
	hclConfigs "github.com/hashicorp/terraform/configs"
	"github.com/spf13/afero"
	"github.com/zclconf/go-cty/cty"
)

// defaultAutoFiles are the well-known values files Terraform loads
// automatically from a module directory.
var defaultAutoFiles = []string{"terraform.tfvars", "terraform.tfvars.json"}

// FileValues is the parsed content of one values file: top-level variable
// names mapped to their cty values, together with the source path and the
// position of every top-level attribute.
type FileValues struct {
	Path   string
	Values map[string]cty.Value
	Ranges map[string]hcl.Range
}

// LoadValuesFile parses a single values file. Both HCL structured text
// (*.tfvars) and JSON (*.tfvars.json) are supported because the underlying
// terraform parser selects the syntax from the file name.
//
// A parse failure is returned as a VarError that names the file and the
// exact position. It is deliberately not swallowed: silently skipping a bad
// file and falling back to defaults would re-introduce false negatives.
func LoadValuesFile(path string) (*FileValues, error) {
	parser := hclConfigs.NewParser(afero.NewOsFs())
	body, diags := parser.LoadHCLFile(path)
	if body == nil {
		return nil, fileParseError(path, diags)
	}
	// the parser can return a non-nil body together with error diagnostics
	// (e.g. an unterminated expression). Such a file is unusable: surface the
	// error instead of silently keeping a partial result.
	if diags.HasErrors() {
		return nil, fileParseError(path, diags)
	}

	attrs, attrDiags := body.JustAttributes()
	if attrDiags.HasErrors() {
		return nil, fileParseError(path, attrDiags)
	}

	fv := &FileValues{
		Path:   path,
		Values: make(map[string]cty.Value, len(attrs)),
		Ranges: make(map[string]hcl.Range, len(attrs)),
	}

	var evalDiags hcl.Diagnostics
	for name, attr := range attrs {
		val, valDiags := attr.Expr.Value(nil)
		if valDiags.HasErrors() {
			evalDiags = append(evalDiags, valDiags...)
			continue
		}
		fv.Values[name] = val
		fv.Ranges[name] = attr.NameRange
	}
	if evalDiags.HasErrors() {
		return fv, fileParseError(path, evalDiags)
	}
	return fv, nil
}

// fileParseError converts HCL diagnostics into a location-aware VarError.
func fileParseError(path string, diags hcl.Diagnostics) error {
	for _, d := range diags {
		if d.Severity == hcl.DiagError {
			line, column := 0, 0
			if d.Subject != nil {
				line = d.Subject.Start.Line
				column = d.Subject.Start.Column
			}
			return &VarError{
				VarName: "",
				Origin:  OriginValuesFile,
				Source:  path,
				Line:    line,
				Column:  column,
				Message: d.Detail,
			}
		}
	}
	return &VarError{Origin: OriginValuesFile, Source: path, Message: "failed to parse values file"}
}

// DiscoverValuesFiles returns the values files present in dir that Terraform
// loads automatically, in deterministic order:
//
//  1. terraform.tfvars / terraform.tfvars.json (whichever exist, in that order)
//  2. every other *.tfvars / *.tfvars.json file, sorted by file name
//
// Missing directories yield an empty list without error.
func DiscoverValuesFiles(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}

	var (
		auto     = make([]string, 0, len(defaultAutoFiles))
		optional []string
	)
	autoSeen := make(map[string]bool)

	for _, name := range defaultAutoFiles {
		path := filepath.Join(dir, name)
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			auto = append(auto, path)
			autoSeen[name] = true
		}
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if autoSeen[name] {
			continue
		}
		if hasTfvarsSuffix(name) {
			optional = append(optional, filepath.Join(dir, name))
		}
	}
	sort.Strings(optional)
	return append(auto, optional...)
}

// hasTfvarsSuffix reports whether name ends in .tfvars or .tfvars.json. The
// latter cannot be detected with filepath.Ext because that returns ".json".
func hasTfvarsSuffix(name string) bool {
	return strings.HasSuffix(name, ".tfvars") || strings.HasSuffix(name, ".tfvars.json")
}

// MergeValuesFiles layers already parsed values files onto one another in the
// given order. Later files win at the per-key level, matching Terraform
// semantics where a later -var-file overrides an earlier one.
//
// A file that failed to parse is passed in failedPaths with its error; the
// variable names it attempted to define are returned through poisoned so the
// caller can mark them pending rather than silently using a default.
func MergeValuesFiles(files []*FileValues) (merged map[string]ExternalValue, order []string) {
	merged = make(map[string]ExternalValue)
	order = make([]string, 0, len(files))

	for _, f := range files {
		order = append(order, f.Path)
		for name, val := range f.Values {
			line, column := 0, 0
			if r, ok := f.Ranges[name]; ok {
				line = r.Start.Line
				column = r.Start.Column
			}
			// later file overrides earlier file at key granularity
			merged[name] = NewFileValue(val, f.Path, line, column)
		}
	}
	return merged, order
}

// describePosition renders file:line:column for error messages.
func describePosition(path string, line, column int) string {
	if line > 0 {
		return fmt.Sprintf("%s:%d:%d", path, line, column)
	}
	return path
}
