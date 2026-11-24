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

// Package varscope resolves Terraform input variables for static analysis.
//
// A variable value can originate from, in increasing order of precedence:
//
//  1. the variable declaration's default value (lowest)
//  2. a process environment variable named TF_VAR_<name>
//  3. one or more values files (*.tfvars / HCL and *.tfvars.json / JSON),
//     merged in the deterministic order in which they are supplied
//  4. a command line -var override (highest)
//
// Module call arguments override the resolved value of the same-named
// variable, but only inside the scope of the called module. Scopes never leak
// across module boundaries: parent values do not flow into a child except
// through explicit call arguments, and child locals never flow back up.
//
// When a variable cannot be determined (no default and no external value, or
// an external value that fails type conversion) it is "pending". Any resource
// attribute that references a pending value is recorded as pending and is
// surfaced to the policy layer as "undecidable" instead of being silently
// treated as a pass.
package varscope

import (
	"fmt"

	"github.com/zclconf/go-cty/cty"
)

// Origin identifies where a variable value came from. It makes precedence
// explainable: every resolved value carries the source that won.
type Origin string

const (
	// OriginDefault means the value is the variable declaration default.
	OriginDefault Origin = "default"

	// OriginEnvVar means the value came from a TF_VAR_<name> env variable.
	OriginEnvVar Origin = "env"

	// OriginValuesFile means the value came from a .tfvars/.tfvars.json file.
	OriginValuesFile Origin = "tfvars"

	// OriginCLI means the value came from a command line -var override.
	OriginCLI Origin = "cli"

	// OriginModuleCall means the value came from a module call argument and
	// is therefore only valid inside the called module's scope.
	OriginModuleCall Origin = "module-call"
)

// originRank defines the global precedence of origins. A higher rank wins.
// Module call arguments are ranked above every external source because they
// apply only within a child scope and are the closest binding.
func originRank(o Origin) int {
	switch o {
	case OriginDefault:
		return 1
	case OriginEnvVar:
		return 2
	case OriginValuesFile:
		return 3
	case OriginCLI:
		return 4
	case OriginModuleCall:
		return 5
	default:
		return 0
	}
}

// ExternalValue is a variable value supplied from outside the module
// declaration (env, tfvars, cli). The raw string is kept for text-only
// sources that must be parsed according to the variable's parsing mode.
type ExternalValue struct {
	// Raw is the textual form of the value for env/cli sources.
	Raw string

	// Parsed is the already parsed cty value for tfvars sources. Nil for
	// env/cli sources, which are parsed against the declaration type.
	Parsed cty.Value

	Origin Origin
	Source string // file path for tfvars, "TF_VAR_<name>" for env, "-var" for cli
	Line   int    // 1-based line within Source when known, 0 otherwise
	Column int    // 1-based column within Source when known, 0 otherwise
	hasRaw bool
}

// NewTextValue builds an ExternalValue coming from a text-only source
// (environment variable or -var override).
func NewTextValue(raw string, origin Origin, source string) ExternalValue {
	return ExternalValue{Raw: raw, Origin: origin, Source: source, hasRaw: true}
}

// NewFileValue builds an ExternalValue coming from a values file.
func NewFileValue(val cty.Value, source string, line, column int) ExternalValue {
	return ExternalValue{Parsed: val, Origin: OriginValuesFile, Source: source, Line: line, Column: column}
}

// VarError records a problem observed while building external variable
// values. It always names the source and, when available, the exact position.
// A VarError never aborts the whole scan: the affected variable is marked
// pending and the error is reported through the directory error list.
type VarError struct {
	VarName string
	Origin  Origin
	Source  string
	Line    int
	Column  int
	Message string
}

// Error implements the error interface.
func (e VarError) Error() string {
	if e.Line > 0 {
		return fmt.Sprintf("%s: variable %q: %s (line %d, column %d)",
			e.Source, e.VarName, e.Message, e.Line, e.Column)
	}
	return fmt.Sprintf("%s: variable %q: %s", e.Source, e.VarName, e.Message)
}

// ResolvedVar is the outcome of resolving a single variable in a scope.
type ResolvedVar struct {
	// Value is the resolved native cty value. It is the zero cty.Value
	// (cty.NilVal) when Pending is true.
	Value cty.Value

	// Origin records which source supplied Value.
	Origin Origin

	// Source is the human readable location of the winning value.
	Source string

	// Sensitive mirrors the variable declaration's sensitive flag. Sensitive
	// values must never be written to logs or reports.
	Sensitive bool

	// Pending is true when the variable could not be determined.
	Pending bool

	// PendingReason explains why the variable is pending. It is safe to
	// surface because it never contains the value itself.
	PendingReason string
}

// PendingAttribute records a resource attribute whose value could not be
// determined because it (transitively) references a pending variable.
type PendingAttribute struct {
	// Path is the dotted attribute path inside the resource config,
	// e.g. "ingress.0.cidr_blocks".
	Path string

	// Expression is the unresolved reference expression, e.g. "${var.cidrs}".
	Expression string
}
