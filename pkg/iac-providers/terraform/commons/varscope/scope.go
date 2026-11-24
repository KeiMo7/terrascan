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
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2"
	hclConfigs "github.com/hashicorp/terraform/configs"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"
)

// envVarPrefix is the Terraform convention for supplying input variables
// through the process environment.
const envVarPrefix = "TF_VAR_"

// Scope holds the resolved value of every variable visible in one module.
// Scopes form a tree that mirrors the module configuration tree: each child
// module gets its own Scope, and lookups never cross scope boundaries except
// through the explicit module call arguments handed to the child.
type Scope struct {
	// name is the module name ("root" for the root module).
	name string

	// vars maps variable name to its resolved outcome.
	vars map[string]ResolvedVar

	// parent is the enclosing module scope, used only for documentation and
	// cycle-safe traversal. Value lookups do not fall through to parent.
	parent *Scope
}

// Name returns the module name this scope belongs to.
func (s *Scope) Name() string { return s.name }

// Names returns every declared variable name in this scope, sorted.
func (s *Scope) Names() []string {
	out := make([]string, 0, len(s.vars))
	for name := range s.vars {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Lookup returns the resolved variable and true when the name is declared in
// this scope. It never consults the parent: scope isolation is a hard rule.
func (s *Scope) Lookup(name string) (ResolvedVar, bool) {
	v, ok := s.vars[name]
	return v, ok
}

// IsPending reports whether the named variable is unresolved in this scope.
// An undeclared variable is treated as pending so that a reference to it can
// never be mistaken for a concrete value.
func (s *Scope) IsPending(name string) bool {
	v, ok := s.vars[name]
	if !ok {
		return true
	}
	return v.Pending
}

// PendingVars returns the names of every variable that could not be resolved,
// sorted for deterministic output.
func (s *Scope) PendingVars() []string {
	out := make([]string, 0)
	for name, v := range s.vars {
		if v.Pending {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// SensitiveVars returns the names of variables declared sensitive, sorted.
func (s *Scope) SensitiveVars() []string {
	out := make([]string, 0)
	for name, v := range s.vars {
		if v.Sensitive {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// CallArg is the evaluated result of one argument in a module call. The
// commons layer evaluates the call expression against the parent scope: a
// concrete cty value, or a pending marker when the expression itself depends
// on an unresolved variable.
type CallArg struct {
	Value   cty.Value
	Pending bool
	Reason  string
}

// RootInput bundles every external source used to build the root scope.
// Precedence (lowest to highest): defaults < env < tfvars < cli.
type RootInput struct {
	// Variables are the root module's variable declarations.
	Variables map[string]*hclConfigs.Variable

	// EnvValues are values taken from TF_VAR_<name> environment variables.
	EnvValues map[string]ExternalValue

	// FileValues are merged values file entries (already ordered by the loader).
	FileValues map[string]ExternalValue

	// CLIValues are -var overrides.
	CLIValues map[string]ExternalValue

	// PoisonedVars are variables that appeared in a values file which failed
	// to parse. They are forced pending even if a default exists, because
	// silently dropping the intended override and using the default would be
	// a false negative.
	PoisonedVars map[string]string
}

// NewRootScope resolves every declared root module variable against the
// external sources and returns the scope plus non-fatal errors (undeclared
// variables, type mismatches, poisoned entries). Errors do not stop
// resolution: the offending variable is marked pending and the rest proceed.
func NewRootScope(name string, in RootInput) (*Scope, []error) {
	s := &Scope{name: scopeName(name), vars: make(map[string]ResolvedVar)}
	var errs []error

	// external names that reference a variable which was never declared
	errs = append(errs, reportUndeclared(in.Variables, in.EnvValues, in.FileValues, in.CLIValues)...)

	for varName, decl := range in.Variables {
		s.vars[varName] = resolveDeclared(varName, decl, in)
	}

	// surface reasons for every pending variable as errors, but keep scanning
	for _, varName := range s.PendingVars() {
		reason := s.vars[varName].PendingReason
		if reason == "" {
			continue
		}
		// only external-source failures become load errors; a merely required
		// variable with no value is a normal pending outcome, not an error
		if strings.HasPrefix(reason, "no value supplied") {
			continue
		}
		errs = append(errs, &VarError{VarName: varName, Message: reason})
	}
	return s, errs
}

// NewChildScope builds the scope of a called module. Call arguments override
// every external source and the declaration default, but only for this scope.
// Arguments not supplied by the caller fall back to the child's own default.
func NewChildScope(name string, variables map[string]*hclConfigs.Variable, parent *Scope, args map[string]CallArg) *Scope {
	s := &Scope{name: scopeName(name), parent: parent, vars: make(map[string]ResolvedVar)}

	for varName, decl := range variables {
		rv := resolveFromDefault(decl)

		if arg, ok := args[varName]; ok {
			if arg.Pending {
				rv = ResolvedVar{
					Sensitive:     decl.Sensitive,
					Pending:       true,
					PendingReason: arg.Reason,
				}
			} else {
				converted, err := convertToDeclaredType(arg.Value, decl)
				if err != nil {
					rv = ResolvedVar{
						Sensitive:     decl.Sensitive,
						Pending:       true,
						PendingReason: fmt.Sprintf("module call argument type mismatch: %s", err),
					}
				} else {
					rv = ResolvedVar{
						Value:     converted,
						Origin:    OriginModuleCall,
						Source:    "module call",
						Sensitive: decl.Sensitive,
					}
				}
			}
		}
		s.vars[varName] = rv
	}
	return s
}

// resolveDeclared applies the full precedence chain for one variable.
func resolveDeclared(varName string, decl *hclConfigs.Variable, in RootInput) ResolvedVar {
	// a poisoned values file entry must win over the default: the user clearly
	// intended to override, and guessing the default would hide a real value
	if reason, poisoned := in.PoisonedVars[varName]; poisoned {
		return ResolvedVar{
			Sensitive:     decl.Sensitive,
			Pending:       true,
			PendingReason: fmt.Sprintf("values file failed to parse: %s", reason),
		}
	}

	// pick the highest precedence external value that exists
	chosen, hasExternal := highestPrecedence(varName, in)
	if !hasExternal {
		return resolveFromDefault(decl)
	}

	val, err := materialize(varName, decl, chosen)
	if err != nil {
		return ResolvedVar{
			Sensitive:     decl.Sensitive,
			Pending:       true,
			PendingReason: err.Error(),
		}
	}
	return ResolvedVar{
		Value:     val,
		Origin:    chosen.Origin,
		Source:    chosen.Source,
		Sensitive: decl.Sensitive,
	}
}

// highestPrecedence returns the external value with the greatest origin rank.
// Ties cannot occur across distinct sources; within one source the loader has
// already applied per-key override ordering.
func highestPrecedence(varName string, in RootInput) (ExternalValue, bool) {
	candidates := make([]ExternalValue, 0, 3)
	if v, ok := in.EnvValues[varName]; ok {
		candidates = append(candidates, v)
	}
	if v, ok := in.FileValues[varName]; ok {
		candidates = append(candidates, v)
	}
	if v, ok := in.CLIValues[varName]; ok {
		candidates = append(candidates, v)
	}
	if len(candidates) == 0 {
		return ExternalValue{}, false
	}
	winner := candidates[0]
	for _, c := range candidates[1:] {
		if originRank(c.Origin) > originRank(winner.Origin) {
			winner = c
		}
	}
	return winner, true
}

// materialize turns an external value into a cty value that conforms to the
// variable declaration. Text-only sources (env, cli) are parsed with the
// declaration's parsing mode first, then converted. This is the same two-step
// approach Terraform itself uses, so "false" stays a string until the bool
// conversion makes it a real boolean false.
func materialize(varName string, decl *hclConfigs.Variable, ev ExternalValue) (cty.Value, error) {
	var raw cty.Value

	switch ev.Origin {
	case OriginValuesFile:
		raw = ev.Parsed
	default:
		// env and cli arrive as text. A zero parsing mode means the
		// declaration did not specify one; treat the text as an HCL
		// expression rather than panicking on an uninitialized mode.
		mode := decl.ParsingMode
		if mode == 0 {
			mode = hclConfigs.VariableParseHCL
		}
		parsed, diags := mode.Parse(varName, ev.Raw)
		if diags.HasErrors() {
			return cty.NilVal, fmt.Errorf("%s: failed to parse value for variable %q: %s",
				describePosition(ev.Source, ev.Line, ev.Column), varName, diagSummary(diags))
		}
		raw = parsed
	}

	converted, err := convertToDeclaredType(raw, decl)
	if err != nil {
		return cty.NilVal, fmt.Errorf("%s: %s", describePosition(ev.Source, ev.Line, ev.Column), err)
	}
	return converted, nil
}

// convertToDeclaredType converts a value to the variable's declared type.
// Variables without an explicit type use cty.DynamicPseudoType and keep the
// value's natural type (numbers stay numbers, lists stay lists).
func convertToDeclaredType(val cty.Value, decl *hclConfigs.Variable) (cty.Value, error) {
	if decl.Type == cty.NilType || decl.Type == cty.DynamicPseudoType {
		return val, nil
	}
	converted, err := convert.Convert(val, decl.Type)
	if err != nil {
		return cty.NilVal, fmt.Errorf("value for variable %q is not compatible with its declared type: %s",
			decl.Name, err)
	}
	return converted, nil
}

// resolveFromDefault returns the default value outcome. A variable with no
// default (a required variable) and no external value is pending.
func resolveFromDefault(decl *hclConfigs.Variable) ResolvedVar {
	if decl.Required() || decl.Default.IsNull() ||
		decl.Default.RawEquals(cty.NilVal) || !decl.Default.IsKnown() {
		return ResolvedVar{
			Sensitive:     decl.Sensitive,
			Pending:       true,
			PendingReason: "no value supplied for required variable and no default is declared",
		}
	}
	return ResolvedVar{
		Value:     decl.Default,
		Origin:    OriginDefault,
		Source:    "variable declaration default",
		Sensitive: decl.Sensitive,
	}
}

// reportUndeclared flags external values whose target variable does not exist
// in the module. Such entries can never be applied and must be visible rather
// than silently ignored.
func reportUndeclared(declared map[string]*hclConfigs.Variable, layers ...map[string]ExternalValue) []error {
	errs := make([]error, 0)
	for _, layer := range layers {
		names := make([]string, 0, len(layer))
		for n := range layer {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			if _, ok := declared[n]; ok {
				continue
			}
			ev := layer[n]
			errs = append(errs, &VarError{
				VarName: n,
				Origin:  ev.Origin,
				Source:  ev.Source,
				Line:    ev.Line,
				Column:  ev.Column,
				Message: "value supplied for undeclared variable",
			})
		}
	}
	return errs
}

// CollectEnvValues reads every TF_VAR_<name> variable from the supplied
// environment (os.Environ style "key=value" strings) and returns text
// ExternalValues keyed by the bare variable name. Taking the environment as an
// argument keeps the function pure and testable.
func CollectEnvValues(env []string) map[string]ExternalValue {
	out := make(map[string]ExternalValue)
	for _, kv := range env {
		idx := strings.IndexByte(kv, '=')
		if idx < 0 {
			continue
		}
		key, val := kv[:idx], kv[idx+1:]
		if !strings.HasPrefix(key, envVarPrefix) {
			continue
		}
		name := strings.TrimPrefix(key, envVarPrefix)
		if name == "" {
			continue
		}
		out[name] = NewTextValue(val, OriginEnvVar, key)
	}
	return out
}

// EnvFromOS is a convenience wrapper over CollectEnvValues for production.
func EnvFromOS() map[string]ExternalValue {
	return CollectEnvValues(os.Environ())
}

func diagSummary(diags hcl.Diagnostics) string {
	parts := make([]string, 0, len(diags))
	for _, d := range diags {
		if d.Severity == hcl.DiagError {
			parts = append(parts, d.Detail)
		}
	}
	return strings.Join(parts, "; ")
}

func scopeName(name string) string {
	if name == "" {
		return "root"
	}
	return name
}
