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
	"os"
	"path/filepath"
	"testing"

	hclConfigs "github.com/hashicorp/terraform/configs"
	"github.com/zclconf/go-cty/cty"
)

// decl builds a *hclConfigs.Variable directly so the precedence tests do not
// depend on parsing HCL files.
func decl(name string, ty cty.Type, sensitive bool, def cty.Value) *hclConfigs.Variable {
	// the real HCL decoder always sets a parsing mode; primitive types use
	// literal parsing, complex types parse the text as an HCL expression.
	mode := hclConfigs.VariableParseHCL
	if ty.IsPrimitiveType() {
		mode = hclConfigs.VariableParseLiteral
	}
	v := &hclConfigs.Variable{
		Name:        name,
		Type:        ty,
		ParsingMode: mode,
		Sensitive:   sensitive,
		Default:     def,
	}
	return v
}

func strDecl(name string) *hclConfigs.Variable {
	return decl(name, cty.String, false, cty.NilVal)
}

func boolDecl(name string) *hclConfigs.Variable {
	return decl(name, cty.Bool, false, cty.NilVal)
}

func numDecl(name string) *hclConfigs.Variable {
	return decl(name, cty.Number, false, cty.NilVal)
}

func listDecl(name string) *hclConfigs.Variable {
	return decl(name, cty.List(cty.String), false, cty.NilVal)
}

func mapDecl(name string) *hclConfigs.Variable {
	return decl(name, cty.Map(cty.String), false, cty.NilVal)
}

// TestEnvParsingAndConversion verifies environment text is converted according
// to the variable's declared type: bool text becomes a real bool, number text
// a real number, and list/map text is parsed as HCL.
func TestEnvParsingAndConversion(t *testing.T) {
	vars := map[string]*hclConfigs.Variable{
		"b":  boolDecl("b"),
		"n":  numDecl("n"),
		"ls": listDecl("ls"),
		"m":  mapDecl("m"),
	}
	env := map[string]ExternalValue{
		"b":  NewTextValue("false", OriginEnvVar, "TF_VAR_b"),
		"n":  NewTextValue("42", OriginEnvVar, "TF_VAR_n"),
		"ls": NewTextValue(`["a","b"]`, OriginEnvVar, "TF_VAR_ls"),
		"m":  NewTextValue(`{"k"="v"}`, OriginEnvVar, "TF_VAR_m"),
	}
	scope, errs := NewRootScope("root", RootInput{Variables: vars, EnvValues: env})
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}

	// the string "false" must NOT be treated as a truthy string; it is a bool
	if got := mustLookup(t, scope, "b"); got.Value != cty.False {
		t.Fatalf("bool conversion wrong: %#v", got.Value)
	}
	if got := mustLookup(t, scope, "n"); got.Value.AsBigFloat().String() != "42" {
		t.Fatalf("number conversion wrong: %v", got.Value)
	}
	if got := mustLookup(t, scope, "ls"); len(got.Value.AsValueSlice()) != 2 || got.Origin != OriginEnvVar {
		t.Fatalf("list conversion/origin wrong: %#v", got)
	}
	if got := mustLookup(t, scope, "m"); got.Value.AsValueMap()["k"].AsString() != "v" {
		t.Fatalf("map conversion wrong: %#v", got.Value)
	}
}

// TestPrecedence verifies the single, explainable precedence chain:
// default < env < tfvars < cli, at per-key granularity.
func TestPrecedence(t *testing.T) {
	vars := map[string]*hclConfigs.Variable{
		"onlyDefault": decl("onlyDefault", cty.String, false, cty.StringVal("def")),
		"v":           strDecl("v"),
	}
	in := RootInput{
		Variables: vars,
		EnvValues: map[string]ExternalValue{
			"v": NewTextValue("env", OriginEnvVar, "TF_VAR_v"),
		},
		FileValues: map[string]ExternalValue{
			"v": NewFileValue(cty.StringVal("file"), "f.tfvars", 1, 1),
		},
		CLIValues: map[string]ExternalValue{
			"v": NewTextValue("cli", OriginCLI, "-var"),
		},
	}
	scope, _ := NewRootScope("root", in)

	if got := mustLookup(t, scope, "v"); got.Value.AsString() != "cli" || got.Origin != OriginCLI {
		t.Fatalf("cli should win, got %v origin %v", got.Value, got.Origin)
	}
	if got := mustLookup(t, scope, "onlyDefault"); got.Value.AsString() != "def" || got.Origin != OriginDefault {
		t.Fatalf("default fallback wrong: %v", got)
	}

	// drop cli -> file wins; drop file -> env wins
	in.CLIValues = nil
	scope, _ = NewRootScope("root", in)
	if got := mustLookup(t, scope, "v"); got.Value.AsString() != "file" {
		t.Fatalf("file should win after cli removed: %v", got.Value)
	}
	in.FileValues = nil
	scope, _ = NewRootScope("root", in)
	if got := mustLookup(t, scope, "v"); got.Value.AsString() != "env" {
		t.Fatalf("env should win after file removed: %v", got.Value)
	}
}

// TestPendingRequiredVariable ensures a required variable with no external
// value is pending, not silently defaulted or treated as a pass.
func TestPendingRequiredVariable(t *testing.T) {
	vars := map[string]*hclConfigs.Variable{"x": strDecl("x")}
	scope, _ := NewRootScope("root", RootInput{Variables: vars})
	got := mustLookup(t, scope, "x")
	if !got.Pending {
		t.Fatalf("required variable without value must be pending, got %#v", got)
	}
	if !scope.IsPending("x") {
		t.Fatal("IsPending should report true")
	}
	if !scope.IsPending("undeclared") {
		t.Fatal("undeclared variable should be treated as pending")
	}
}

// TestTypeMismatchIsPending ensures a value incompatible with the declared
// type becomes pending instead of being coerced into something misleading.
func TestTypeMismatchIsPending(t *testing.T) {
	vars := map[string]*hclConfigs.Variable{"b": boolDecl("b")}
	in := RootInput{
		Variables: vars,
		CLIValues: map[string]ExternalValue{"b": NewTextValue("not-a-bool", OriginCLI, "-var")},
	}
	scope, errs := NewRootScope("root", in)
	if len(errs) == 0 {
		t.Fatal("type mismatch should produce a load error")
	}
	if got := mustLookup(t, scope, "b"); !got.Pending {
		t.Fatalf("incompatible value must be pending, got %#v", got)
	}
}

// TestUndeclaredExternalValueIsError ensures values for variables that were
// never declared are reported rather than silently dropped.
func TestUndeclaredExternalValueIsError(t *testing.T) {
	vars := map[string]*hclConfigs.Variable{"real": strDecl("real")}
	in := RootInput{
		Variables: vars,
		CLIValues: map[string]ExternalValue{
			"ghost": NewTextValue("x", OriginCLI, "-var"),
		},
		EnvValues: map[string]ExternalValue{
			"ghost2": NewTextValue("y", OriginEnvVar, "TF_VAR_ghost2"),
		},
	}
	_, errs := NewRootScope("root", in)
	if len(errs) != 2 {
		t.Fatalf("expected 2 undeclared-variable errors, got %d: %v", len(errs), errs)
	}
}

// TestSensitiveFlagIsCarried ensures sensitivity is preserved and a pending
// sensitive variable is still detectable.
func TestSensitiveFlagIsCarried(t *testing.T) {
	vars := map[string]*hclConfigs.Variable{
		"secret": decl("secret", cty.String, true, cty.NilVal),
	}
	scope, _ := NewRootScope("root", RootInput{
		Variables: vars,
		CLIValues: map[string]ExternalValue{"secret": NewTextValue("s3cr3t", OriginCLI, "-var")},
	})
	got := mustLookup(t, scope, "secret")
	if !got.Sensitive || got.Value.AsString() != "s3cr3t" {
		t.Fatalf("sensitive flag/value wrong: %#v", got)
	}
	// without a value it stays pending and sensitive
	pending, _ := NewRootScope("root", RootInput{Variables: vars})
	if g := mustLookup(t, pending, "secret"); !g.Pending || !g.Sensitive {
		t.Fatalf("pending sensitive variable wrong: %#v", g)
	}
}

// TestChildScopeCallArgs verifies call arguments override child defaults only
// inside the child scope, parent values never leak, and each call is isolated.
func TestChildScopeCallArgs(t *testing.T) {
	childVars := map[string]*hclConfigs.Variable{
		"a": decl("a", cty.String, false, cty.StringVal("child-default")),
		"b": decl("b", cty.String, false, cty.NilVal),
	}
	parent, _ := NewRootScope("parent", RootInput{
		Variables: map[string]*hclConfigs.Variable{
			"a": strDecl("a"), // a exists in parent too
		},
		CLIValues: map[string]ExternalValue{"a": NewTextValue("parent-value", OriginCLI, "-var")},
	})

	// call one passes a explicitly; call two passes nothing
	callOne := NewChildScope("one", childVars, parent, map[string]CallArg{
		"a": {Value: cty.StringVal("from-call-one")},
		"b": {Value: cty.StringVal("b-one")},
	})
	callTwo := NewChildScope("two", childVars, parent, map[string]CallArg{
		"b": {Value: cty.StringVal("b-two")},
	})

	if g := mustLookup(t, callOne, "a"); g.Value.AsString() != "from-call-one" || g.Origin != OriginModuleCall {
		t.Fatalf("call arg must override: %#v", g)
	}
	if g := mustLookup(t, callTwo, "a"); g.Value.AsString() != "child-default" {
		t.Fatalf("missing call arg must fall back to child default, not parent: %#v", g)
	}
	if g := mustLookup(t, callOne, "b"); g.Value.AsString() != "b-one" {
		t.Fatalf("call one b wrong: %v", g.Value)
	}
	if g := mustLookup(t, callTwo, "b"); g.Value.AsString() != "b-two" {
		t.Fatalf("call sites must be independent, call two b wrong: %v", g.Value)
	}
	// parent's own value is untouched and never leaked into children
	if g := mustLookup(t, parent, "a"); g.Value.AsString() != "parent-value" {
		t.Fatalf("parent scope mutated: %v", g.Value)
	}
}

// TestChildScopePendingArg propagates an unresolved call argument as pending.
func TestChildScopePendingArg(t *testing.T) {
	childVars := map[string]*hclConfigs.Variable{"b": strDecl("b")}
	parent, _ := NewRootScope("parent", RootInput{
		Variables: map[string]*hclConfigs.Variable{"x": strDecl("x")},
	})
	child := NewChildScope("c", childVars, parent, map[string]CallArg{
		"b": {Pending: true, Reason: "references an unresolved variable"},
	})
	if g := mustLookup(t, child, "b"); !g.Pending {
		t.Fatalf("pending call arg must propagate, got %#v", g)
	}
}

func mustLookup(t *testing.T, s *Scope, name string) ResolvedVar {
	t.Helper()
	rv, ok := s.Lookup(name)
	if !ok {
		t.Fatalf("variable %q not found in scope", name)
	}
	return rv
}

// TestValuesFileHCLAndJSON exercises real files on disk, both syntaxes,
// deterministic ordering and layered override, plus a corrupted file being
// isolated while sibling files still load.
func TestValuesFileHCLAndJSON(t *testing.T) {
	dir := t.TempDir()

	hclFile := filepath.Join(dir, "a.tfvars")
	jsonFile := filepath.Join(dir, "b.tfvars.json")
	badFile := filepath.Join(dir, "bad.tfvars")

	if err := os.WriteFile(hclFile, []byte("v = \"from-hcl\"\nnum = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(jsonFile, []byte(`{"v":"from-json","flag":true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	// malformed HCL: an unclosed expression is a hard syntax error
	if err := os.WriteFile(badFile, []byte("broken = [1, 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// good files parse, both syntaxes
	fvA, err := LoadValuesFile(hclFile)
	if err != nil {
		t.Fatalf("hcl file: %v", err)
	}
	if fvA.Values["v"].AsString() != "from-hcl" {
		t.Fatal("hcl parse wrong")
	}
	fvB, err := LoadValuesFile(jsonFile)
	if err != nil {
		t.Fatalf("json file: %v", err)
	}
	if fvB.Values["flag"] != cty.True {
		t.Fatal("json parse wrong")
	}

	// later file overrides earlier one per key
	merged, order := MergeValuesFiles([]*FileValues{fvA, fvB})
	if len(order) != 2 || order[0] != hclFile || order[1] != jsonFile {
		t.Fatalf("merge order wrong: %v", order)
	}
	if merged["v"].Parsed.AsString() != "from-json" {
		t.Fatal("later values file must override earlier one")
	}
	if _, ok := merged["num"]; !ok {
		t.Fatal("non-overlapping keys must be retained")
	}

	// corrupted file yields a location-aware error and does not panic
	if _, err := LoadValuesFile(badFile); err == nil {
		t.Fatal("corrupted values file must return an error, not be silently skipped")
	} else {
		ve, ok := err.(*VarError)
		if !ok || ve.Source != badFile || ve.Line == 0 {
			t.Fatalf("error must name file and position: %v", err)
		}
	}
}

// TestDiscoverValuesFilesOrdering verifies auto discovery ordering:
// terraform.tfvars first, then remaining *.tfvars sorted by name.
func TestDiscoverValuesFilesOrdering(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"z.tfvars", "terraform.tfvars", "a.tfvars.json", "terraform.tfvars.json", "note.txt"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x=1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got := DiscoverValuesFiles(dir)
	want := []string{
		filepath.Join(dir, "terraform.tfvars"),
		filepath.Join(dir, "terraform.tfvars.json"),
		filepath.Join(dir, "a.tfvars.json"),
		filepath.Join(dir, "z.tfvars"),
	}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ordering wrong at %d: got %v want %v", i, got, want)
		}
	}
}

// TestCollectEnvValues verifies TF_VAR_* extraction and ignores other vars.
func TestCollectEnvValues(t *testing.T) {
	env := []string{"TF_VAR_a=hello", "TF_VAR_b=w=o=w", "PATH=/bin", "TF_VAR_=ignored"}
	got := CollectEnvValues(env)
	if got["a"].Raw != "hello" || got["a"].Origin != OriginEnvVar {
		t.Fatalf("env extraction wrong: %#v", got)
	}
	if got["b"].Raw != "w=o=w" {
		t.Fatalf("value containing '=' wrong: %q", got["b"].Raw)
	}
	if _, ok := got["PATH"]; ok {
		t.Fatal("non TF_VAR entries must be ignored")
	}
	if _, ok := got[""]; ok {
		t.Fatal("empty variable name must be ignored")
	}
}

// TestPoisonedVarBeatsDefault ensures a values file that failed while setting
// a variable never silently falls back to the default (a false negative).
func TestPoisonedVarBeatsDefault(t *testing.T) {
	vars := map[string]*hclConfigs.Variable{
		"v": decl("v", cty.String, false, cty.StringVal("default-val")),
	}
	scope, errs := NewRootScope("root", RootInput{
		Variables:    vars,
		PoisonedVars: map[string]string{"v": "bad.tfvars: syntax error"},
	})
	if len(errs) == 0 {
		t.Fatal("poisoned variable should surface an error")
	}
	if g := mustLookup(t, scope, "v"); !g.Pending {
		t.Fatalf("poisoned variable must be pending, not defaulted: %#v", g)
	}
}
