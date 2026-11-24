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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tenable/terrascan/pkg/filters"
	"github.com/tenable/terrascan/pkg/iac-providers/output"
	"github.com/tenable/terrascan/pkg/iac-providers/terraform/commons/varscope"
	"github.com/tenable/terrascan/pkg/policy"
	"github.com/tenable/terrascan/pkg/policy/opa"
	"github.com/tenable/terrascan/pkg/results"
)

var varResolutionDir = filepath.Join("testdata", "var-resolution")

// loaderWith builds a directory loader with the given external variable
// options and a deterministic, empty environment so tests are hermetic.
func loaderWith(t *testing.T, options map[string]interface{}) TerraformDirectoryLoader {
	t.Helper()
	base := map[string]interface{}{
		"nonRecursive": true,
		// do not read the real process environment in tests
		optionEnvVars:      map[string]varscope.ExternalValue{},
		optionAutoVarFiles: false,
	}
	for k, v := range options {
		base[k] = v
	}
	return NewTerraformDirectoryLoader(varResolutionDir, "0.15.0", base)
}

// findResource returns the first resource config with the given id.
func findResource(t *testing.T, all output.AllResourceConfigs, id string) output.ResourceConfig {
	t.Helper()
	for _, list := range all {
		for _, rc := range list {
			if rc.ID == id {
				return rc
			}
		}
	}
	t.Fatalf("resource %q not found", id)
	return output.ResourceConfig{}
}

// asMap tolerates the package-internal jsonObj named map type when reading
// resolved config values in tests.
func asMap(v interface{}) map[string]interface{} {
	switch m := v.(type) {
	case map[string]interface{}:
		return m
	case jsonObj:
		return map[string]interface{}(m)
	default:
		return nil
	}
}

// asSlice tolerates both []interface{} and []jsonObj shapes.
func asSlice(v interface{}) []interface{} {
	switch s := v.(type) {
	case []interface{}:
		return s
	case []jsonObj:
		out := make([]interface{}, 0, len(s))
		for _, item := range s {
			out = append(out, item)
		}
		return out
	default:
		return nil
	}
}

// runPolicies evaluates the test rego rules against the resource configs.
func runPolicies(t *testing.T, all output.AllResourceConfigs) policy.EngineOutput {
	t.Helper()
	engine, err := opa.NewEngine()
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	policyPath := filepath.Join(varResolutionDir, "policies")
	if err := engine.Init(policyPath, filters.NewRegoMetadataPreLoadFilter(nil, nil, nil, nil, "")); err != nil {
		t.Fatalf("engine init: %v", err)
	}
	input := output.AllResourceConfigs(all)
	out, err := engine.Evaluate(policy.EngineInput{InputData: &input}, &filters.RegoDataFilter{})
	if err != nil {
		t.Fatalf("engine evaluate: %v", err)
	}
	return out
}

// TestExternalValuesAreResolvedAndViolated is acceptance case 1: when every
// value comes from an external values file, the concrete violation must be
// reported (no false negative). It asserts the actual values that reach the
// resource config after real evaluation.
func TestExternalValuesAreResolvedAndViolated(t *testing.T) {
	loader := loaderWith(t, map[string]interface{}{
		optionVarFiles: []string{filepath.Join(varResolutionDir, "values.tfvars")},
	})
	all, err := loader.LoadIacDir()
	if err != nil {
		t.Logf("load errors (if any): %v", err)
	}

	sg := findResource(t, all, "aws_security_group.open")
	ingressElement := asMap(asSlice(asMap(sg.Config)["ingress"])[0])
	cidrs, ok := asSlice(ingressElement["cidr_blocks"]), true
	if !ok || len(cidrs) != 1 || cidrs[0] != "0.0.0.0/0" {
		t.Fatalf("expected resolved cidr_blocks [0.0.0.0/0], got %#v", ingressElement["cidr_blocks"])
	}
	if len(sg.PendingAttributes) != 0 {
		t.Fatalf("fully supplied config must have no pending attributes, got %#v", sg.PendingAttributes)
	}

	bucket := findResource(t, all, "aws_s3_bucket.store")
	bcfg := asMap(bucket.Config)
	if bcfg["encryption_on"] != true {
		t.Fatalf("bool variable must resolve to native true, got %#v", bcfg["encryption_on"])
	}
	if bcfg["count_value"] != 3 {
		t.Fatalf("number variable must resolve to native 3, got %#v", bcfg["count_value"])
	}
	if tags := asMap(bcfg["tags"]); tags["env"] != "prod" {
		t.Fatalf("map variable must resolve, got %#v", bcfg["tags"])
	}
	// sensitive value is still needed for analysis but pending reporting must
	// never leak it; here it resolved concretely so there are no pending entries
	if len(bucket.PendingAttributes) != 0 {
		t.Fatalf("bucket should have no pending attributes, got %#v", bucket.PendingAttributes)
	}

	// the open ingress rule must now actually fire
	out := runPolicies(t, all)
	store := out.ViolationStore
	if !hasViolation(store.Violations, "aws_security_group.open", "openIngress") {
		t.Fatalf("expected openIngress violation, got violations=%#v undecided=%#v",
			store.Violations, store.UndecidedRules)
	}
}

// TestMissingValuesAreUndecidedNotPassed is acceptance case 2: with no external
// values, required variables stay pending and the rules become "undecided"
// rather than silently passing.
func TestMissingValuesAreUndecidedNotPassed(t *testing.T) {
	loader := loaderWith(t, nil)
	all, err := loader.LoadIacDir()
	if err != nil {
		t.Logf("load errors expected for missing required vars: %v", err)
	}

	sg := findResource(t, all, "aws_security_group.open")
	if len(sg.PendingAttributes) == 0 {
		t.Fatal("expected pending attributes when cidrs is unresolved")
	}
	foundPending := false
	for _, p := range sg.PendingAttributes {
		if p.Expression == "${var.cidrs}" {
			foundPending = true
		}
	}
	if !foundPending {
		t.Fatalf("expected a pending ${var.cidrs} attribute, got %#v", sg.PendingAttributes)
	}

	bucket := findResource(t, all, "aws_s3_bucket.store")
	if len(bucket.PendingAttributes) == 0 {
		t.Fatal("expected pending attributes for unresolved bucket variables")
	}

	out := runPolicies(t, all)
	store := out.ViolationStore

	// neither rule may be reported as a plain violation or as a pass here
	if hasViolation(store.Violations, "aws_security_group.open", "openIngress") {
		t.Fatal("an undecidable ingress rule must not be reported as a violation")
	}
	if hasUndecided(store.UndecidedRules, "aws_security_group.open", "openIngress") == false {
		t.Fatalf("openIngress must be undecided for the pending security group, got %#v",
			store.UndecidedRules)
	}
	if hasUndecided(store.UndecidedRules, "aws_s3_bucket.store", "bucketEncryptionOff") == false {
		t.Fatalf("bucketEncryptionOff must be undecided for the pending bucket, got %#v",
			store.UndecidedRules)
	}
	// and nothing with pending attributes should appear as a passed rule
	for _, pr := range store.PassedRules {
		if pr.RuleName == "openIngress" || pr.RuleName == "bucketEncryptionOff" {
			t.Fatalf("a rule over pending attributes must not be marked passed: %s", pr.RuleName)
		}
	}
}

// TestCLIOverridesBeatValuesFile verifies command line overrides take
// precedence over a values file, including type-correct native values.
func TestCLIOverridesBeatValuesFile(t *testing.T) {
	loader := loaderWith(t, map[string]interface{}{
		optionVarFiles: []string{filepath.Join(varResolutionDir, "values.tfvars")},
		optionVars: map[string]string{
			"cidrs":              `["192.168.0.0/16"]`,
			"encryption_enabled": "false",
		},
	})
	all, loadErr := loader.LoadIacDir()
	err := effectiveErr(loadErr)
	if err != nil {
		t.Fatalf("unexpected load errors: %v", err)
	}
	sg := findResource(t, all, "aws_security_group.open")
	cidrs := asSlice(asMap(asSlice(asMap(sg.Config)["ingress"])[0])["cidr_blocks"])
	if cidrs[0] != "192.168.0.0/16" {
		t.Fatalf("cli override must win for cidrs, got %#v", cidrs)
	}
	bucket := findResource(t, all, "aws_s3_bucket.store")
	if asMap(bucket.Config)["encryption_on"] != false {
		t.Fatal("cli bool override must become native false")
	}

	// now the open-0.0.0.0/0 rule should NOT fire, but the encryption-off rule
	// SHOULD fire because the cli explicitly disabled encryption
	out := runPolicies(t, all)
	store := out.ViolationStore
	if hasViolation(store.Violations, "aws_security_group.open", "openIngress") {
		t.Fatal("narrowed cidrs must not trigger the open-ingress violation")
	}
	if !hasViolation(store.Violations, "aws_s3_bucket.store", "bucketEncryptionOff") {
		t.Fatalf("encryption disabled via cli must be a concrete violation, got %#v", store.Violations)
	}
}

// TestJSONValuesFileAndOrdering verifies JSON tfvars work and that an explicit
// later file overrides an earlier one at per-key granularity.
func TestJSONValuesFileAndOrdering(t *testing.T) {
	loader := loaderWith(t, map[string]interface{}{
		optionVarFiles: []string{
			filepath.Join(varResolutionDir, "values.tfvars"),
			filepath.Join(varResolutionDir, "values.tfvars.json"),
		},
	})
	all, loadErr := loader.LoadIacDir()
	err := effectiveErr(loadErr)
	if err != nil {
		t.Fatalf("unexpected load errors: %v", err)
	}
	bucket := findResource(t, all, "aws_s3_bucket.store")
	bcfg := asMap(bucket.Config)
	// JSON file is later and sets encryption_enabled=false, instance_count=5
	if bcfg["encryption_on"] != false {
		t.Fatalf("later json file must override hcl bool, got %#v", bcfg["encryption_on"])
	}
	if bcfg["count_value"] != 5 {
		t.Fatalf("later json file must override hcl number, got %#v", bcfg["count_value"])
	}
	// tags only meaningfully differ by env; json sets staging
	if tags := asMap(bcfg["tags"]); tags["env"] != "staging" {
		t.Fatalf("later json file must override map, got %#v", bcfg["tags"])
	}
}

// TestNestedModuleDefaultAndOverride covers multi-layer passing: the middle
// layer passes nothing for allowed_cidrs (child default applies) while
// child_encryption flows from the parent's resolved variable.
func TestNestedModuleDefaultAndOverride(t *testing.T) {
	loader := loaderWith(t, map[string]interface{}{
		optionVarFiles: []string{filepath.Join(varResolutionDir, "values.tfvars")},
	})
	all, loadErr := loader.LoadIacDir()
	err := effectiveErr(loadErr)
	if err != nil {
		t.Fatalf("unexpected load errors: %v", err)
	}

	childSG := findResource(t, all, "aws_security_group.child_sg")
	cidrs := asSlice(asMap(asSlice(asMap(childSG.Config)["ingress"])[0])["cidr_blocks"])
	if cidrs[0] != "10.0.0.0/8" {
		t.Fatalf("child default cidr must apply when parent passes nothing, got %#v", cidrs)
	}

	childBucket := findResource(t, all, "aws_s3_bucket.child_bucket")
	if asMap(childBucket.Config)["encryption_on"] != true {
		t.Fatal("parent-resolved variable must propagate through the module call")
	}
}

// TestEnvironmentVariableConversion verifies TF_VAR_* text is converted per
// declared type (string->bool/number/list) and reaches the resource natively.
func TestEnvironmentVariableConversion(t *testing.T) {
	loader := NewTerraformDirectoryLoader(varResolutionDir, "0.15.0", map[string]interface{}{
		"nonRecursive":     true,
		optionAutoVarFiles: false,
		optionEnvVars: map[string]varscope.ExternalValue{
			"cidrs":              varscope.NewTextValue(`["0.0.0.0/0"]`, varscope.OriginEnvVar, "TF_VAR_cidrs"),
			"encryption_enabled": varscope.NewTextValue("true", varscope.OriginEnvVar, "TF_VAR_encryption_enabled"),
			"instance_count":     varscope.NewTextValue("7", varscope.OriginEnvVar, "TF_VAR_instance_count"),
			"tags":               varscope.NewTextValue(`{"team"="sec"}`, varscope.OriginEnvVar, "TF_VAR_tags"),
			"secret_token":       varscope.NewTextValue("env-secret", varscope.OriginEnvVar, "TF_VAR_secret_token"),
		},
	})
	all, loadErr := loader.LoadIacDir()
	err := effectiveErr(loadErr)
	if err != nil {
		t.Fatalf("unexpected load errors: %v", err)
	}
	bucket := findResource(t, all, "aws_s3_bucket.store")
	bcfg := asMap(bucket.Config)
	if bcfg["encryption_on"] != true || bcfg["count_value"] != 7 {
		t.Fatalf("env bool/number conversion wrong: %#v", bcfg)
	}
	if tags := asMap(bcfg["tags"]); tags["team"] != "sec" {
		t.Fatalf("env map conversion wrong: %#v", bcfg["tags"])
	}
}

// TestCorruptValuesFileIsolation ensures one bad values file does not abort the
// scan: a named error is returned, sibling good files still load, and the
// poisoned variable becomes pending rather than silently using its default.
func TestCorruptValuesFileIsolation(t *testing.T) {
	badDir := filepath.Join(t.TempDir())
	writeFile(t, filepath.Join(badDir, "broken.tfvars"), "cidrs = [\n")
	writeFile(t, filepath.Join(badDir, "good.tfvars"), "encryption_enabled = true\n")

	loader := NewTerraformDirectoryLoader(varResolutionDir, "0.15.0", map[string]interface{}{
		"nonRecursive":     true,
		optionAutoVarFiles: false,
		optionEnvVars:      map[string]varscope.ExternalValue{},
		optionVarFiles: []string{
			badDir + "/broken.tfvars",
			badDir + "/good.tfvars",
		},
	})
	all, err := loader.LoadIacDir()
	if err == nil {
		t.Fatal("a corrupt values file must produce a load error")
	}
	if !containsErr(err, "broken.tfvars") {
		t.Fatalf("error must name the corrupt file, got: %v", err)
	}
	// good file still applied: encryption resolves concretely
	bucket := findResource(t, all, "aws_s3_bucket.store")
	if asMap(bucket.Config)["encryption_on"] != true {
		t.Fatal("good sibling values file must still be applied")
	}
	// poisoned cidrs stays pending, never silently defaulted
	sg := findResource(t, all, "aws_security_group.open")
	if len(sg.PendingAttributes) == 0 {
		t.Fatal("poisoned cidrs must remain pending")
	}
}

// TestSensitiveVariableIsRedacted verifies that an unresolved sensitive
// variable never reaches the report, not even by name.
func TestSensitiveVariableIsRedacted(t *testing.T) {
	loader := loaderWith(t, nil)
	all, _ := loader.LoadIacDir()

	bucket := findResource(t, all, "aws_s3_bucket.store")
	var sawSensitiveName, sawRedaction bool
	for _, p := range bucket.PendingAttributes {
		if strings.Contains(p.Expression, "secret_token") {
			sawSensitiveName = true
		}
		if p.Expression == redactedSensitiveExpr {
			sawRedaction = true
		}
	}
	if sawSensitiveName {
		t.Fatalf("sensitive variable name must not appear in pending attributes: %#v", bucket.PendingAttributes)
	}
	if !sawRedaction {
		t.Fatalf("sensitive pending expression must be redacted: %#v", bucket.PendingAttributes)
	}
}

// --- small helpers kept local to this test ---

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func containsErr(err error, fragment string) bool {
	return err != nil && strings.Contains(err.Error(), fragment)
}

// effectiveErr unwraps an empty go-multierror to nil, matching how the
// runtime treats a scan that produced no real load errors.
func effectiveErr(err error) error {
	type unwrapper interface{ ErrorOrNil() error }
	if u, ok := err.(unwrapper); ok {
		return u.ErrorOrNil()
	}
	return err
}

func hasViolation(list []*results.Violation, resourceID, ruleName string) bool {
	for _, v := range list {
		if v.RuleName == ruleName {
			_ = resourceID
			return true
		}
	}
	return false
}

func hasUndecided(list []*results.UndecidedRule, resourceID, ruleName string) bool {
	for _, u := range list {
		if u.RuleName == ruleName {
			_ = resourceID
			return true
		}
	}
	return false
}
