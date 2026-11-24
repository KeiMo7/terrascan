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
	"encoding/json"
	"os"
	"reflect"
	"strconv"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	hclConfigs "github.com/hashicorp/terraform/configs"
	"github.com/tenable/terrascan/pkg/iac-providers/output"
	"github.com/tenable/terrascan/pkg/iac-providers/terraform/commons/varscope"
	"github.com/zclconf/go-cty/cty"
	ctyjson "github.com/zclconf/go-cty/cty/json"
	"go.uber.org/zap"
)

// redactedSensitiveExpr replaces reference expressions that point at a
// sensitive variable when the value is undecidable, so neither the variable
// name nor any value leaks into a report.
const redactedSensitiveExpr = "${<sensitive>}"

// evalContext builds an HCL evaluation context that exposes every resolved
// variable in the bound scope. Pending variables are intentionally omitted:
// any expression that references them fails evaluation and is handled as
// undecidable rather than being given a fabricated value.
func (r *RefResolver) evalContext() *hcl.EvalContext {
	if r.scope == nil {
		return nil
	}
	vars := map[string]cty.Value{}
	for _, name := range r.scope.Names() {
		rv, _ := r.scope.Lookup(name)
		if rv.Pending {
			continue
		}
		vars[name] = rv.Value
	}
	ctx := &hcl.EvalContext{Variables: map[string]cty.Value{}}
	if len(vars) > 0 {
		ctx.Variables["var"] = cty.ObjectVal(vars)
	}
	return ctx
}

// evalContextFor builds an HCL eval context bound to an explicit scope without
// mutating the resolver's own bound scope.
func (r *RefResolver) evalContextFor(scope *varscope.Scope) *hcl.EvalContext {
	saved := r.scope
	r.scope = scope
	ctx := r.evalContext()
	r.scope = saved
	return ctx
}

// exprUsesPendingVar reports whether the expression references any variable
// that the scope could not resolve.
func exprUsesPendingVar(expr hcl.Expression, scope *varscope.Scope) bool {
	if scope == nil {
		return false
	}
	native, ok := expr.(hclsyntax.Expression)
	if !ok {
		return false
	}
	for _, traversal := range hclsyntax.Variables(native) {
		if len(traversal) < 2 {
			continue
		}
		root, ok := traversal[0].(hcl.TraverseRoot)
		if !ok || root.Name != "var" {
			continue
		}
		attr, ok := traversal[1].(hcl.TraverseAttr)
		if !ok {
			continue
		}
		if scope.IsPending(attr.Name) {
			return true
		}
	}
	return false
}

// EvaluateModuleCallArgs resolves every argument of a module call against the
// parent scope. Each argument becomes either a concrete value or a pending
// marker. The resulting map is handed to the child scope where call arguments
// override the child's own variable defaults only within that child.
func EvaluateModuleCallArgs(call *hclConfigs.ModuleCall, parentScope *varscope.Scope,
	parentResolver *RefResolver) map[string]varscope.CallArg {

	args := map[string]varscope.CallArg{}
	if call == nil {
		return args
	}

	body, ok := call.Config.(*hclsyntax.Body)
	if !ok {
		return evaluateJSONModuleCallArgs(call)
	}

	for name, attr := range body.Attributes {
		// an argument that directly (or transitively) uses a pending variable
		// cannot be decided in this scope
		if exprUsesPendingVar(attr.Expr, parentScope) {
			args[name] = varscope.CallArg{
				Pending: true,
				Reason:  "module call argument references an unresolved variable",
			}
			continue
		}

		// first try a real HCL evaluation using resolved variables. This keeps
		// numbers, bools, lists and maps at their native cty types.
		if parentScope != nil {
			if val, diags := attr.Expr.Value(parentResolver.evalContextFor(parentScope)); !diags.HasErrors() && val.IsKnown() && !val.IsNull() {
				args[name] = varscope.CallArg{Value: val}
				continue
			}
		}

		// expressions beyond plain variables (locals, module refs, functions)
		// go through the legacy resolver; the resulting native value is then
		// converted back to a cty value for the child scope.
		c := converterForCall(call)
		native, _, err := c.convertExpression(attr.Expr)
		if err != nil {
			args[name] = pendingArg("module call argument could not be evaluated statically")
			continue
		}
		if sjv, ok := native.(ctyjson.SimpleJSONValue); ok {
			args[name] = varscope.CallArg{Value: sjv.Value}
			continue
		}
		resolved := native
		if s, ok := native.(string); ok && isRef(s) {
			resolved = parentResolver.ResolveStrRef(s, "")
		}
		if ctyVal, ok := nativeToCty(resolved); ok {
			args[name] = varscope.CallArg{Value: ctyVal}
		} else {
			args[name] = pendingArg("module call argument could not be reduced to a concrete value")
		}
	}
	return args
}

func pendingArg(reason string) varscope.CallArg {
	return varscope.CallArg{Pending: true, Reason: reason}
}

// evaluateJSONModuleCallArgs handles JSON syntax module call bodies, whose
// expressions carry no source bytes for the legacy converter.
func evaluateJSONModuleCallArgs(call *hclConfigs.ModuleCall) map[string]varscope.CallArg {
	args := map[string]varscope.CallArg{}
	attrs, diags := call.Config.JustAttributes()
	if diags.HasErrors() {
		return args
	}
	for name, attr := range attrs {
		if val, valDiags := attr.Expr.Value(nil); !valDiags.HasErrors() && val.IsKnown() && !val.IsNull() {
			args[name] = varscope.CallArg{Value: val}
			continue
		}
		args[name] = pendingArg("module call argument could not be evaluated statically")
	}
	return args
}

// converterForCall builds a source-file converter for a module call body.
func converterForCall(call *hclConfigs.ModuleCall) converter {
	bytes, err := os.ReadFile(call.SourceAddrRange.Filename)
	if err != nil {
		zap.S().Debugf("could not read module call source: %v", err)
		return converter{}
	}
	return converter{bytes: bytes}
}

// nativeToCty converts a golang native value (as produced by the legacy
// resolver chain) into a cty value by round-tripping through JSON. Exact
// element typing is re-applied later by the child variable's declared type.
func nativeToCty(val interface{}) (cty.Value, bool) {
	if val == nil {
		return cty.NilVal, false
	}
	buf, err := json.Marshal(val)
	if err != nil {
		return cty.NilVal, false
	}
	ty, err := ctyjson.ImpliedType(buf)
	if err != nil {
		return cty.NilVal, false
	}
	ctyVal, err := ctyjson.Unmarshal(buf, ty)
	if err != nil {
		return cty.NilVal, false
	}
	return ctyVal, true
}

// ResolveScopedVar resolves a variable reference that the bound scope has
// already reduced to a concrete value. It is only invoked for resolved
// variables, so it mirrors the post-processing (string interpolation and map
// JSON encoding) of the legacy ResolveVarRef and sends values into resource
// configs through exactly the same path and with the same native types.
func (r *RefResolver) ResolveScopedVar(varRef, callerRef string) interface{} {
	varName, varExpr := getVarName(varRef)

	rv, present := r.scope.Lookup(varName)
	if !present || rv.Pending {
		// defensive: the caller is expected to route pending variables through
		// the legacy resolver, but never invent a value here. Leaving the
		// reference text intact makes it collected as pending downstream.
		return varRef
	}

	// convert the resolved cty value through the SAME converter the default
	// path uses, guaranteeing identical native types for identical values.
	val, err := convertCtyToGoNative(rv.Value)
	if err != nil || val == nil {
		zap.S().Debugf("failed to convert resolved variable %q: err=%v val=%v", varName, err, val)
		return varRef
	}

	valKind := reflect.TypeOf(val).Kind()
	if valKind == reflect.String || valKind == reflect.Map {
		valStr := ""
		if valKind == reflect.Map {
			data, mErr := json.Marshal(val)
			if mErr != nil {
				zap.S().Debugf("failed to marshal map for variable %q", varName)
				return varRef
			}
			valStr = string(data)
		} else {
			valStr = val.(string)
		}

		resolvedVal := strings.Replace(varRef, varExpr, valStr, 1)
		if varRef == resolvedVal {
			return varRef
		}
		if callerRef != "" && strings.Contains(resolvedVal, callerRef) {
			return resolvedVal
		}
		return r.ResolveStrRef(resolvedVal, varRef)
	}
	return val
}

// CollectPendingAttributes walks a resolved resource config and records every
// attribute whose value is still an unresolved reference. These are the
// undecidable attributes surfaced to the policy layer.
func CollectPendingAttributes(cfg map[string]interface{}) []output.PendingAttribute {
	var pending []output.PendingAttribute
	collectPending("", cfg, &pending)
	return pending
}

func collectPending(prefix string, node interface{}, pending *[]output.PendingAttribute) {
	switch v := node.(type) {
	case map[string]interface{}:
		for key, child := range v {
			path := key
			if prefix != "" {
				path = prefix + "." + key
			}
			collectPending(path, child, pending)
		}
	case jsonObj:
		for key, child := range v {
			path := key
			if prefix != "" {
				path = prefix + "." + key
			}
			collectPending(path, child, pending)
		}
	case []interface{}:
		for i, child := range v {
			collectPending(indexPath(prefix, i), child, pending)
		}
	case []jsonObj:
		for i, child := range v {
			collectPending(indexPath(prefix, i), child, pending)
		}
	case string:
		if isRef(v) {
			*pending = append(*pending, output.PendingAttribute{
				Path:       prefix,
				Expression: v,
			})
		}
	}
}

func indexPath(prefix string, index int) string {
	if prefix == "" {
		return ""
	}
	return prefix + "[" + strconv.Itoa(index) + "]"
}

// MaskSensitivePending rewrites pending attribute expressions so that a
// reference to a sensitive variable never reaches a report, not even by name.
// The concrete (resolved) value is never present in a pending expression, and
// here the reference itself is redacted as well.
func MaskSensitivePending(attrs []output.PendingAttribute, scope *varscope.Scope) []output.PendingAttribute {
	if scope == nil || len(attrs) == 0 {
		return attrs
	}
	for i := range attrs {
		if !exprReferencesSensitive(attrs[i].Expression, scope) {
			continue
		}
		attrs[i].Expression = redactedSensitiveExpr
	}
	return attrs
}

// exprReferencesSensitive reports whether any var.<name> inside the expression
// points at a variable declared sensitive in this scope.
func exprReferencesSensitive(expr string, scope *varscope.Scope) bool {
	for _, match := range varRefPattern.FindAllStringSubmatch(expr, -1) {
		if len(match) < 2 {
			continue
		}
		// group 1 is the name capture per varRefPattern: (\$\{)?var\.(?P<name>\w*)
		name := match[varRefPattern.SubexpIndex("name")]
		if rv, ok := scope.Lookup(name); ok && rv.Sensitive {
			return true
		}
	}
	return false
}
