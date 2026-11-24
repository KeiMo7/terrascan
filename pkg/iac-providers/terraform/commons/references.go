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
	"reflect"
	"regexp"

	hclConfigs "github.com/hashicorp/terraform/configs"
	"github.com/tenable/terrascan/pkg/iac-providers/terraform/commons/varscope"
	"go.uber.org/zap"
)

var (
	// reference patterns
	refPattern = regexp.MustCompile(`\$\{.*\}`)
)

// RefResolver tries to resolve all the references in the given terraform
// config
type RefResolver struct {
	Config           *hclConfigs.Config
	ParentModuleCall *hclConfigs.ModuleCall

	// scope holds the resolved variable values visible in this module. It may
	// be nil for legacy call paths; when present it takes precedence over the
	// default-only resolution and enables pending (undecidable) detection.
	scope *varscope.Scope
}

// NewRefResolver returns a new RefResolver struct
func NewRefResolver(config *hclConfigs.Config,
	parentModuleCall *hclConfigs.ModuleCall) *RefResolver {
	return &RefResolver{
		Config:           config,
		ParentModuleCall: parentModuleCall,
	}
}

// NewScopedRefResolver returns a RefResolver bound to a resolved variable
// scope. The scope is consulted first for every variable reference; unknown
// variables are recorded as pending instead of being silently passed.
func NewScopedRefResolver(config *hclConfigs.Config,
	parentModuleCall *hclConfigs.ModuleCall, scope *varscope.Scope) *RefResolver {
	r := NewRefResolver(config, parentModuleCall)
	r.scope = scope
	return r
}

// isRef returns true if the given string is a variable reference
func isRef(val string) bool {
	return refPattern.MatchString(val) || isVarRef(val) || isModuleRef(val) || isLocalRef(val) || isLookupRef(val)
}

// ResolveRefs figures out all the variable references in the resource config
// and tries to replace the variable references, if possible,
// with actual value
func (r *RefResolver) ResolveRefs(config jsonObj) jsonObj {

	// iterate over every attribute in the config to resolve references
	for k, v := range config {

		var (
			vKind = reflect.TypeOf(v).Kind()
			vType = reflect.TypeOf(v).String()
		)

		switch {
		case vKind == reflect.String:

			// case 1: config value is a string; in resource config, refs
			// are of the type string
			value := r.ResolveStrRef(v.(string), "")

			// check if value is string and can be converted to map
			if valueStr, ok := value.(string); ok {
				var temp jsonObj
				err := json.Unmarshal([]byte(valueStr), &temp)
				if err != nil {
					zap.S().Debugf("failed to unmarshal json string %s", valueStr)
				} else {
					value = temp
				}
			}

			config[k] = value
		case vType == "tfv12.jsonObj" && vKind == reflect.Map:

			// case 2: config value is of type jsonObj
			config[k] = r.ResolveRefs(v.(jsonObj))

		case vType == "[]interface {}" && vKind == reflect.Slice:

			// case 3: config value is a []interface{}
			sConfig, ok := v.([]interface{})
			if !ok {
				continue
			}

			// if the golang native type is string, then try and resolve
			// references
			if len(sConfig) > 0 && reflect.TypeOf(sConfig[0]).Kind() == reflect.String {
				for i, c := range sConfig {
					sConfig[i] = r.ResolveStrRef(c.(string), "")
				}
				config[k] = sConfig
			}

		case vKind == reflect.Slice:

			// case 4: config value is of type []jsonObj

			// type assert interface{} -> []jsonObj
			sConfig, ok := v.([]jsonObj)
			if !ok {
				continue
			}

			// iterate over the []jsonObj to resolve refs
			for i, c := range sConfig {
				sConfig[i] = r.ResolveRefs(c)
			}
			config[k] = sConfig
		}
	}

	return config
}

// ResolveStrRef tries to resolve a string reference. Reference can be a
// variable "${var.foo}", cross module variable "${module.foo.bar}", local
// value "${local.foo}"
func (r *RefResolver) ResolveStrRef(ref, callerRef string) interface{} {

	switch {
	case isModuleRef(ref):

		// resolve cross module references
		return r.ResolveModuleRef(ref, callerRef, r.Config.Children)

	case isLocalRef(ref):

		// resolve local value references
		return r.ResolveLocalRef(ref, callerRef)

	case isLookupRef(ref):

		// resolve lookup references
		return r.ResolveLookupRef(ref, callerRef)

	case isVarRef(ref):

		/*
			Variable values initialized in the parent module call take
			precedence over values initialized in the same module,
			hence we execute the following steps:
			- resolve variables initialized in parent module call
			- resolve variables initialized in same module
		*/

		// A resolved, concrete value from the variable scope is authoritative:
		// external values (env, tfvars, cli), module call arguments and
		// defaults have already been merged with the correct precedence and
		// type conversion. Undeclared or still-pending variables deliberately
		// fall through to the legacy resolver so their output stays identical
		// to previous releases; the only addition for those is the pending
		// marker that turns an unknown value into an undecidable result.
		if r.scope != nil {
			varName, _ := getVarName(ref)
			if rv, ok := r.scope.Lookup(varName); ok && !rv.Pending {
				return r.ResolveScopedVar(ref, callerRef)
			}
		}

		// 1. resolve variables initialized in parent module call
		val := r.ResolveVarRefFromParentModuleCall(ref, callerRef)

		if reflect.TypeOf(val).Kind() == reflect.String {

			valStr := val.(string)
			/*
			 Now, if the output of ResolveVarRefFromParentModuleCall is a string
			 then there are following possibilities, output can be a:
			 - variable reference (resolve the variable reference)
			 - cross module variable reference in parent module call
			 	(resolve module reference)
			 - some other reference
			 - an absolute value (return from here)
			*/

			switch {
			case isVarRef(valStr):

				// resolve variable reference
				return r.ResolveVarRef(valStr, ref)

			case isModuleRef(valStr):

				// resolve cross module reference in parent module
				return r.ResolveModuleRef(valStr, ref, r.Config.Parent.Children)

			case isRef(valStr):

				// some other reference
				return r.ResolveStrRef(valStr, ref)
			}
		}

		// hopefully, the variable has been resolved here
		return val

	default:
		return ref
	}
}
