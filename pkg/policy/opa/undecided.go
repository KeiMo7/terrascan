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

package opa

import (
	"regexp"

	"github.com/tenable/terrascan/pkg/iac-providers/output"
	"github.com/tenable/terrascan/pkg/policy"
	"github.com/tenable/terrascan/pkg/results"
)

// inputResourcePattern captures the resource collection referenced from the
// rego input document, e.g. input.aws_s3_bucket[_]. It is the fallback used
// when a rule's metadata does not declare resource_type explicitly.
var inputResourcePattern = regexp.MustCompile(`input\.([a-zA-Z0-9_]+)`)

// collectUndecided returns one UndecidedRule per resource that (a) carries
// unresolved, pending attributes and (b) is in scope for the given rule.
//
// A rule that fires a concrete violation for a resource is still reported as
// a violation; this only handles resources for which the rule produced no
// violation because the relevant value is unknown. Undecided is never a pass.
func (e *Engine) collectUndecided(regoData *policy.RegoData,
	engineInput policy.EngineInput) []*results.UndecidedRule {

	resourceType := applicableResourceType(regoData)
	if resourceType == "" || engineInput.InputData == nil {
		return nil
	}

	resources, ok := (*engineInput.InputData)[resourceType]
	if !ok {
		return nil
	}

	var undecided []*results.UndecidedRule
	for i := range resources {
		resource := &resources[i]
		if len(resource.PendingAttributes) == 0 {
			continue
		}
		undecided = append(undecided, buildUndecidedRule(regoData, resource))
	}
	return undecided
}

// applicableResourceType resolves the resource type a rule applies to, using
// the metadata when present and falling back to the rego source otherwise.
func applicableResourceType(regoData *policy.RegoData) string {
	if regoData.Metadata.ResourceType != "" {
		return regoData.Metadata.ResourceType
	}
	if len(regoData.RawRego) == 0 {
		return ""
	}
	match := inputResourcePattern.FindSubmatch(regoData.RawRego)
	if len(match) < 2 {
		return ""
	}
	return string(match[1])
}

// buildUndecidedRule assembles the report entry, copying only safe metadata
// and the already-masked pending attributes (sensitive values never appear).
func buildUndecidedRule(regoData *policy.RegoData, resource *output.ResourceConfig) *results.UndecidedRule {
	pending := make([]results.PendingAttribute, 0, len(resource.PendingAttributes))
	for _, p := range resource.PendingAttributes {
		pending = append(pending, results.PendingAttribute{
			Path:       p.Path,
			Expression: p.Expression,
		})
	}
	return &results.UndecidedRule{
		RuleName:          regoData.Metadata.Name,
		Description:       regoData.Metadata.Description,
		RuleID:            regoData.Metadata.ID,
		Severity:          regoData.Metadata.Severity,
		Category:          regoData.Metadata.Category,
		ResourceName:      resource.Name,
		ResourceType:      resource.Type,
		ModuleName:        resource.ModuleName,
		File:              resource.Source,
		PlanRoot:          resource.PlanRoot,
		LineNumber:        resource.Line,
		PendingAttributes: pending,
	}
}
