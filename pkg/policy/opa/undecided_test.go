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
	"testing"

	"github.com/tenable/terrascan/pkg/iac-providers/output"
	"github.com/tenable/terrascan/pkg/policy"
)

func TestApplicableResourceType(t *testing.T) {
	// metadata path
	withMeta := &policy.RegoData{
		Metadata: policy.RegoMetadata{ResourceType: "aws_s3_bucket"},
	}
	if got := applicableResourceType(withMeta); got != "aws_s3_bucket" {
		t.Fatalf("metadata resource_type wrong: %q", got)
	}

	// rego text fallback path
	fromRego := &policy.RegoData{
		RawRego: []byte("package accurics\nr[x]{ b = input.aws_security_group[_] }"),
	}
	if got := applicableResourceType(fromRego); got != "aws_security_group" {
		t.Fatalf("rego fallback resource type wrong: %q", got)
	}

	// nothing usable
	if got := applicableResourceType(&policy.RegoData{}); got != "" {
		t.Fatalf("expected empty type, got %q", got)
	}
}

func TestCollectUndecided(t *testing.T) {
	engine := &Engine{}
	regoData := &policy.RegoData{
		Metadata: policy.RegoMetadata{
			Name:         "openIngress",
			Description:  "no open ingress",
			ID:           "TEST.SG.1",
			Severity:     "HIGH",
			Category:     "Network",
			ResourceType: "aws_security_group",
		},
	}

	all := output.AllResourceConfigs{
		"aws_security_group": {
			{
				ID:   "aws_security_group.open",
				Name: "open",
				Type: "aws_security_group",
				Config: map[string]interface{}{
					"ingress": []interface{}{
						map[string]interface{}{"cidr_blocks": "${var.cidrs}"},
					},
				},
				PendingAttributes: []output.PendingAttribute{
					{Path: "ingress[0].cidr_blocks", Expression: "${var.cidrs}"},
				},
			},
			{
				// a fully resolved resource must not be marked undecided
				ID:     "aws_security_group.closed",
				Name:   "closed",
				Type:   "aws_security_group",
				Config: map[string]interface{}{"name": "closed"},
			},
		},
	}
	input := policy.EngineInput{InputData: &all}

	got := engine.collectUndecided(regoData, input)
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 undecided rule, got %d: %#v", len(got), got)
	}
	u := got[0]
	if u.RuleName != "openIngress" || u.ResourceName != "open" {
		t.Fatalf("undecided entry targets wrong rule/resource: %#v", u)
	}
	if len(u.PendingAttributes) != 1 || u.PendingAttributes[0].Expression != "${var.cidrs}" {
		t.Fatalf("pending attributes not propagated: %#v", u.PendingAttributes)
	}

	// a rule for a different resource type produces nothing
	other := &policy.RegoData{
		Metadata: policy.RegoMetadata{Name: "x", ResourceType: "aws_s3_bucket"},
	}
	if len(engine.collectUndecided(other, input)) != 0 {
		t.Fatal("rule for unrelated resource type must not match")
	}
}
