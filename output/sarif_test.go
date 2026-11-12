package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/open-policy-agent/conftest/internal/version"
	"github.com/owenrumney/go-sarif/v2/sarif"
)

func TestSARIF_OutputArtifactPaths(t *testing.T) {
	tests := []struct {
		file string
		uri  string
	}{
		{"config.yaml", "config.yaml"},
		{filepath.Join("configs", "service #1%.yaml"), "configs/service%20%231%25.yaml"},
		{"configs/already%20named.yaml", "configs/already%2520named.yaml"},
		{"configs/caf\u00e9.yaml", "configs/caf%C3%A9.yaml"},
	}
	for _, tt := range tests {
		for _, explicitLocation := range []bool{false, true} {
			name := "filename/" + tt.file
			if explicitLocation {
				name = "location/" + tt.file
			}
			t.Run(name, func(t *testing.T) {
				failure := Result{Message: "policy failed"}
				filename := tt.file
				if explicitLocation {
					filename = "other.yaml"
					failure.Location = &Location{File: tt.file, Line: json.Number("7")}
				}
				var buf bytes.Buffer
				if err := NewSARIF(&buf).Output(CheckResults{{
					FileName: filename, Namespace: "main", Failures: []Result{failure},
				}}); err != nil {
					t.Fatal(err)
				}
				var report sarif.Report
				if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
					t.Fatal(err)
				}
				location := report.Runs[0].Results[0].Locations[0].PhysicalLocation
				got := *location.ArtifactLocation.URI
				if got != tt.uri {
					t.Errorf("artifact URI = %q, want %q", got, tt.uri)
				}
				parsed, err := url.Parse(got)
				if err != nil {
					t.Fatal(err)
				}
				if parsed.Path != filepath.ToSlash(tt.file) || parsed.Fragment != "" || parsed.RawQuery != "" {
					t.Errorf("URI does not preserve the filename: %+v", parsed)
				}
				if explicitLocation && *location.Region.StartLine != 7 {
					t.Errorf("start line = %d, want 7", *location.Region.StartLine)
				}
			})
		}
	}
}

func TestSARIF_Output(t *testing.T) {
	tests := []struct {
		name     string
		results  []CheckResult
		wantErr  bool
		wantJSON string
	}{
		{
			name:    "empty results",
			results: []CheckResult{},
			wantJSON: mustJSON(t, map[string]any{
				"version": "2.1.0",
				"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
				"runs": []map[string]any{
					{
						"tool": map[string]any{
							"driver": map[string]any{
								"informationUri": toolURI,
								"name":           toolName,
								"version":        version.Version,
								"rules":          []any{},
							},
						},
						"invocations": []map[string]any{
							{
								"executionSuccessful": true,
								"exitCode":            0,
								"exitCodeDescription": "No policy violations found",
							},
						},
						"results": []any{},
					},
				},
			}),
		},
		{
			name: "single failure",
			results: []CheckResult{
				{
					FileName:  "test.yaml",
					Namespace: "main",
					Failures: []Result{
						{
							Message: "test failure",
							Metadata: map[string]any{
								"package": "test",
								"rule":    "rule1",
							},
						},
					},
				},
			},
			wantJSON: mustJSON(t, map[string]any{
				"version": "2.1.0",
				"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
				"runs": []map[string]any{
					{
						"tool": map[string]any{
							"driver": map[string]any{
								"informationUri": toolURI,
								"name":           toolName,
								"version":        version.Version,
								"rules": []map[string]any{
									{
										"id": "main/deny",
										"shortDescription": map[string]any{
											"text": "Policy violation",
										},
										"properties": map[string]any{
											"package": "test",
											"rule":    "rule1",
										},
									},
								},
							},
						},
						"invocations": []map[string]any{
							{
								"executionSuccessful": true,
								"exitCode":            1,
								"exitCodeDescription": "Policy violations found",
							},
						},
						"results": []map[string]any{
							{
								"ruleId":    "main/deny",
								"ruleIndex": 0,
								"level":     "error",
								"message": map[string]any{
									"text": "test failure",
								},
								"locations": []map[string]any{
									{
										"physicalLocation": map[string]any{
											"artifactLocation": map[string]any{
												"uri": "test.yaml",
											},
										},
									},
								},
							},
						},
					},
				},
			}),
		},
		{
			name: "single warning",
			results: []CheckResult{
				{
					FileName:  "test.yaml",
					Namespace: "main",
					Warnings: []Result{
						{
							Message: "test warning",
							Location: &Location{
								File: "test.yaml",
								Line: json.Number("123"),
							},
							Metadata: map[string]any{
								"foo": "bar",
							},
						},
					},
				},
			},
			wantJSON: mustJSON(t, map[string]any{
				"version": "2.1.0",
				"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
				"runs": []map[string]any{
					{
						"tool": map[string]any{
							"driver": map[string]any{
								"informationUri": toolURI,
								"name":           toolName,
								"version":        version.Version,
								"rules": []map[string]any{
									{
										"id": "main/warn",
										"shortDescription": map[string]any{
											"text": "Policy warning",
										},
										"properties": map[string]any{
											"foo": "bar",
										},
									},
								},
							},
						},
						"invocations": []map[string]any{
							{
								"executionSuccessful": true,
								"exitCode":            0,
								"exitCodeDescription": "Policy warnings found",
							},
						},
						"results": []map[string]any{
							{
								"ruleId":    "main/warn",
								"ruleIndex": 0,
								"level":     "warning",
								"message": map[string]any{
									"text": "test warning",
								},
								"locations": []map[string]any{
									{
										"physicalLocation": map[string]any{
											"artifactLocation": map[string]any{
												"uri": "test.yaml",
											},
											"region": map[string]any{
												"startLine": float64(123),
												"endLine":   float64(123),
											},
										},
									},
								},
							},
						},
					},
				},
			}),
		},
		{
			name: "single exception",
			results: []CheckResult{
				{
					FileName:  "test.yaml",
					Namespace: "main",
					Exceptions: []Result{
						{
							Message: "test exception",
							Metadata: map[string]any{
								"description": "test exception description",
							},
						},
					},
				},
			},
			wantJSON: mustJSON(t, map[string]any{
				"version": "2.1.0",
				"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
				"runs": []map[string]any{
					{
						"tool": map[string]any{
							"driver": map[string]any{
								"informationUri": toolURI,
								"name":           toolName,
								"version":        version.Version,
								"rules": []map[string]any{
									{
										"id": "main/allow",
										"shortDescription": map[string]any{
											"text": "Policy exception",
										},
										"properties": map[string]any{
											"description": "test exception description",
										},
									},
									{
										"id": "main/success",
										"shortDescription": map[string]any{
											"text": "Policy was satisfied successfully",
										},
										"properties": map[string]any{
											"description": "Policy was satisfied successfully",
										},
									},
								},
							},
						},
						"invocations": []map[string]any{
							{
								"executionSuccessful": true,
								"exitCode":            0,
								"exitCodeDescription": "No policy violations found",
							},
						},
						"results": []map[string]any{
							{
								"ruleId":    "main/allow",
								"ruleIndex": 0,
								"level":     "note",
								"message": map[string]any{
									"text": "test exception",
								},
								"locations": []map[string]any{
									{
										"physicalLocation": map[string]any{
											"artifactLocation": map[string]any{
												"uri": "test.yaml",
											},
										},
									},
								},
							},
							{
								"ruleId":    "main/success",
								"ruleIndex": 1,
								"level":     "none",
								"message": map[string]any{
									"text": "Policy was satisfied successfully",
								},
								"locations": []map[string]any{
									{
										"physicalLocation": map[string]any{
											"artifactLocation": map[string]any{
												"uri": "test.yaml",
											},
										},
									},
								},
							},
						},
					},
				},
			}),
		},
		{
			name: "skipped result",
			results: []CheckResult{
				{
					FileName:  "test.yaml",
					Namespace: "main",
					Successes: 0,
				},
			},
			wantJSON: mustJSON(t, map[string]any{
				"version": "2.1.0",
				"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
				"runs": []map[string]any{
					{
						"tool": map[string]any{
							"driver": map[string]any{
								"informationUri": toolURI,
								"name":           toolName,
								"version":        version.Version,
								"rules": []map[string]any{
									{
										"id": "main/skip",
										"shortDescription": map[string]any{
											"text": "Policy check was skipped",
										},
										"properties": map[string]any{
											"description": "Policy check was skipped",
										},
									},
								},
							},
						},
						"invocations": []map[string]any{
							{
								"executionSuccessful": true,
								"exitCode":            0,
								"exitCodeDescription": "No policy violations found",
							},
						},
						"results": []map[string]any{
							{
								"ruleId":    "main/skip",
								"ruleIndex": 0,
								"level":     "none",
								"message": map[string]any{
									"text": "Policy check was skipped",
								},
								"locations": []map[string]any{
									{
										"physicalLocation": map[string]any{
											"artifactLocation": map[string]any{
												"uri": "test.yaml",
											},
										},
									},
								},
							},
						},
					},
				},
			}),
		},
		{
			name: "multiple results same rule",
			results: []CheckResult{
				{
					FileName:  "test1.yaml",
					Namespace: "main",
					Failures: []Result{
						{
							Message: "test failure 1",
							Metadata: map[string]any{
								"package": "test",
								"rule":    "rule1",
							},
						},
						{
							Message: "test failure 2",
							Metadata: map[string]any{
								"package": "test",
								"rule":    "rule1",
							},
						},
					},
				},
			},
			wantJSON: mustJSON(t, map[string]any{
				"version": "2.1.0",
				"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
				"runs": []map[string]any{
					{
						"tool": map[string]any{
							"driver": map[string]any{
								"informationUri": toolURI,
								"name":           toolName,
								"version":        version.Version,
								"rules": []map[string]any{
									{
										"id": "main/deny",
										"shortDescription": map[string]any{
											"text": "Policy violation",
										},
										"properties": map[string]any{
											"package": "test",
											"rule":    "rule1",
										},
									},
								},
							},
						},
						"invocations": []map[string]any{
							{
								"executionSuccessful": true,
								"exitCode":            1,
								"exitCodeDescription": "Policy violations found",
							},
						},
						"results": []map[string]any{
							{
								"ruleId":    "main/deny",
								"ruleIndex": 0,
								"level":     "error",
								"message": map[string]any{
									"text": "test failure 1",
								},
								"locations": []map[string]any{
									{
										"physicalLocation": map[string]any{
											"artifactLocation": map[string]any{
												"uri": "test1.yaml",
											},
										},
									},
								},
							},
							{
								"ruleId":    "main/deny",
								"ruleIndex": 0,
								"level":     "error",
								"message": map[string]any{
									"text": "test failure 2",
								},
								"locations": []map[string]any{
									{
										"physicalLocation": map[string]any{
											"artifactLocation": map[string]any{
												"uri": "test1.yaml",
											},
										},
									},
								},
							},
						},
					},
				},
			}),
		},
		{
			name: "successful policy check",
			results: []CheckResult{
				{
					FileName:  "test.yaml",
					Namespace: "main",
					Successes: 1,
				},
			},
			wantJSON: mustJSON(t, map[string]any{
				"version": "2.1.0",
				"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
				"runs": []map[string]any{
					{
						"tool": map[string]any{
							"driver": map[string]any{
								"informationUri": toolURI,
								"name":           toolName,
								"version":        version.Version,
								"rules": []map[string]any{
									{
										"id": "main/success",
										"shortDescription": map[string]any{
											"text": "Policy was satisfied successfully",
										},
										"properties": map[string]any{
											"description": "Policy was satisfied successfully",
										},
									},
								},
							},
						},
						"invocations": []map[string]any{
							{
								"executionSuccessful": true,
								"exitCode":            0,
								"exitCodeDescription": "No policy violations found",
							},
						},
						"results": []map[string]any{
							{
								"ruleId":    "main/success",
								"ruleIndex": 0,
								"level":     "none",
								"message": map[string]any{
									"text": "Policy was satisfied successfully",
								},
								"locations": []map[string]any{
									{
										"physicalLocation": map[string]any{
											"artifactLocation": map[string]any{
												"uri": "test.yaml",
											},
										},
									},
								},
							},
						},
					},
				},
			}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			s := NewSARIF(&buf)

			err := s.Output(tt.results)
			if (err != nil) != tt.wantErr {
				t.Errorf("SARIF.Output() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				compareJSON(t, buf.String(), tt.wantJSON)
			}
		})
	}
}

func TestRuleIdentityRuleID(t *testing.T) {
	tests := []struct {
		name     string
		identity RuleIdentity
		want     string
	}{
		{
			name:     "plain deny keeps historical id",
			identity: RuleIdentity{Namespace: "main", Name: "deny", Kind: ruleKindDeny},
			want:     "main/deny",
		},
		{
			name:     "plain violation is reported as deny",
			identity: RuleIdentity{Namespace: "main", Name: "violation", Kind: ruleKindDeny},
			want:     "main/deny",
		},
		{
			name:     "plain warn keeps historical id",
			identity: RuleIdentity{Namespace: "main", Name: "warn", Kind: ruleKindWarn},
			want:     "main/warn",
		},
		{
			name:     "named deny rule uses full rego name",
			identity: RuleIdentity{Namespace: "main", Name: "deny_tags", Kind: ruleKindDeny},
			want:     "main/deny_tags",
		},
		{
			name:     "named violation rule uses full rego name",
			identity: RuleIdentity{Namespace: "main", Name: "violation_critical", Kind: ruleKindDeny},
			want:     "main/violation_critical",
		},
		{
			name:     "named warn rule uses full rego name",
			identity: RuleIdentity{Namespace: "main", Name: "warn_deprecated", Kind: ruleKindWarn},
			want:     "main/warn_deprecated",
		},
		{
			name:     "different namespace",
			identity: RuleIdentity{Namespace: "kubernetes", Name: "deny", Kind: ruleKindDeny},
			want:     "kubernetes/deny",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.identity.RuleID(); got != tt.want {
				t.Errorf("RuleID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestResultIdentity(t *testing.T) {
	tests := []struct {
		name      string
		result    Result
		namespace string
		fallback  string
		want      RuleIdentity
	}{
		{
			name: "named deny rule is resolved from query",
			result: Result{
				Message:  "boom",
				Metadata: map[string]any{"query": "data.main.deny_tags"},
			},
			namespace: "main",
			fallback:  ruleKindDeny,
			want:      RuleIdentity{Namespace: "main", Name: "deny_tags", Kind: ruleKindDeny},
		},
		{
			name: "named warn rule is resolved from query",
			result: Result{
				Message:  "careful",
				Metadata: map[string]any{"query": "data.kube.warn_deprecated", "rule": "x"},
			},
			namespace: "kube",
			fallback:  ruleKindWarn,
			want:      RuleIdentity{Namespace: "kube", Name: "warn_deprecated", Kind: ruleKindWarn},
		},
		{
			name: "plain deny query maps to deny kind",
			result: Result{
				Message:  "boom",
				Metadata: map[string]any{"query": "data.main.deny"},
			},
			namespace: "main",
			fallback:  ruleKindDeny,
			want:      RuleIdentity{Namespace: "main", Name: "deny", Kind: ruleKindDeny},
		},
		{
			name:      "missing metadata falls back to namespace and kind",
			result:    Result{Message: "boom"},
			namespace: "main",
			fallback:  ruleKindDeny,
			want:      RuleIdentity{Namespace: "main", Name: "", Kind: ruleKindDeny},
		},
		{
			name: "success placeholder falls back to success kind",
			result: Result{
				Message:  successDesc,
				Metadata: map[string]any{"description": successDesc},
			},
			namespace: "main",
			fallback:  ruleKindSuccess,
			want:      RuleIdentity{Namespace: "main", Name: "", Kind: ruleKindSuccess},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.result.identity(tt.namespace, tt.fallback)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("identity() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestSARIF_RuleAttribution ensures that distinct Rego rules in the same
// namespace produce distinct SARIF rules with stable rule indices, and that
// each violation is attributed to the rule that actually produced it. This is
// the regression test for rules previously collapsed into a single
// "namespace/deny" entry whose metadata came from the first rule only.
func TestSARIF_RuleAttribution(t *testing.T) {
	results := CheckResults{
		{
			FileName:  "deployment.yaml",
			Namespace: "main",
			Failures: []Result{
				{
					Message: "same message",
					Metadata: map[string]any{
						"query": "data.main.deny_labels",
						"rule":  "labels",
					},
					Location: &Location{File: "deployment.yaml", Line: json.Number("10")},
				},
				{
					Message: "same message",
					Metadata: map[string]any{
						"query": "data.main.deny_replicas",
						"rule":  "replicas",
					},
					Location: &Location{File: "deployment.yaml", Line: json.Number("42")},
				},
			},
			Warnings: []Result{
				{
					Message: "same message",
					Metadata: map[string]any{
						"query": "data.main.warn_deprecated",
						"rule":  "deprecated",
					},
					Location: &Location{File: "deployment.yaml", Line: json.Number("7")},
				},
			},
		},
		{
			FileName:  "service.yaml",
			Namespace: "main",
			Failures: []Result{
				{
					// A second occurrence of the first rule, in another file,
					// must reuse the existing rule and its index.
					Message:  "another failure",
					Metadata: map[string]any{"query": "data.main.deny_labels"},
				},
			},
		},
	}

	var buf bytes.Buffer
	if err := NewSARIF(&buf).Output(results); err != nil {
		t.Fatal(err)
	}

	var report sarif.Report
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	run := report.Runs[0]

	wantRules := map[string]map[string]any{
		"main/deny_labels":     {"index": uint(0), "rule": "labels", "query": "data.main.deny_labels", "level": "error", "desc": failureDesc},
		"main/deny_replicas":   {"index": uint(1), "rule": "replicas", "query": "data.main.deny_replicas", "level": "error", "desc": failureDesc},
		"main/warn_deprecated": {"index": uint(2), "rule": "deprecated", "query": "data.main.warn_deprecated", "level": "warning", "desc": warningDesc},
	}
	if len(run.Tool.Driver.Rules) != len(wantRules) {
		t.Fatalf("got %d rules, want %d: %#v", len(run.Tool.Driver.Rules), len(wantRules), run.Tool.Driver.Rules)
	}
	for ruleIndex, rule := range run.Tool.Driver.Rules {
		want, ok := wantRules[rule.ID]
		if !ok {
			t.Errorf("unexpected rule %q", rule.ID)
			continue
		}
		if uint(ruleIndex) != want["index"] {
			t.Errorf("rule %q position = %d, want %v", rule.ID, ruleIndex, want["index"])
		}
		if *rule.ShortDescription.Text != want["desc"] {
			t.Errorf("rule %q description = %q, want %q", rule.ID, *rule.ShortDescription.Text, want["desc"])
		}
		if got := fmt.Sprint(rule.Properties["rule"]); got != want["rule"] {
			t.Errorf("rule %q properties.rule = %v, want %v", rule.ID, got, want["rule"])
		}
		if got := fmt.Sprint(rule.Properties["query"]); got != want["query"] {
			t.Errorf("rule %q query metadata = %v, want %v", rule.ID, got, want["query"])
		}
	}

	type expectation struct {
		ruleID string
		index  uint
		level  string
		line   int
		file   string
	}
	wantResults := []expectation{
		{ruleID: "main/deny_labels", index: 0, level: "error", line: 10, file: "deployment.yaml"},
		{ruleID: "main/deny_replicas", index: 1, level: "error", line: 42, file: "deployment.yaml"},
		{ruleID: "main/warn_deprecated", index: 2, level: "warning", line: 7, file: "deployment.yaml"},
		{ruleID: "main/deny_labels", index: 0, level: "error", line: 0, file: "service.yaml"},
	}
	if len(run.Results) != len(wantResults) {
		t.Fatalf("got %d results, want %d", len(run.Results), len(wantResults))
	}
	for i, want := range wantResults {
		got := run.Results[i]
		if *got.RuleID != want.ruleID {
			t.Errorf("result %d ruleId = %q, want %q", i, *got.RuleID, want.ruleID)
		}
		if *got.RuleIndex != want.index {
			t.Errorf("result %d ruleIndex = %d, want %d", i, *got.RuleIndex, want.index)
		}
		if *got.Level != want.level {
			t.Errorf("result %d level = %q, want %q", i, *got.Level, want.level)
		}
		location := got.Locations[0].PhysicalLocation
		if *location.ArtifactLocation.URI != want.file {
			t.Errorf("result %d file = %q, want %q", i, *location.ArtifactLocation.URI, want.file)
		}
		if want.line != 0 && *location.Region.StartLine != want.line {
			t.Errorf("result %d line = %d, want %d", i, *location.Region.StartLine, want.line)
		}
	}

	invocation := run.Invocations[0]
	if *invocation.ExitCode != results.ExitCode() || *invocation.ExitCode != 1 {
		t.Errorf("exit code = %d, want 1 (matching CheckResults.ExitCode)", *invocation.ExitCode)
	}
	if *invocation.ExecutionSuccessful != true {
		t.Errorf("executionSuccessful = %v, want true", *invocation.ExecutionSuccessful)
	}
}

// TestSARIF_JSONAndSARIFShareRuleIdentity verifies that the rule identity
// driving SARIF is derived from the same metadata that is serialised in the
// JSON output, so both formats trace a violation back to the same Rego rule.
func TestSARIF_JSONAndSARIFShareRuleIdentity(t *testing.T) {
	result := Result{
		Message:  "boom",
		Metadata: map[string]any{"query": "data.main.deny_tags", "severity": "high"},
	}
	results := CheckResults{{
		FileName: "test.yaml", Namespace: "main", Failures: []Result{result},
	}}

	var jsonBuf, sarifBuf bytes.Buffer
	if err := NewJSON(&jsonBuf).Output(results); err != nil {
		t.Fatal(err)
	}
	if err := NewSARIF(&sarifBuf).Output(results); err != nil {
		t.Fatal(err)
	}

	var jsonOutput CheckResults
	if err := json.Unmarshal(jsonBuf.Bytes(), &jsonOutput); err != nil {
		t.Fatal(err)
	}
	jsonQuery, _ := jsonOutput[0].Failures[0].Metadata["query"].(string)

	var report sarif.Report
	if err := json.Unmarshal(sarifBuf.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	rule := report.Runs[0].Tool.Driver.Rules[0]
	sarifQuery := fmt.Sprint(rule.Properties["query"])

	if sarifQuery != jsonQuery {
		t.Errorf("SARIF rule query %q does not match JSON metadata query %q", sarifQuery, jsonQuery)
	}
	wantID := "main/deny_tags"
	if rule.ID != wantID {
		t.Errorf("rule id = %q, want %q derived from shared query %q", rule.ID, wantID, jsonQuery)
	}
	if *report.Runs[0].Results[0].RuleIndex != 0 {
		t.Errorf("ruleIndex = %d, want 0", *report.Runs[0].Results[0].RuleIndex)
	}
}

// compareJSON normalizes and compares two JSON strings.
// JSON strings are normalised to their canonical form without whitespace.
func compareJSON(t *testing.T, got, want string) {
	t.Helper()
	var gotJSON, wantJSON any
	if err := json.Unmarshal([]byte(got), &gotJSON); err != nil {
		t.Fatalf("failed to unmarshal actual JSON: %v", err)
	}
	if err := json.Unmarshal([]byte(want), &wantJSON); err != nil {
		t.Fatalf("failed to unmarshal expected JSON: %v", err)
	}

	if diff := cmp.Diff(wantJSON, gotJSON); diff != "" {
		t.Errorf("JSON mismatch (-want +got):\n%s", diff)
	}
}

// mustJSON converts a value to a JSON string, failing the test if marshaling fails
func mustJSON(t *testing.T, value map[string]any) string {
	t.Helper()
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
