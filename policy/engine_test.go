package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"testing/fstest"

	"github.com/open-policy-agent/conftest/output"
	"github.com/open-policy-agent/conftest/parser"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/loader"
	"github.com/owenrumney/go-sarif/v2/sarif"
)

func testOptions(t *testing.T) CompilerOptions {
	t.Helper()
	return CompilerOptions{
		Capabilities: ast.CapabilitiesForThisVersion(),
		RegoVersion:  "v0",
	}
}

func TestException(t *testing.T) {
	ctx := t.Context()

	policies := []string{"../examples/exceptions/policy"}
	engine, err := Load(policies, testOptions(t))
	if err != nil {
		t.Fatalf("loading policies: %v", err)
	}

	configFiles := []string{"../examples/exceptions/deployments.yaml"}
	configs, err := parser.ParseConfigurations(configFiles)
	if err != nil {
		t.Fatalf("loading configs: %v", err)
	}

	results, err := engine.Check(ctx, configs, "main")
	if err != nil {
		t.Fatalf("could not process policy file: %s", err)
	}

	const expectedFailures = 1
	actualFailures := len(results[0].Failures)
	if actualFailures != expectedFailures {
		t.Errorf("Multifile yaml test failure. Got %v failures, expected %v", actualFailures, expectedFailures)
	}

	const expectedSuccesses = 0
	actualSuccesses := results[0].Successes
	if actualSuccesses != expectedSuccesses {
		t.Errorf("Multifile yaml test failure. Got %v success, expected %v", actualSuccesses, expectedSuccesses)
	}

	const expectedExceptions = 1
	actualExceptions := len(results[0].Exceptions)
	if actualExceptions != expectedExceptions {
		t.Errorf("Multifile yaml test failure. Got %v exceptions, expected %v", actualExceptions, expectedExceptions)
	}
}

func TestTracing(t *testing.T) {
	t.Run("with tracing ", func(t *testing.T) {
		ctx := t.Context()

		policies := []string{"../examples/kubernetes/policy"}
		engine, err := Load(policies, testOptions(t))
		if err != nil {
			t.Fatalf("loading policies: %v", err)
		}

		engine.EnableTracing()

		configFiles := []string{"../examples/kubernetes/service.yaml"}
		configs, err := parser.ParseConfigurations(configFiles)
		if err != nil {
			t.Fatalf("loading configs: %v", err)
		}

		results, err := engine.Check(ctx, configs, "main")
		if err != nil {
			t.Fatalf("could not process policy file: %s", err)
		}

		for _, query := range results[0].Queries {
			if len(query.Traces) == 0 {
				t.Errorf("Tracing error: Expected trace objects, got 0 instead")
			}
		}
	})

	t.Run("without tracing", func(t *testing.T) {
		ctx := t.Context()

		policies := []string{"../examples/kubernetes/policy"}
		engine, err := Load(policies, testOptions(t))
		if err != nil {
			t.Fatalf("loading policies: %v", err)
		}

		configFiles := []string{"../examples/kubernetes/service.yaml"}
		configs, err := parser.ParseConfigurations(configFiles)
		if err != nil {
			t.Fatalf("loading configs: %v", err)
		}

		results, err := engine.Check(ctx, configs, "main")
		if err != nil {
			t.Fatalf("could not process policy file: %s", err)
		}

		for _, query := range results[0].Queries {
			if len(query.Traces) != 0 {
				t.Errorf("Tracing error: Expected no trace objects, got %d", len(query.Traces))
			}
		}
	})

}

func TestMultifileYaml(t *testing.T) {
	ctx := t.Context()

	policies := []string{"../examples/kubernetes/policy"}
	engine, err := Load(policies, testOptions(t))
	if err != nil {
		t.Fatalf("loading policies: %v", err)
	}

	configFiles := []string{"../examples/kubernetes/deployment+service.yaml"}
	configs, err := parser.ParseConfigurations(configFiles)
	if err != nil {
		t.Fatalf("loading configs: %v", err)
	}

	results, err := engine.Check(ctx, configs, "main")
	if err != nil {
		t.Fatalf("could not process policy file: %s", err)
	}

	const expectedFailures = 4
	actualFailures := len(results[0].Failures)
	if actualFailures != expectedFailures {
		t.Errorf("Multifile yaml test failure. Got %v failures, expected %v", actualFailures, expectedFailures)
	}

	const expectedWarnings = 1
	actualWarnings := len(results[0].Warnings)
	if actualWarnings != expectedWarnings {
		t.Errorf("Multifile yaml test failure. Got %v warnings, expected %v", actualWarnings, expectedWarnings)
	}

	const expectedSuccesses = 5
	actualSuccesses := results[0].Successes
	if actualSuccesses != expectedSuccesses {
		t.Errorf("Multifile yaml test failure. Got %v successes, expected %v", actualSuccesses, expectedSuccesses)
	}

	// 10 warnings/failures/successes queries, and 2 dummy exception queries
	const expectedQueries = 12
	actualQueries := len(results[0].Queries)
	if actualQueries != expectedQueries {
		t.Errorf("Multifile yaml test failure. Got %v queries, expected %v", actualQueries, expectedQueries)
	}
}

func TestDockerfile(t *testing.T) {
	ctx := t.Context()

	policies := []string{"../examples/docker/policy"}
	engine, err := Load(policies, testOptions(t))
	if err != nil {
		t.Fatalf("loading policies: %v", err)
	}

	configFiles := []string{"../examples/docker/Dockerfile"}
	configs, err := parser.ParseConfigurations(configFiles)
	if err != nil {
		t.Fatalf("loading configs: %v", err)
	}

	results, err := engine.Check(ctx, configs, "main")
	if err != nil {
		t.Fatalf("could not process policy file: %s", err)
	}

	const expectedFailures = 1
	actualFailures := len(results[0].Failures)
	if actualFailures != expectedFailures {
		t.Errorf("Dockerfile test failure. Got %v failures, expected %v", actualFailures, expectedFailures)
	}

	const expectedSuccesses = 0
	actualSuccesses := results[0].Successes
	if actualSuccesses != expectedSuccesses {
		t.Errorf("Dockerfile test failure. Got %v successes, expected %v", actualSuccesses, expectedSuccesses)
	}

	// 1 failure, and 1 dummy exception query
	const expectedQueries = 2
	actualQueries := len(results[0].Queries)
	if actualQueries != expectedQueries {
		t.Errorf("Dockerfile test failure. Got %v queries, expected %v", actualQueries, expectedQueries)
	}
}

func TestIsWarning(t *testing.T) {
	tests := []struct {
		in  string
		exp bool
	}{
		{"", false},
		{"warn", true},
		{"warnXYZ", false},
		{"warn_", false},
		{"warn_x", true},
		{"warn_1", true},
		{"warn_x_y_z", true},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			res := isWarning(tt.in)
			if tt.exp != res {
				t.Errorf("%s recognized as `warn` query - expected: %v actual: %v", tt.in, tt.exp, res)
			}
		})
	}
}

func TestIsFailure(t *testing.T) {
	tests := []struct {
		in  string
		exp bool
	}{
		{"", false},
		{"deny", true},
		{"violation", true},
		{"denyXYZ", false},
		{"violationXYZ", false},
		{"deny_", false},
		{"violation_", false},
		{"deny_x", true},
		{"violation_x", true},
		{"deny_1", true},
		{"violation_1", true},
		{"deny_x_y_z", true},
		{"violation_x_y_z", true},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			res := isFailure(tt.in)

			if tt.exp != res {
				t.Fatalf("%s recognized as `fail` query - expected: %v actual: %v", tt.in, tt.exp, res)
			}
		})
	}
}

func TestAddFileInfo(t *testing.T) {
	tests := []struct {
		desc  string
		input string
		name  string
	}{
		{
			desc:  "SingleFile",
			input: "foobar.txt",
			name:  "foobar.txt",
		},
		{
			desc:  "RelativePath",
			input: "../foobar.txt",
			name:  "foobar.txt",
		},
		{
			desc:  "FullPath",
			input: "/some/dir/foobar.txt",
			name:  "foobar.txt",
		},
	}

	modules := make(map[string]string, 1)
	modules["test.rego"] = `package main

deny contains {"msg": msg} if {
	msg := data.conftest.file.name
}
`

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			var e Engine
			ctx := t.Context()
			if err := e.addFileInfo(ctx, tt.input); err != nil {
				t.Error(err)
			}

			module, err := ast.ParseModule("test.rego", modules["test.rego"])
			if err != nil {
				t.Error(err)
			}
			e.modules = make(map[string]*ast.Module, 1)
			e.modules["test.rego"] = module
			compiler, err := ast.CompileModules(modules)
			if err != nil {
				t.Error(err)
			}
			e.compiler = compiler

			qr, err := e.query(ctx, nil, "data.main.deny")
			if err != nil {
				t.Error(err)
			}
			if qr.Results[0].Message != tt.name {
				t.Errorf("mismatch. have [%v], want [%v]", qr.Results[0].Message, tt.name)
			}
		})
	}
}

func TestLoadWithData(t *testing.T) {
	testCases := []struct {
		desc         string
		policyPaths  []string
		dataPaths    []string
		strict       bool
		wantPolicies bool
		wantDocs     bool
		wantErr      bool
	}{
		{
			desc:         "Load both policies and data",
			policyPaths:  []string{"../examples/kubernetes/policy"},
			dataPaths:    []string{"../examples/kubernetes/service.yaml"},
			wantPolicies: true,
			wantDocs:     true,
		},
		{
			desc:         "Load only data",
			dataPaths:    []string{"../examples/kubernetes/service.yaml"},
			wantPolicies: false,
			wantDocs:     true,
		},
		{
			desc:         "Load only policies",
			policyPaths:  []string{"../examples/kubernetes/policy"},
			wantPolicies: true,
			wantDocs:     false,
		},
		{
			desc:        "Invalid policy path",
			policyPaths: []string{"nonexistent/path"},
			dataPaths:   []string{"../examples/kubernetes/service.yaml"},
			wantErr:     true,
		},
		{
			desc:        "Invalid data path",
			policyPaths: []string{"../examples/kubernetes/policy"},
			dataPaths:   []string{"nonexistent/data.yaml"},
			wantErr:     true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			opts := CompilerOptions{
				Strict:       tc.strict,
				Capabilities: ast.CapabilitiesForThisVersion(),
				RegoVersion:  "v0",
			}
			engine, err := LoadWithData(tc.policyPaths, tc.dataPaths, opts)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tc.wantPolicies {
				if len(engine.Policies()) == 0 {
					t.Error("expected policies to be loaded but got none")
				}
				if len(engine.Modules()) == 0 {
					t.Error("expected modules to be loaded but got none")
				}
				if engine.Compiler() == nil {
					t.Error("expected compiler to be initialized")
				}
			} else {
				if len(engine.Policies()) > 0 {
					t.Error("expected no policies but got some")
				}
			}

			if tc.wantDocs {
				if len(engine.Documents()) == 0 {
					t.Error("expected documents to be loaded but got none")
				}
				if engine.Store() == nil {
					t.Error("expected store to be initialized")
				}
			} else {
				if len(engine.Documents()) > 0 {
					t.Error("expected no documents but got some")
				}
			}
		})
	}
}

func TestLoadCapabilities(t *testing.T) {
	tmpDir := t.TempDir()

	inaccessibleCapabilitiesPath := filepath.Join(tmpDir, "capabilities")
	err := os.WriteFile(inaccessibleCapabilitiesPath, []byte(""), 0o000)
	if err != nil {
		t.Fatalf("failed to write empty policy file: %v", err)
	}

	t.Cleanup(func() {
		err := os.Chmod(inaccessibleCapabilitiesPath, 0o600)
		if err != nil {
			t.Fatalf("failed to restore capabilities file permissions: %v", err)
		}
	})

	invalidCapabilitiesPath := filepath.Join(tmpDir, "invalid-capabilities")
	err = os.WriteFile(invalidCapabilitiesPath, []byte("invalid json"), 0o600)
	if err != nil {
		t.Fatalf("failed to write invalid capabilities file: %v", err)
	}

	tests := []struct {
		desc    string
		path    string
		wantErr bool
	}{
		{
			desc:    "Inaccessible capabilities file",
			path:    inaccessibleCapabilitiesPath,
			wantErr: true,
		},
		{
			desc:    "Invalid capabilities file",
			path:    invalidCapabilitiesPath,
			wantErr: true,
		},
		{
			desc: "No path does not error",
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			_, err := LoadCapabilities(tc.path)
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Errorf("LoadCapabilities(%s) error = %v, want %v", tc.path, gotErr, tc.wantErr)
			}
		})
	}
}

func TestNamespaces(t *testing.T) {
	tests := []struct {
		name     string
		policies map[string][]byte
		want     []string
	}{
		{
			name: "multiple namespaces",
			policies: map[string][]byte{
				"main.rego": []byte(`package main
deny contains msg if { msg := "denied" }`),
				"k8s.rego": []byte(`package kubernetes
deny contains msg if { msg := "denied" }`),
				"nested.rego": []byte(`package main.sub
deny contains msg if { msg := "denied" }`),
				"main_duplicate.rego": []byte(`package main
warn contains msg if { msg := "warning" }`),
			},
			want: []string{"main", "kubernetes", "main.sub"},
		},
		{
			name: "single namespace",
			policies: map[string][]byte{
				"main.rego": []byte(`package main
deny contains msg if { msg := "denied" }`),
			},
			want: []string{"main"},
		},
		{
			name:     "no policies",
			policies: map[string][]byte{},
			want:     nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Convert policies to fstest.MapFS format
			files := make(map[string]*fstest.MapFile)
			for name, data := range tt.policies {
				files[name] = &fstest.MapFile{Data: data}
			}
			// Explicit conversion needed despite files being fstest.MapFS type
			// to ensure fs.FS interface implementation for loader.WithFS
			fs := fstest.MapFS(files) //nolint:unconvert

			l := loader.NewFileLoader().WithFS(fs)

			keys := make([]string, 0, len(tt.policies))
			for k := range tt.policies {
				keys = append(keys, k)
			}
			pols, err := l.All(keys)
			if err != nil {
				t.Fatalf("Load policies: %v", err)
			}

			engine := Engine{
				modules: pols.ParsedModules(),
			}

			got := engine.Namespaces()
			sort.Strings(got)
			sort.Strings(tt.want)

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Namespaces() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestQueryMetadata(t *testing.T) {
	type want struct {
		msg  string
		meta map[string]any
	}

	tests := []struct {
		name   string
		policy []byte
		query  string
		want   []want
	}{
		{
			name: "string return type",
			policy: []byte(`package main
deny contains msg if {
	msg := "simple denial"
}`),
			query: "data.main.deny",
			want: []want{
				{
					msg:  "simple denial",
					meta: map[string]any{"query": "data.main.deny"},
				},
			},
		},
		{
			name: "map return type",
			policy: []byte(`package main
violation contains result if {
	result := {
		"msg": "violation with metadata",
		"severity": "high"
	}
}`),
			query: "data.main.violation",
			want: []want{
				{
					msg: "violation with metadata",
					meta: map[string]any{
						"query":    "data.main.violation",
						"severity": "high",
					},
				},
			},
		},
		{
			name: "multiple results",
			policy: []byte(`package main
deny contains msg if {
	msg := "first denial"
}
deny contains msg if {
	msg := "second denial"
}
violation contains result if {
	result := {
		"msg": "violation one",
		"severity": "high"
	}
}
violation contains result if {
	result := {
		"msg": "violation two",
		"severity": "low"
	}
}`),
			query: "data.main.deny",
			want: []want{
				{
					msg:  "first denial",
					meta: map[string]any{"query": "data.main.deny"},
				},
				{
					msg:  "second denial",
					meta: map[string]any{"query": "data.main.deny"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()

			files := fstest.MapFS{
				"policy.rego": &fstest.MapFile{
					Data: tt.policy,
				},
			}

			l := loader.NewFileLoader().WithFS(files)
			pols, err := l.All([]string{"policy.rego"})
			if err != nil {
				t.Fatalf("Load policies: %v", err)
			}

			engine := Engine{
				modules:  pols.ParsedModules(),
				compiler: ast.NewCompiler().WithEnablePrintStatements(true),
			}
			engine.compiler.Compile(engine.modules)
			if engine.compiler.Failed() {
				t.Fatalf("Compiler error: %v", engine.compiler.Errors)
			}

			result, err := engine.query(ctx, nil, tt.query)
			if err != nil {
				t.Fatalf("Query error: %v", err)
			}

			if len(result.Results) != len(tt.want) {
				t.Fatalf("got %d results, want %d", len(result.Results), len(tt.want))
			}

			for i, got := range result.Results {
				want := tt.want[i]
				if got.Message != want.msg {
					t.Errorf("result[%d]: got Message=%q, want Message=%q",
						i, got.Message, want.msg)
				}
				if !reflect.DeepEqual(got.Metadata, want.meta) {
					t.Errorf("result[%d]: got Metadata=%v, want Metadata=%v",
						i, got.Metadata, want.meta)
				}
			}
		})
	}
}

func TestInterQueryCache(t *testing.T) {
	newServer := func(t *testing.T) (*httptest.Server, *atomic.Int64) {
		t.Helper()
		var hits atomic.Int64
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			hits.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"message": "ok"}`))
		}))
		t.Cleanup(srv.Close)
		return srv, &hits
	}

	newEngine := func(t *testing.T, url string) *Engine {
		t.Helper()
		policy := fmt.Sprintf(`package main

teams := http.send({
	"url": %q,
	"method": "get",
	"raise_error": false,
	"cache": true,
	"force_cache": true,
	"force_cache_duration_seconds": 60,
})

deny_is_twohundred contains msg if {
	teams.status_code == 200
	msg := "Statuscode is 200!"
}

deny_not_twohundred contains msg if {
	teams.status_code != 200
	msg := "Statuscode is NOT 200!"
}
`, url)
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "policy.rego"), []byte(policy), 0o600); err != nil {
			t.Fatalf("write policy: %v", err)
		}
		opts := testOptions(t)
		opts.RegoVersion = "v1"
		engine, err := Load([]string{dir}, opts)
		if err != nil {
			t.Fatalf("load policies: %v", err)
		}
		return engine
	}

	configs := map[string]any{
		"a.yaml": map[string]any{"kind": "a"},
		"b.yaml": map[string]any{"kind": "b"},
	}

	t.Run("disabled", func(t *testing.T) {
		srv, hits := newServer(t)
		engine := newEngine(t, srv.URL)
		if _, err := engine.Check(t.Context(), configs, "main"); err != nil {
			t.Fatalf("check: %v", err)
		}
		// Two deny rules evaluated against two inputs, with no cache shared between queries.
		if got, want := hits.Load(), int64(4); got != want {
			t.Errorf("expected %d requests without the cache, got %d", want, got)
		}
	})

	t.Run("enabled", func(t *testing.T) {
		srv, hits := newServer(t)
		engine := newEngine(t, srv.URL)
		engine.EnableInterQueryCache()
		if _, err := engine.Check(t.Context(), configs, "main"); err != nil {
			t.Fatalf("check: %v", err)
		}
		if got, want := hits.Load(), int64(1); got != want {
			t.Errorf("expected %d request with the cache enabled, got %d", want, got)
		}
	})
}

// TestCheckSARIFRuleAttribution runs real Rego policies containing several
// deny/warn rule names in one namespace and verifies that the SARIF output
// keeps one distinct rule per Rego rule, with ruleIndex and metadata
// attributed to the rule that produced each violation. This guards the shared
// rule identity used by both the JSON metadata and the SARIF renderer.
func TestCheckSARIFRuleAttribution(t *testing.T) {
	ctx := t.Context()

	policySource := []byte(`package main

deny_labels contains msg if {
	msg := "same message"
}

deny_replicas contains result if {
	result := {
		"msg": "same message",
		"severity": "high",
		"_loc": {"file": "config.yaml", "line": 42}
	}
}

warn_deprecated contains msg if {
	msg := "same message"
}
`)

	files := fstest.MapFS{
		"policy.rego": &fstest.MapFile{Data: policySource},
	}
	l := loader.NewFileLoader().WithFS(files)
	pols, err := l.All([]string{"policy.rego"})
	if err != nil {
		t.Fatalf("load policies: %v", err)
	}

	compiler := ast.NewCompiler().WithEnablePrintStatements(true)
	compiler.Compile(pols.ParsedModules())
	if compiler.Failed() {
		t.Fatalf("compile policies: %v", compiler.Errors)
	}

	engine := Engine{
		modules:  pols.ParsedModules(),
		compiler: compiler,
	}

	results, err := engine.Check(ctx, map[string]any{"config.yaml": map[string]any{"kind": "Deployment"}}, "main")
	if err != nil {
		t.Fatalf("check: %v", err)
	}

	var buf bytes.Buffer
	if err := output.NewSARIF(&buf).Output(results); err != nil {
		t.Fatalf("render sarif: %v", err)
	}

	var report sarif.Report
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("parse sarif: %v", err)
	}
	run := report.Runs[0]

	wantRuleIDs := []string{"main/deny_labels", "main/deny_replicas", "main/warn_deprecated"}
	if len(run.Tool.Driver.Rules) != len(wantRuleIDs) {
		t.Fatalf("got %d rules %v, want %v", len(run.Tool.Driver.Rules), run.Tool.Driver.Rules, wantRuleIDs)
	}

	ruleIndex := make(map[string]int, len(wantRuleIDs))
	for i, rule := range run.Tool.Driver.Rules {
		ruleIndex[rule.ID] = i
		query := fmt.Sprint(rule.Properties["query"])
		wantQuery := "data." + strings.Replace(rule.ID, "/", ".", 1)
		if query != wantQuery {
			t.Errorf("rule %q query metadata = %q, want %q", rule.ID, query, wantQuery)
		}
	}
	for _, id := range wantRuleIDs {
		if _, ok := ruleIndex[id]; !ok {
			t.Errorf("missing rule %q in SARIF rules", id)
		}
	}

	if len(run.Results) != 3 {
		t.Fatalf("got %d results, want 3", len(run.Results))
	}
	seen := make(map[string]bool)
	for _, sarifResult := range run.Results {
		id := *sarifResult.RuleID
		seen[id] = true
		if int(*sarifResult.RuleIndex) != ruleIndex[id] {
			t.Errorf("result %q ruleIndex = %d, want %d", id, *sarifResult.RuleIndex, ruleIndex[id])
		}
		if id == "main/warn_deprecated" && *sarifResult.Level != "warning" {
			t.Errorf("warning level = %q, want warning", *sarifResult.Level)
		}
		if id == "main/deny_replicas" {
			region := sarifResult.Locations[0].PhysicalLocation.Region
			if region == nil || *region.StartLine != 42 {
				t.Errorf("deny_replicas line = %v, want 42", region)
			}
		}
	}
	for _, id := range wantRuleIDs {
		if !seen[id] {
			t.Errorf("no SARIF result attributed to %q", id)
		}
	}

	if exitCode := results.ExitCode(); *run.Invocations[0].ExitCode != exitCode || exitCode != 1 {
		t.Errorf("sarif exit code = %d, want CheckResults.ExitCode() = %d", *run.Invocations[0].ExitCode, exitCode)
	}
}
