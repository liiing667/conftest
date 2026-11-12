package output

import (
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/open-policy-agent/conftest/internal/version"
	"github.com/owenrumney/go-sarif/v2/sarif"
)

const (
	// Tool information
	toolName     = "conftest"
	toolURI      = "https://github.com/open-policy-agent/conftest"
	sarifVersion = sarif.Version210

	// Result descriptions
	successDesc   = "Policy was satisfied successfully"
	skippedDesc   = "Policy check was skipped"
	failureDesc   = "Policy violation"
	warningDesc   = "Policy warning"
	exceptionDesc = "Policy exception"

	// Exit code descriptions
	exitNoViolations = "No policy violations found"
	exitViolations   = "Policy violations found"
	exitWarnings     = "Policy warnings found"
)

// SARIF represents an Outputter that outputs results in SARIF format.
type SARIF struct {
	writer io.Writer
}

// NewSARIF creates a new SARIF with the given writer.
func NewSARIF(w io.Writer) *SARIF {
	return &SARIF{
		writer: w,
	}
}

// getRuleDescription returns the appropriate description based on the rule kind.
func getRuleDescription(kind string) string {
	switch kind {
	case ruleKindSuccess:
		return successDesc
	case ruleKindSkip:
		return skippedDesc
	case ruleKindAllow:
		return exceptionDesc
	case ruleKindWarn:
		return warningDesc
	default:
		return failureDesc
	}
}

// ruleRegistry keeps the mapping between stable rule IDs and their position in
// the SARIF tool driver rule array. Tracking indices explicitly ensures that
// every result points at the rule describing the exact Rego rule that produced
// it, even when several rules share a namespace or produce identical messages.
type ruleRegistry struct {
	indices map[string]int
}

func newRuleRegistry() ruleRegistry {
	return ruleRegistry{indices: make(map[string]int)}
}

// index returns the rule index for the given identity, registering the rule
// (including its result metadata) the first time it is encountered.
func (r ruleRegistry) index(run *sarif.Run, identity RuleIdentity, result Result) int {
	ruleID := identity.RuleID()
	if idx, ok := r.indices[ruleID]; ok {
		return idx
	}

	desc := getRuleDescription(identity.Kind)
	run.AddRule(ruleID).
		WithDescription(desc).
		WithProperties(sarif.Properties(result.Metadata)).
		WithShortDescription(sarif.NewMultiformatMessageString(desc))

	idx := len(run.Tool.Driver.Rules) - 1
	r.indices[ruleID] = idx
	return idx
}

// addResult adds a result to the SARIF run, attributing it to the stable rule
// identity derived from the result itself.
func addResult(run *sarif.Run, result Result, namespace, kind, level, fileName string, registry ruleRegistry) {
	identity := result.identity(namespace, kind)
	ruleID := identity.RuleID()
	idx := registry.index(run, identity, result)

	location := sarif.NewPhysicalLocation()
	if loc := result.Location; loc != nil {
		line, _ := strconv.Atoi(loc.Line.String())
		fileName = loc.File
		location.Region = sarif.NewRegion().WithStartLine(line).WithEndLine(line)
	}
	uri := url.URL{Path: filepath.ToSlash(fileName)}
	location.ArtifactLocation = sarif.NewSimpleArtifactLocation(uri.EscapedPath())

	run.CreateResultForRule(ruleID).
		WithRuleIndex(idx).
		WithLevel(level).
		WithMessage(sarif.NewTextMessage(result.Message)).
		AddLocation(sarif.NewLocationWithPhysicalLocation(location))
}

// Output outputs the results in SARIF format.
func (s *SARIF) Output(results CheckResults) error {
	report, err := sarif.New(sarifVersion)
	if err != nil {
		return fmt.Errorf("create sarif report: %w", err)
	}

	// SARIF versions must start with a number, so we remove the "v" prefix.
	toolVersion := strings.TrimPrefix(version.Version, "v")
	driver := sarif.NewVersionedDriver(toolName, toolVersion).WithInformationURI(toolURI)
	run := sarif.NewRun(sarif.Tool{Driver: driver})
	registry := newRuleRegistry()

	for _, result := range results {
		// Process failures
		for _, failure := range result.Failures {
			addResult(run, failure, result.Namespace, ruleKindDeny, "error", result.FileName, registry)
		}

		// Process warnings
		for _, warning := range result.Warnings {
			addResult(run, warning, result.Namespace, ruleKindWarn, "warning", result.FileName, registry)
		}

		// Process exceptions (treated as successes)
		hasSuccesses := result.Successes > 0
		for _, exception := range result.Exceptions {
			addResult(run, exception, result.Namespace, ruleKindAllow, "note", result.FileName, registry)
			hasSuccesses = true
		}

		// Don't add success/skip results if there are failures or warnings
		hasErrors := result.HasFailure() || result.HasWarning()
		if hasErrors {
			continue
		}

		// Add success/exception results if there are no failures or warnings
		if hasSuccesses {
			statusResult := Result{
				Message: successDesc,
				Metadata: map[string]any{
					"description": successDesc,
				},
			}
			addResult(run, statusResult, result.Namespace, ruleKindSuccess, "none", result.FileName, registry)
		} else {
			statusResult := Result{
				Message: skippedDesc,
				Metadata: map[string]any{
					"description": skippedDesc,
				},
			}
			addResult(run, statusResult, result.Namespace, ruleKindSkip, "none", result.FileName, registry)
		}
	}

	exitDesc := exitNoViolations
	if results.HasFailure() {
		exitDesc = exitViolations
	} else if results.HasWarning() {
		exitDesc = exitWarnings
	}

	run.AddInvocations(sarif.NewInvocation().
		WithExecutionSuccess(true).
		WithExitCode(results.ExitCode()).
		WithExitCodeDescription(exitDesc))

	// Add the run to the report
	report.AddRun(run)

	// Write the report
	return report.Write(s.writer)
}
