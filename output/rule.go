package output

import "strings"

const (
	// queryMetadataKey is the metadata key under which the engine stores the
	// fully qualified Rego query that produced a result, e.g.
	// data.main.deny_tags. It is the stable identity shared by every output
	// format so that a violation can always be traced back to a single rule.
	queryMetadataKey = "query"

	// Rule kinds used to classify a result when its originating rule cannot be
	// determined from the result metadata.
	ruleKindDeny    = "deny"
	ruleKindWarn    = "warn"
	ruleKindAllow   = "allow"
	ruleKindSuccess = "success"
	ruleKindSkip    = "skip"
)

// RuleIdentity identifies the Rego rule that produced a result.
//
// Namespace is the policy namespace (e.g. main) and Name is the full Rego
// rule name (e.g. deny, deny_tags, violation_critical or warn). Kind is the
// normalised severity kind (deny, warn, allow, success, skip), which is used
// to preserve the historical rule IDs of plain deny/warn rules.
type RuleIdentity struct {
	Namespace string
	Name      string
	Kind      string
}

// RuleID returns the stable SARIF rule ID for the rule.
//
// Plain deny, violation and warn rules keep their historical IDs
// (namespace/deny, namespace/warn) for backwards compatibility. Every other
// rule name, including deny_*/violation_*/warn_* variants, uses the full Rego
// rule name so that distinct rules in the same namespace can never collide.
func (r RuleIdentity) RuleID() string {
	return r.Namespace + "/" + r.ruleSegment()
}

// ruleSegment returns the portion of the rule ID following the namespace.
func (r RuleIdentity) ruleSegment() string {
	switch r.Name {
	case "", "deny", "violation":
		if r.Kind == ruleKindWarn {
			return ruleKindWarn
		}
		if r.Kind == ruleKindDeny {
			return ruleKindDeny
		}
		return r.Kind
	case "warn":
		return ruleKindWarn
	default:
		return r.Name
	}
}

// query returns the fully qualified Rego query stored on the result, if any.
func (r Result) query() string {
	if r.Metadata == nil {
		return ""
	}
	query, _ := r.Metadata[queryMetadataKey].(string)
	return query
}

// ruleNameFromQuery extracts the Rego rule name from a fully qualified query
// such as "data.main.deny_tags". An empty string is returned when the query
// does not reference a namespaced rule.
func ruleNameFromQuery(query string) string {
	const dataPrefix = "data."
	if !strings.HasPrefix(query, dataPrefix) {
		return ""
	}

	remainder := strings.TrimPrefix(query, dataPrefix)
	separator := strings.LastIndex(remainder, ".")
	if separator < 0 {
		return ""
	}

	return remainder[separator+1:]
}

// kindForRule maps a Rego rule name to its normalised severity kind. Rules that
// are not warnings are treated as failures, matching the engine's evaluation.
func kindForRule(ruleName string) string {
	if strings.HasPrefix(ruleName, "warn") {
		return ruleKindWarn
	}
	return ruleKindDeny
}

// identity resolves the stable identity of the rule that produced the result.
//
// The originating query in the result metadata is preferred because it is
// populated by the engine for every evaluated rule and is therefore shared by
// the JSON and SARIF outputs. When it is absent (for example for results built
// directly by an outputter such as success/skip placeholders), the supplied
// fallback namespace and kind are used instead.
func (r Result) identity(namespace, fallbackKind string) RuleIdentity {
	identity := RuleIdentity{
		Namespace: namespace,
		Kind:      fallbackKind,
	}

	if ruleName := ruleNameFromQuery(r.query()); ruleName != "" {
		identity.Name = ruleName
		identity.Kind = kindForRule(ruleName)
	}

	return identity
}
