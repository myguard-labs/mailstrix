package cape

import (
	"context"
	"sort"
)

// SignatureRule maps an exact CAPE signature name to a bounded local identifier.
// These rules are administrator policy, not upstream severity guarantees.
type SignatureRule struct {
	Name, Signal string
	Evidence     Evidence
}

// SignatureMapper applies one immutable, explicitly versioned signature policy.
// Changing rules requires a new policy identifier for admission/dedup identity.
type SignatureMapper struct {
	policy string
	rules  map[string]SignatureRule
}

// NewSignatureMapper validates and freezes an exact-signature mapping policy.
func NewSignatureMapper(policy string, rules []SignatureRule) (*SignatureMapper, error) {
	if !identifier(policy, 128) || len(rules) == 0 || len(rules) > 128 {
		return nil, &Error{Code: Invalid}
	}
	m := &SignatureMapper{policy: policy, rules: make(map[string]SignatureRule, len(rules))}
	for _, rule := range rules {
		if !identifier(rule.Name, 128) || !identifier(rule.Signal, 128) ||
			(rule.Evidence != EvidenceMalicious && rule.Evidence != EvidenceSuspicious) {
			return nil, &Error{Code: Invalid}
		}
		if _, exists := m.rules[rule.Name]; exists {
			return nil, &Error{Code: Invalid}
		}
		m.rules[rule.Name] = rule
	}
	return m, nil
}

// Normalize requires a signatures array of objects with nonempty bounded names.
// Missing/malformed signatures are unavailable, not no_signal. Scores and raw
// signature descriptions are never consumed or persisted.
func (m *SignatureMapper) Normalize(ctx context.Context, report *Report, policy string) (NormalizedResult, error) {
	if err := ctx.Err(); err != nil {
		return NormalizedResult{}, err
	}
	if m == nil || policy != m.policy || report == nil {
		return NormalizedResult{}, &Error{Code: Protocol}
	}
	signatures, ok := report.document["signatures"].([]any)
	if !ok || len(signatures) > 4096 {
		return NormalizedResult{}, &Error{Code: Protocol}
	}
	result := NormalizedResult{Version: 1, Policy: policy, Evidence: EvidenceNoSignal}
	seen := make(map[string]bool)
	for _, raw := range signatures {
		if err := ctx.Err(); err != nil {
			return NormalizedResult{}, err
		}
		signature, ok := raw.(map[string]any)
		if !ok {
			return NormalizedResult{}, &Error{Code: Protocol}
		}
		name, ok := signature["name"].(string)
		if !ok || !identifier(name, 128) {
			return NormalizedResult{}, &Error{Code: Protocol}
		}
		if rule, found := m.rules[name]; found {
			seen[rule.Signal] = true
			if rule.Evidence == EvidenceMalicious || result.Evidence == EvidenceNoSignal {
				result.Evidence = rule.Evidence
			}
		}
	}
	for signal := range seen {
		result.Signals = append(result.Signals, signal)
	}
	sort.Strings(result.Signals)
	if _, err := normalizedBytes(result, policy); err != nil {
		return NormalizedResult{}, err
	}
	return result, nil
}
