// Package verdict turns a strixd /scan response into the actionable verdict its
// CGO-free clients report.
//
// It exists so the two clients that talk to strixd over HTTP — strix-scan (the
// Sieve/LDA exit-code client) and strix-milter (the Postfix/Sendmail milter) —
// share ONE definition of "actionable" and ONE family-resolution order. The
// canary/allowlist rules below are security-relevant: a rule tagged
// mailstrix_canary=1 or mailstrix_allow=1 must never make a client act. Two
// copies of that logic would eventually disagree, and the disagreement would be
// silent — a canary rule that stops a Sieve pipe but not a milter, or vice
// versa. Hence one package, one behaviour, one set of tests.
//
// This package deliberately shares no type with the scanner: the clients are
// pure Go and must not pull in the CGO/libyara side of the tree.
package verdict

import "strings"

// Match is the subset of strixd's /scan response the clients render.
type Match struct {
	Rule      string            `json:"rule"`
	Namespace string            `json:"namespace"`
	Meta      map[string]string `json:"meta"`
}

// Response is strixd's /scan response body.
type Response struct {
	Matches []Match `json:"matches"`
}

// Verdict is the structured result of a scan. Family is the single canonical
// malware family for the input ("" when no family-bearing rule matched); Rules
// lists the matched (actionable) rule names. Confidence is "family" when a
// family was resolved, "rule" when rules matched but none carried family
// metadata, and "" when nothing matched.
type Verdict struct {
	Malicious  bool     `json:"malicious"`
	Family     string   `json:"family"`
	Confidence string   `json:"confidence"`
	Rules      []string `json:"rules"`
}

// familyMetaKeys are the rule-meta keys that carry a malware family, in priority
// order. A rule that sets one of these is "family-bearing"; a rule with none is
// a generic / technique rule (http, meth_get_eip, pe_*, SUSP_*, …) and never
// contributes a family label.
var familyMetaKeys = []string{"family", "malware_family", "actor"}

// Actionable drops the matches a client must NOT act on: canary rules
// (mailstrix_canary=1, deployed to prove the pipeline is live) and allowlisted
// rules (mailstrix_allow=1, known-benign hits kept for logging). Both are
// log-only by definition — treating either as a hit would block legitimate mail.
//
// The input slice is never mutated; the common case (nothing to drop) returns
// it as-is.
func Actionable(matches []Match) []Match {
	if len(matches) == 0 {
		return nil
	}
	var out []Match
	for i, m := range matches {
		if isLogOnly(m) {
			if out == nil {
				out = make([]Match, 0, len(matches)-1)
				out = append(out, matches[:i]...)
			}
			continue
		}
		if out != nil {
			out = append(out, m)
		}
	}
	if out == nil {
		return matches
	}
	return out
}

func isLogOnly(m Match) bool {
	if m.Meta == nil {
		return false
	}
	return m.Meta["mailstrix_canary"] == "1" || m.Meta["mailstrix_allow"] == "1"
}

// For builds the structured verdict from already-Actionable matches. The
// reported Family is the first family-bearing match's family (one family per
// file = highest-confidence family-bearing hit); generic/technique rules that
// carry no family meta are dropped from family consideration but still count
// toward Malicious + Rules.
func For(matches []Match) Verdict {
	v := Verdict{Rules: make([]string, 0, len(matches))}
	for _, m := range matches {
		v.Malicious = true
		v.Rules = append(v.Rules, m.Rule)
		if v.Family == "" {
			if fam := familyOf(m); fam != "" {
				v.Family = fam
			}
		}
	}
	switch {
	case v.Family != "":
		v.Confidence = "family"
	case v.Malicious:
		v.Confidence = "rule"
	}
	return v
}

// familyOf extracts a family string from one match's metadata, preferring the
// keys in familyMetaKeys. Returns "" for a generic/technique rule that carries
// no family meta (the caller drops it from family consideration).
func familyOf(m Match) string {
	for _, k := range familyMetaKeys {
		if v := strings.TrimSpace(m.Meta[k]); v != "" {
			return v
		}
	}
	return ""
}
