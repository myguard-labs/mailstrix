package main

import (
	"cmp"
	"slices"
)

type observation struct {
	Status  string
	Matches []symbol
}

type symbolCounts struct {
	Partition string   `json:"partition"`
	Symbol    symbol   `json:"symbol"`
	TP        int      `json:"tp"`
	FP        int      `json:"fp"`
	FN        int      `json:"fn"`
	TN        int      `json:"tn"`
	Excluded  int      `json:"excluded"`
	Precision *float64 `json:"precision"`
	Recall    *float64 `json:"recall"`
}

type summary struct {
	UniqueSamples     int            `json:"unique_samples"`
	Duplicates        int            `json:"duplicates"`
	Statuses          map[string]int `json:"statuses"`
	Symbols           []symbolCounts `json:"symbols"`
	UnlabelledMatches int            `json:"unlabelled_matches"`
	Pass              bool           `json:"labelled_nonregression_pass"`
}

func fraction(n, d int) *float64 {
	if d == 0 {
		return nil
	}
	f := float64(n) / float64(d)
	return &f
}

// summarize scores explicit symbol truth only. A structural indicator present
// in a benign fixture is a TP for that indicator, never a malware TP. Failed
// evaluations are excluded from ratios but independently prevent a passing gate.
func summarize(m manifest, observations map[string]observation) summary {
	out := summary{Statuses: map[string]int{}, Symbols: []symbolCounts{}, Pass: true}
	type key struct {
		partition string
		symbol    symbol
	}
	counts := map[key]*symbolCounts{}
	seen := map[string]bool{}
	for _, s := range m.Samples {
		if seen[s.SHA256] {
			out.Duplicates++
			continue
		}
		seen[s.SHA256] = true
		out.UniqueSamples++
		o, ok := observations[s.SHA256]
		if !ok {
			o.Status = "missing"
		}
		out.Statuses[o.Status]++
		if o.Status != "ok" {
			out.Pass = false
		}
		hits := make(map[symbol]bool, len(o.Matches))
		for _, sym := range o.Matches {
			hits[sym] = true
		}
		labelled := make(map[symbol]bool, len(s.Truth.Symbols))
		for _, l := range s.Truth.Symbols {
			labelled[l.Symbol] = true
			k := key{s.Partition, l.Symbol}
			c := counts[k]
			if c == nil {
				c = &symbolCounts{Partition: s.Partition, Symbol: l.Symbol}
				counts[k] = c
			}
			if o.Status != "ok" {
				c.Excluded++
				continue
			}
			switch {
			case l.Expected == "present" && hits[l.Symbol]:
				c.TP++
			case l.Expected == "present":
				c.FN++
				out.Pass = false
			case hits[l.Symbol]:
				c.FP++
				out.Pass = false
			default:
				c.TN++
			}
		}
		if o.Status == "ok" {
			for sym := range hits {
				if !labelled[sym] {
					out.UnlabelledMatches++
				}
			}
		}
	}
	if len(counts) == 0 {
		out.Pass = false
	}
	for _, c := range counts {
		c.Precision = fraction(c.TP, c.TP+c.FP)
		c.Recall = fraction(c.TP, c.TP+c.FN)
		out.Symbols = append(out.Symbols, *c)
	}
	slices.SortFunc(out.Symbols, func(a, b symbolCounts) int {
		if n := cmp.Compare(a.Partition, b.Partition); n != 0 {
			return n
		}
		if n := cmp.Compare(a.Symbol.Namespace, b.Symbol.Namespace); n != 0 {
			return n
		}
		return cmp.Compare(a.Symbol.Rule, b.Symbol.Rule)
	})
	return out
}
