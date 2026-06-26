package extract

import (
	"bytes"
	"os"
	"testing"
)

// node_rat_webpack.yara lints — the unit suite does not link libyara; actual
// compile+match runs in the Docker `full` CI stage (compile-rules.sh). These
// guards pin the mechanic literals, the size gate and the full conjunction so an
// edit cannot silently weaken the rule. The three webpack require shims +
// execSync + the scheme-hiding `"http://".concat(` are the discriminator: a
// benign bundled Node tool may carry child_process+axios+form-data but does not
// hide its HTTP scheme via concat while also running execSync. blacktop/yara:
// fires on the real sample fe66493e…, clean on a benign bundle carrying all
// three requires but no execSync / scheme-hide.

func loadNodeRATWebpackRule(t *testing.T) []byte {
	t.Helper()
	for _, p := range []string{
		"../../../../docker/local-rules/node_rat_webpack.yara",
		"../../../docker/local-rules/node_rat_webpack.yara",
		"../../docker/local-rules/node_rat_webpack.yara",
	} {
		if b, err := os.ReadFile(p); err == nil {
			return b
		}
	}
	t.Skip("node_rat_webpack.yara not found relative to test dir")
	return nil
}

func TestNodeRATWebpackRule_Present(t *testing.T) {
	data := loadNodeRATWebpackRule(t)
	for _, want := range []string{
		"rule Node_RAT_Webpack_Bundle",
		`"require(\"child_process\")"`,
		`"require(\"axios\")"`,
		`"require(\"form-data\")"`,
		`"execSync"`,
	} {
		if !bytes.Contains(data, []byte(want)) {
			t.Errorf("node_rat_webpack.yara missing %q", want)
		}
	}
}

// The size gate, the scheme-hiding concat marker and the full conjunction are
// the FP firewall: without the concat marker the rule fires on benign bundles
// carrying child_process+axios+form-data.
func TestNodeRATWebpackRule_Gates(t *testing.T) {
	data := loadNodeRATWebpackRule(t)
	if !bytes.Contains(data, []byte("filesize < 1048576")) {
		t.Error("missing the filesize < 1048576 size gate")
	}
	if !bytes.Contains(data, []byte(`/"http:\/\/"\s*\.concat\(/`)) {
		t.Error("missing the scheme-hiding `\"http://\".concat(` marker — the FP discriminator vs benign bundles")
	}
	if !bytes.Contains(data, []byte("all of them")) {
		t.Error("condition is not the full conjunction (`all of them`) — a weaker OR would raise FP")
	}
}

func TestNodeRATWebpackRule_NoBackreference(t *testing.T) {
	data := loadNodeRATWebpackRule(t)
	for _, bad := range [][]byte{[]byte(`\1`), []byte(`\2`)} {
		if bytes.Contains(data, bad) {
			t.Errorf("node_rat_webpack.yara contains backreference %q — yarac rejects it", bad)
		}
	}
}
