package mailstrix

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	yara "github.com/hillu/go-yara/v4"
)

type lifecycleCompiler struct {
	destroyed int
	defineErr error
	addErr    error
	rules     *yara.Rules
	getErr    error
}

func (c *lifecycleCompiler) AddFile(*os.File, string) error { return c.addErr }

func (c *lifecycleCompiler) DefineVariable(string, interface{}) error {
	return c.defineErr
}

func (c *lifecycleCompiler) Destroy() { c.destroyed++ }

func (c *lifecycleCompiler) GetRules() (*yara.Rules, error) {
	return c.rules, c.getErr
}

func stubRuleCompiler(t *testing.T, factory func() (ruleCompiler, error)) {
	t.Helper()
	old := newRuleCompiler
	newRuleCompiler = factory
	t.Cleanup(func() { newRuleCompiler = old })
}

func lifecycleRuleFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "valid.yar")
	if err := os.WriteFile(path, []byte("rule Valid { condition: true }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func lifecycleRules(t *testing.T, identifier string) *yara.Rules {
	t.Helper()
	rules, err := yara.Compile("rule "+identifier+" { condition: true }", nil)
	if err != nil {
		t.Fatal(err)
	}
	return rules
}

func TestCompileRuleFilesDestroysTemporaryCompiler(t *testing.T) {
	path := lifecycleRuleFile(t)
	cause := errors.New("native failure")
	tests := []struct {
		name             string
		files            []string
		constructorErr   error
		configure        func(*lifecycleCompiler)
		wantErr          string
		wantCause        bool
		wantActive       bool
		wantCompilerFree int
		wantRulesFree    int
	}{
		{name: "success transfers active rules", files: []string{path}, wantActive: true, wantCompilerFree: 1},
		{name: "constructor failure", files: []string{path}, constructorErr: cause, wantErr: "new compiler", wantCause: true},
		{name: "no files", wantErr: "no compilable", wantCompilerFree: 1},
		{name: "external definition", files: []string{path}, configure: func(c *lifecycleCompiler) { c.defineErr = cause }, wantErr: "define external", wantCause: true, wantCompilerFree: 1},
		{name: "AddFile rejection", files: []string{path}, configure: func(c *lifecycleCompiler) { c.addErr = cause }, wantErr: "no compilable", wantCompilerFree: 1},
		{name: "GetRules failure", files: []string{path}, configure: func(c *lifecycleCompiler) { c.getErr = cause }, wantErr: "get rules", wantCause: true, wantCompilerFree: 1},
		{name: "GetRules result with error", files: []string{path}, configure: func(c *lifecycleCompiler) { c.rules = lifecycleRules(t, "Failed"); c.getErr = cause }, wantErr: "get rules", wantCause: true, wantCompilerFree: 1, wantRulesFree: 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			compiler := &lifecycleCompiler{}
			if tc.wantActive {
				compiler.rules = lifecycleRules(t, "Active")
			}
			if tc.configure != nil {
				tc.configure(compiler)
			}
			stubRuleCompiler(t, func() (ruleCompiler, error) {
				if tc.constructorErr != nil {
					return nil, tc.constructorErr
				}
				return compiler, nil
			})
			oldDestroy := destroyTemporaryRules
			temporaryRulesFreed := 0
			destroyTemporaryRules = func(rules *yara.Rules) {
				temporaryRulesFreed++
				oldDestroy(rules)
			}
			t.Cleanup(func() { destroyTemporaryRules = oldDestroy })

			rules, err := compileRuleFiles(filepath.Dir(path), tc.files, func(string, ...any) {})
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("compileRuleFiles: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("compileRuleFiles error = %v, want containing %q", err, tc.wantErr)
			}
			if tc.wantCause && !errors.Is(err, cause) {
				t.Fatalf("errors.Is(%v, cause) = false", err)
			}
			if compiler.destroyed != tc.wantCompilerFree {
				t.Fatalf("compiler Destroy calls = %d, want %d before return", compiler.destroyed, tc.wantCompilerFree)
			}
			if temporaryRulesFreed != tc.wantRulesFree {
				t.Fatalf("temporary rules Destroy calls = %d, want %d before return", temporaryRulesFreed, tc.wantRulesFree)
			}
			if tc.wantActive {
				if rules != compiler.rules {
					t.Fatalf("returned rules = %p, want transferred %p", rules, compiler.rules)
				}
				var matches yara.MatchRules
				if err := rules.ScanMem([]byte("anything"), 0, 0, &matches); err != nil || len(matches) != 1 {
					t.Fatalf("transferred rules unusable: matches=%d err=%v", len(matches), err)
				}
				rules.Destroy()
			} else if rules != nil {
				t.Fatalf("rules = %p, want nil on error", rules)
			}
		})
	}
}

func TestCompileDirRepeatedTemporaryOwnership(t *testing.T) {
	path := lifecycleRuleFile(t)
	const iterations = 8
	created := 0
	compilers := make([]*lifecycleCompiler, 0, iterations*2)
	stubRuleCompiler(t, func() (ruleCompiler, error) {
		created++
		compiler := &lifecycleCompiler{rules: lifecycleRules(t, "Repeat")}
		compilers = append(compilers, compiler)
		return compiler, nil
	})
	oldDestroy := destroyTemporaryRules
	validationRulesFreed := 0
	destroyTemporaryRules = func(rules *yara.Rules) {
		validationRulesFreed++
		oldDestroy(rules)
	}
	t.Cleanup(func() { destroyTemporaryRules = oldDestroy })

	for i := 0; i < iterations; i++ {
		rules, err := compileDir(filepath.Dir(path), func(string, ...any) {})
		if err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
		var matches yara.MatchRules
		if err := rules.ScanMem(nil, 0, 0, &matches); err != nil || len(matches) != 1 {
			t.Fatalf("iteration %d active rules: matches=%d err=%v", i, len(matches), err)
		}
		rules.Destroy()
	}
	if created != iterations*2 {
		t.Fatalf("created compilers = %d, want %d validation plus aggregate", created, iterations*2)
	}
	if validationRulesFreed != iterations {
		t.Fatalf("validation rules Destroy calls = %d, want %d", validationRulesFreed, iterations)
	}
	for i, compiler := range compilers {
		if compiler.destroyed != 1 {
			t.Fatalf("compiler %d Destroy calls = %d, want 1", i, compiler.destroyed)
		}
	}
}

func TestFileCompilesDestroysValidationObjects(t *testing.T) {
	path := lifecycleRuleFile(t)
	cause := errors.New("native failure")
	tests := []struct {
		name             string
		path             string
		constructorErr   error
		configure        func(*lifecycleCompiler)
		wantErr          bool
		wantSetupErr     bool
		wantCompilerFree int
		wantRulesFree    int
	}{
		{name: "success", path: path, configure: func(c *lifecycleCompiler) { c.rules = lifecycleRules(t, "Validation") }, wantCompilerFree: 1, wantRulesFree: 1},
		{name: "GetRules result with error", path: path, configure: func(c *lifecycleCompiler) { c.rules = lifecycleRules(t, "ValidationError"); c.getErr = cause }, wantErr: true, wantCompilerFree: 1, wantRulesFree: 1},
		{name: "GetRules error", path: path, configure: func(c *lifecycleCompiler) { c.getErr = cause }, wantErr: true, wantCompilerFree: 1},
		{name: "AddFile error", path: path, configure: func(c *lifecycleCompiler) { c.addErr = cause }, wantErr: true, wantCompilerFree: 1},
		{name: "external definition error", path: path, configure: func(c *lifecycleCompiler) { c.defineErr = cause }, wantErr: true, wantSetupErr: true, wantCompilerFree: 1},
		{name: "open error", path: filepath.Join(t.TempDir(), "missing.yar"), wantErr: true, wantCompilerFree: 1},
		{name: "constructor error", path: path, constructorErr: cause, wantErr: true, wantSetupErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			compiler := &lifecycleCompiler{}
			if tc.configure != nil {
				tc.configure(compiler)
			}
			stubRuleCompiler(t, func() (ruleCompiler, error) {
				if tc.constructorErr != nil {
					return nil, tc.constructorErr
				}
				return compiler, nil
			})
			oldDestroy := destroyTemporaryRules
			rulesFreed := 0
			destroyTemporaryRules = func(rules *yara.Rules) {
				rulesFreed++
				oldDestroy(rules)
			}
			t.Cleanup(func() { destroyTemporaryRules = oldDestroy })

			err := fileCompiles(tc.path)
			if (err != nil) != tc.wantErr {
				t.Fatalf("fileCompiles error = %v, wantErr=%v", err, tc.wantErr)
			}
			if tc.wantErr && !tc.wantSetupErr && !errors.Is(err, cause) && tc.name != "open error" {
				t.Fatalf("errors.Is(%v, cause) = false", err)
			}
			var setupErr *ruleSetupError
			if errors.As(err, &setupErr) != tc.wantSetupErr {
				t.Fatalf("errors.As(%v, *ruleSetupError) = %v, want %v", err, errors.As(err, &setupErr), tc.wantSetupErr)
			}
			if compiler.destroyed != tc.wantCompilerFree {
				t.Fatalf("compiler Destroy calls = %d, want %d", compiler.destroyed, tc.wantCompilerFree)
			}
			if rulesFreed != tc.wantRulesFree {
				t.Fatalf("validation rules Destroy calls = %d, want %d", rulesFreed, tc.wantRulesFree)
			}
		})
	}
}
