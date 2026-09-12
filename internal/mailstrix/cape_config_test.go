package mailstrix

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/myguard-labs/mailstrix/internal/cape"
	"github.com/myguard-labs/mailstrix/internal/verdict"
)

func capeFixtureConfig() *capeDaemonConfig {
	return &capeDaemonConfig{Version: 1, Policy: verdict.StaticOnly, Listen: "127.0.0.1:0", TLSCertRef: "cert", TLSKeyRef: "key", Workers: 1, AcceptLimit: 8,
		References:     map[string]capeReference{"cert": {Env: "FIXTURE_CERT"}, "key": {Env: "FIXTURE_KEY"}, "remote": {Env: "FIXTURE_REMOTE"}, "alpha": {Env: "FIXTURE_ALPHA"}, "beta": {Env: "FIXTURE_BETA"}},
		Endpoints:      map[string]capeEndpoint{"primary": {Generation: "generation_v1", Account: "account_v1", Origin: "https://cape.invalid", Destination: "127.0.0.1:443", Machine: "windows", CredentialRef: "remote"}},
		Profiles:       map[string]capeAdmissionProfile{"manual": {Endpoint: "primary", SubmissionPolicy: "manual_v1", ResultPolicy: "signals_v1", StaticPolicy: capeStaticPolicy, AllowUnknown: true}},
		Tenants:        map[string]capeTenant{"alpha": {TokenRefs: []string{"alpha"}, Profiles: []string{"manual"}}, "beta": {TokenRefs: []string{"beta"}, Profiles: []string{"manual"}}},
		SignalPolicies: map[string][]capeSignalRule{"signals_v1": {{Name: "bad", Signal: "local_bad", Evidence: cape.EvidenceMalicious}}},
		Store:          cape.StoreConfig{Directory: "/fixture/private"},
	}
}

func TestCAPEDaemonConfigStrict(t *testing.T) {
	raw, err := json.Marshal(capeFixtureConfig())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseCAPEDaemonConfig(raw); err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{
		"unknown":   []byte(strings.Replace(string(raw), `"version":1`, `"version":1,"secret":"never"`, 1)),
		"duplicate": []byte(strings.Replace(string(raw), `"version":1`, `"version":1,"version":1`, 1)),
		"alias":     []byte(strings.Replace(string(raw), `"version":1`, `"version":1,"Version":1`, 1)),
		"trailing":  append(append([]byte(nil), raw...), []byte(`{}`)...),
		"oversize":  []byte(strings.Repeat(" ", capeConfigLimit+1)),
		"malformed": []byte(`{"version":`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseCAPEDaemonConfig(raw); !errors.Is(err, ErrCAPEConfig) {
				t.Fatalf("ambiguous configuration accepted: %v", err)
			}
		})
	}
	for _, policy := range []verdict.SandboxPolicy{verdict.Tempfail, verdict.QuarantinePending, "typo"} {
		c := capeFixtureConfig()
		c.Policy = policy
		if c.validate() == nil {
			t.Fatal("unsupported policy accepted")
		}
	}
	for name, mutate := range map[string]func(*capeDaemonConfig){
		"accept-limit-zero": func(c *capeDaemonConfig) { c.AcceptLimit = 0 },
		"accept-limit-high": func(c *capeDaemonConfig) { c.AcceptLimit = 4097 },
		"reference":         func(c *capeDaemonConfig) { c.TLSKeyRef = "missing" },
		"inline-and-file":   func(c *capeDaemonConfig) { c.References["key"] = capeReference{Env: "KEY", File: "/fixture/key"} },
		"relative":          func(c *capeDaemonConfig) { c.References["key"] = capeReference{File: "relative"} },
		"plaintext": func(c *capeDaemonConfig) {
			e := c.Endpoints["primary"]
			e.Origin = "http://cape.invalid"
			c.Endpoints["primary"] = e
		},
		"tenant-profile": func(c *capeDaemonConfig) {
			c.Tenants["alpha"] = capeTenant{TokenRefs: []string{"alpha"}, Profiles: []string{"missing"}}
		},
		"duplicate-ref": func(c *capeDaemonConfig) {
			c.Tenants["alpha"] = capeTenant{TokenRefs: []string{"alpha", "alpha"}, Profiles: []string{"manual"}}
		},
		"credential-role-overlap": func(c *capeDaemonConfig) {
			c.Tenants["alpha"] = capeTenant{TokenRefs: []string{"remote"}, Profiles: []string{"manual"}}
		},
		"static-policy": func(c *capeDaemonConfig) {
			p := c.Profiles["manual"]
			p.StaticPolicy = "unknown"
			c.Profiles["manual"] = p
		},
		"arbitrary-tenants": func(c *capeDaemonConfig) { c.Store.Tenants = []string{"caller"} },
		"max-jobs-high":     func(c *capeDaemonConfig) { c.Store.MaxJobs = 10001 },
		"tenant-jobs-high":  func(c *capeDaemonConfig) { c.Store.MaxJobs, c.Store.TenantJobs = 1, 2 },
		"max-bytes-negative": func(c *capeDaemonConfig) {
			c.Store.MaxBytes = -1
		},
		"submit-rate-high": func(c *capeDaemonConfig) { c.Store.SubmitPerMinute = 10001 },
		"concurrency-high": func(c *capeDaemonConfig) { c.Store.SubmissionConcurrency = 101 },
	} {
		t.Run(name, func(t *testing.T) {
			c := capeFixtureConfig()
			mutate(c)
			if c.validate() == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
}

func TestCAPEDaemonConfigDefaultsAndReferences(t *testing.T) {
	t.Setenv("MAILSTRIX_CAPE_CONFIG_FILE", "")
	t.Setenv("MAILSTRIX_CAPE_POLICY", "")
	cfg := LoadConfig()
	if cfg.CAPEConfigFile != "" || cfg.CAPEPolicy != "static-only" || cfg.ValidateCAPE() != nil {
		t.Fatal("disabled default changed")
	}
	for _, policy := range []string{"tempfail", "quarantine-pending"} {
		cfg.CAPEPolicy = policy
		if cfg.ValidateCAPE() == nil {
			t.Fatal("daemon enforcement accepted")
		}
	}
	c := capeFixtureConfig()
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("synthetic-value\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c.References["file"] = capeReference{File: path}
	raw, err := c.resolver()(context.Background(), "file")
	if err != nil || string(raw) != "synthetic-value\n" {
		t.Fatal("reference resolution failed", err)
	}
	if _, err := c.resolver()(context.Background(), "absent"); err == nil {
		t.Fatal("missing reference accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.resolver()(ctx, "file"); err == nil {
		t.Fatal("cancelled resolver accepted")
	}
	if err := os.WriteFile(path, make([]byte, capeReferenceLimit+1), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.resolver()(context.Background(), "file"); err == nil {
		t.Fatal("oversize reference accepted")
	}
}

func TestCAPEDaemonIdentities(t *testing.T) {
	e := capeFixtureConfig().Endpoints["primary"]
	base := capeGenerationID(e, nil)
	for name, mutate := range map[string]func(*capeEndpoint){
		"generation": func(e *capeEndpoint) { e.Generation += "2" }, "account": func(e *capeEndpoint) { e.Account += "2" }, "origin": func(e *capeEndpoint) { e.Origin = "https://other.invalid" }, "destination": func(e *capeEndpoint) { e.Destination = "127.0.0.2:443" }, "machine": func(e *capeEndpoint) { e.Machine = "other" }, "credential-ref": func(e *capeEndpoint) { e.CredentialRef = "other" }, "ca-ref": func(e *capeEndpoint) { e.CARef = "trust" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := e
			mutate(&changed)
			if capeGenerationID(changed, nil) == base {
				t.Fatal("effective endpoint change reused generation")
			}
		})
	}
	if capeGenerationID(e, []byte("different trust")) == base {
		t.Fatal("trust change reused generation")
	}
	rules := []capeSignalRule{{"one", "a", cape.EvidenceMalicious}, {"two", "b", cape.EvidenceSuspicious}}
	first := capeResultIdentity("v1", rules)
	if capeResultIdentity("v1", []capeSignalRule{rules[1], rules[0]}) != first {
		t.Fatal("rule order changed identity")
	}
	if capeResultIdentity("v2", rules) == first {
		t.Fatal("result version ignored")
	}
	for _, field := range []string{"name", "signal", "evidence"} {
		changed := append([]capeSignalRule(nil), rules...)
		switch field {
		case "name":
			changed[0].Name = "new"
		case "signal":
			changed[0].Signal = "new"
		case "evidence":
			changed[0].Evidence = cape.EvidenceSuspicious
		}
		if capeResultIdentity("v1", changed) == first {
			t.Fatal("effective result policy change ignored", field)
		}
	}
	p := capeFixtureConfig().Profiles["manual"]
	first = capeSubmissionIdentity(p)
	for _, field := range []string{"label", "static", "eligibility"} {
		changed := p
		switch field {
		case "label":
			changed.SubmissionPolicy = "new"
		case "static":
			changed.StaticPolicy = "new"
		case "eligibility":
			changed.AllowUnknown = false
		}
		if capeSubmissionIdentity(changed) == first {
			t.Fatal("effective submission policy change ignored", field)
		}
	}
}

func TestCAPEDaemonPolicyRotation(t *testing.T) {
	c := capeFixtureConfig()
	oldRules := c.SignalPolicies["signals_v1"]
	oldID := capeResultIdentity("signals_v1", oldRules)
	oldMapper, err := cape.NewSignatureMapper(oldID, []cape.SignatureRule{{Name: "bad", Signal: "local_bad", Evidence: cape.EvidenceMalicious}})
	if err != nil {
		t.Fatal(err)
	}
	c.SignalPolicies["signals_v2"] = []capeSignalRule{{Name: "bad", Signal: "local_suspicious", Evidence: cape.EvidenceSuspicious}}
	p := c.Profiles["manual"]
	p.ResultPolicy = "signals_v2"
	c.Profiles["manual"] = p
	if err := c.validate(); err != nil {
		t.Fatal("additive policy rotation rejected", err)
	}
	mappers, ids, err := capeBuildPolicyMappers(c.SignalPolicies)
	if err != nil || ids["signals_v1"] != oldID || !reflect.DeepEqual(mappers[oldID], oldMapper) {
		t.Fatal("old mapper identity or exact rules lost during rotation", err)
	}
	newID := ids[c.Profiles["manual"].ResultPolicy]
	newMapper, err := cape.NewSignatureMapper(newID, []cape.SignatureRule{{Name: "bad", Signal: "local_suspicious", Evidence: cape.EvidenceSuspicious}})
	if err != nil || newID == oldID || !reflect.DeepEqual(mappers[newID], newMapper) {
		t.Fatal("new admission mapper did not use new policy", err)
	}
	delete(c.SignalPolicies, "signals_v1")
	mappers, _, err = capeBuildPolicyMappers(c.SignalPolicies)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mappers.Normalize(context.Background(), nil, oldID); !errors.Is(err, ErrCAPEConfig) {
		t.Fatal("removed old policy unexpectedly retained its mapper", err)
	}
}

func TestCAPEDaemonTenantAuth(t *testing.T) {
	c := capeFixtureConfig()
	resolve := func(_ context.Context, name string) ([]byte, error) { return []byte("fixture-" + name), nil }
	auth, err := buildCAPEAuth(context.Background(), c, resolve, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "https://local.invalid/v1/cape/jobs", nil)
	r.Header.Set("Authorization", "Bearer fixture-alpha")
	r.Header.Set("X-Tenant", "beta")
	if tenant, err := auth(r); err != nil || tenant != "alpha" {
		t.Fatal("request header changed authenticated tenant", tenant, err)
	}
	r.Header.Add("Authorization", "Bearer fixture-beta")
	if _, err := auth(r); err == nil {
		t.Fatal("multiple credentials accepted")
	}
	if _, err := buildCAPEAuth(context.Background(), c, func(context.Context, string) ([]byte, error) { return []byte("same"), nil }, nil); !errors.Is(err, ErrCAPEConfig) {
		t.Fatal("ambiguous credentials accepted", err)
	}
}

func TestCAPEDaemonCredentialRoleSeparation(t *testing.T) {
	c := capeFixtureConfig()
	upstream := sha256.Sum256([]byte("upstream-secret"))

	t.Run("distinct credentials", func(t *testing.T) {
		resolve := func(_ context.Context, name string) ([]byte, error) {
			return []byte("tenant-" + name), nil
		}
		if _, err := buildCAPEAuth(context.Background(), c, resolve, map[[32]byte]struct{}{upstream: {}}); err != nil {
			t.Fatal("distinct credential roles rejected", err)
		}
	})

	t.Run("distinct references same value", func(t *testing.T) {
		resolve := func(_ context.Context, name string) ([]byte, error) {
			if name == "alpha" {
				return []byte("upstream-secret"), nil
			}
			return []byte("tenant-" + name), nil
		}
		if _, err := buildCAPEAuth(context.Background(), c, resolve, map[[32]byte]struct{}{upstream: {}}); !errors.Is(err, ErrCAPEConfig) {
			t.Fatal("credential value reused across roles", err)
		}
	})
}

func TestCAPEDaemonConflictingListener(t *testing.T) {
	for _, target := range []string{"http", "icap", "clamd"} {
		t.Run(target, func(t *testing.T) {
			c := capeFixtureConfig()
			c.Listen = "127.0.0.1:8443"
			raw, err := json.Marshal(c)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "admin.json")
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			cfg := &Config{CAPEConfigFile: path, Port: 8079}
			switch target {
			case "http":
				cfg.Port = 8443
			case "icap":
				cfg.ICAPAddr = ":8443"
			case "clamd":
				cfg.ClamdTCPAddr = "127.0.0.1:8443"
			}
			if err := cfg.ValidateCAPE(); !errors.Is(err, ErrCAPEConfig) || cfg.capeConfig != nil {
				t.Fatal("CAPE listener stole static adapter port", err)
			}
		})
	}
}

func TestCAPEDaemonPublicListenerPort(t *testing.T) {
	for _, port := range []string{"0", "8443"} {
		t.Run(port, func(t *testing.T) {
			c := capeFixtureConfig()
			c.Listen = "127.0.0.1:" + port
			raw, err := json.Marshal(c)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "admin.json")
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			cfg := &Config{CAPEConfigFile: path, Port: 8079}
			err = cfg.ValidateCAPE()
			if port == "0" {
				if !errors.Is(err, ErrCAPEConfig) || cfg.capeConfig != nil {
					t.Fatal("public CAPE ephemeral port accepted", err)
				}
			} else if err != nil || cfg.capeConfig == nil {
				t.Fatal("fixed public CAPE port rejected", err)
			}
		})
	}
}

func TestCAPEDaemonRuntimeReferenceAndStoreFailures(t *testing.T) {
	c := capeFixtureConfig()
	c.Store.Directory = filepath.Join(t.TempDir(), "absent")
	s := newTestServer(&fakeEngine{}, "tok")
	resolve := func(_ context.Context, ref string) ([]byte, error) { return []byte("fixture-" + ref), nil }
	if runtime, err := buildCAPERuntime(context.Background(), c, resolve, s.capeStaticScan); runtime != nil || !errors.Is(err, ErrCAPEUnavailable) {
		t.Fatal("missing durable state did not fail operationally", err)
	}
	c.Store.MaxAttachment = cape.MaxAttachment + 1
	if runtime, err := buildCAPERuntime(context.Background(), c, resolve, s.capeStaticScan); runtime != nil || !errors.Is(err, ErrCAPEConfig) {
		t.Fatal("invalid store config accepted", err)
	}
	c.Store.MaxAttachment = 0
	missing := func(ctx context.Context, ref string) ([]byte, error) {
		if ref == "remote" {
			return nil, errors.New("private-path-details")
		}
		return resolve(ctx, ref)
	}
	if runtime, err := buildCAPERuntime(context.Background(), c, missing, s.capeStaticScan); runtime != nil || !errors.Is(err, ErrCAPEUnavailable) || strings.Contains(err.Error(), "private-path") {
		t.Fatal("reference failure not sanitized", err)
	}
}

func TestCAPEDaemonRuntimeCredentialRoleSeparation(t *testing.T) {
	c := capeFixtureConfig()
	c.Store.Directory = filepath.Join(t.TempDir(), "absent")
	s := newTestServer(&fakeEngine{}, "tok")

	resolve := func(_ context.Context, ref string) ([]byte, error) {
		if ref == "remote" || ref == "alpha" {
			return []byte("shared-secret"), nil
		}
		return []byte("fixture-" + ref), nil
	}
	if runtime, err := buildCAPERuntime(context.Background(), c, resolve, s.capeStaticScan); runtime != nil || !errors.Is(err, ErrCAPEConfig) {
		t.Fatal("resolved credential reused across roles", err)
	}

	resolve = func(_ context.Context, ref string) ([]byte, error) {
		return []byte("distinct-" + ref), nil
	}
	if runtime, err := buildCAPERuntime(context.Background(), c, resolve, s.capeStaticScan); runtime != nil || !errors.Is(err, ErrCAPEUnavailable) {
		t.Fatal("distinct credential roles did not reach store initialization", err)
	}
}
