package mailstrix

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"github.com/myguard-labs/mailstrix/internal/cape"
	"github.com/myguard-labs/mailstrix/internal/verdict"
)

const capeConfigLimit = 256 << 10
const capeReferenceLimit = 1 << 20
const capeStaticPolicy = "actionable-v1"

// ErrCAPEConfig is deliberately sanitized: configuration may contain paths and
// identifiers which must not be echoed into logs or HTTP errors.
var ErrCAPEConfig = errors.New("cape_invalid_configuration")

// ErrCAPEUnavailable reports that the configured CAPE service cannot start or serve requests.
var ErrCAPEUnavailable = errors.New("cape_service_unavailable")

// ErrCAPEDrain reports that CAPE shutdown could not durably settle all active work.
var ErrCAPEDrain = errors.New("cape_service_drain_incomplete")

type capeReference struct {
	File string `json:"file,omitempty"`
	Env  string `json:"env,omitempty"`
}
type capeEndpoint struct {
	Generation    string `json:"generation"`
	Account       string `json:"account"`
	Origin        string `json:"origin"`
	Destination   string `json:"destination"`
	Machine       string `json:"machine"`
	CredentialRef string `json:"credential_ref"`
	CARef         string `json:"ca_ref,omitempty"`
}
type capeAdmissionProfile struct {
	Endpoint         string `json:"endpoint"`
	SubmissionPolicy string `json:"submission_policy"`
	ResultPolicy     string `json:"result_policy"`
	StaticPolicy     string `json:"static_policy"`
	AllowUnknown     bool   `json:"allow_unknown"`
}
type capeTenant struct {
	TokenRefs []string `json:"token_refs"`
	Profiles  []string `json:"profiles"`
}
type capeSignalRule struct {
	Name     string        `json:"name"`
	Signal   string        `json:"signal"`
	Evidence cape.Evidence `json:"evidence"`
}
type capeDaemonConfig struct {
	Version        int                             `json:"version"`
	Policy         verdict.SandboxPolicy           `json:"policy"`
	Listen         string                          `json:"listen"`
	TLSCertRef     string                          `json:"tls_cert_ref"`
	TLSKeyRef      string                          `json:"tls_key_ref"`
	References     map[string]capeReference        `json:"references"`
	Endpoints      map[string]capeEndpoint         `json:"endpoints"`
	Profiles       map[string]capeAdmissionProfile `json:"profiles"`
	Tenants        map[string]capeTenant           `json:"tenants"`
	SignalPolicies map[string][]capeSignalRule     `json:"signal_policies"`
	// Store's existing field names are used verbatim. Tenants are derived from
	// the authenticated tenant map and cannot be configured a second time.
	Store   cape.StoreConfig `json:"store"`
	Workers int              `json:"workers"`
	// AcceptLimit bounds accepted sockets until each connection closes.
	AcceptLimit int `json:"accept_limit"`
}

func capeName(s string) bool {
	if len(s) < 1 || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

// ValidateCAPE checks administrator syntax and policy without resolving secrets,
// opening durable state or contacting an endpoint. Call before daemon listeners.
func (c *Config) ValidateCAPE() error {
	if verdict.ValidateReportOnlyPolicy(verdict.SandboxPolicy(c.CAPEPolicy)) != nil {
		return ErrCAPEConfig
	}
	c.capeConfig = nil
	if c.CAPEConfigFile == "" {
		return nil
	}
	raw, err := capeReadFile(c.CAPEConfigFile, capeConfigLimit)
	if err != nil {
		return ErrCAPEConfig
	}
	parsed, err := parseCAPEDaemonConfig(raw)
	if err == nil {
		address, _ := netip.ParseAddrPort(parsed.Listen)
		if address.Port() == 0 {
			return ErrCAPEConfig
		}
		if int(address.Port()) == c.Port {
			return ErrCAPEConfig
		}
		for _, other := range []string{c.ICAPAddr, c.ClamdTCPAddr} {
			_, port, e := net.SplitHostPort(other)
			if e == nil && port == strconv.Itoa(int(address.Port())) {
				return ErrCAPEConfig
			}
		}
		c.capeConfig = parsed
	}
	return err
}

func capeReadFile(path string, limit int64) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, ErrCAPEUnavailable
	}
	f, err := os.Open(path) // #nosec G304 -- operator-selected daemon config or credential reference path
	if err != nil {
		return nil, ErrCAPEUnavailable
	}
	defer f.Close()
	info, err = f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, ErrCAPEUnavailable
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, ErrCAPEUnavailable
	}
	return b, nil
}

func parseCAPEDaemonConfig(raw []byte) (*capeDaemonConfig, error) {
	if len(raw) > capeConfigLimit {
		return nil, ErrCAPEConfig
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if capeJSONValue(d, 0) != nil {
		return nil, ErrCAPEConfig
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, ErrCAPEConfig
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	var c capeDaemonConfig
	if capeConfigKeys(raw, reflect.TypeOf(c)) != nil || d.Decode(&c) != nil || c.validate() != nil {
		return nil, ErrCAPEConfig
	}
	return &c, nil
}

// encoding/json otherwise accepts case aliases for struct fields, allowing
// distinct keys such as version/Version to overwrite the same setting.
func capeConfigKeys(raw json.RawMessage, typ reflect.Type) error {
	switch typ.Kind() {
	case reflect.Struct:
		var object map[string]json.RawMessage
		if json.Unmarshal(raw, &object) != nil {
			return ErrCAPEConfig
		}
		fields := map[string]reflect.Type{}
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			name := strings.Split(field.Tag.Get("json"), ",")[0]
			if name == "" {
				name = field.Name
			}
			fields[name] = field.Type
		}
		for key, value := range object {
			field, ok := fields[key]
			if !ok || capeConfigKeys(value, field) != nil {
				return ErrCAPEConfig
			}
		}
	case reflect.Map:
		var object map[string]json.RawMessage
		if json.Unmarshal(raw, &object) != nil {
			return ErrCAPEConfig
		}
		for _, value := range object {
			if capeConfigKeys(value, typ.Elem()) != nil {
				return ErrCAPEConfig
			}
		}
	case reflect.Slice:
		var items []json.RawMessage
		if json.Unmarshal(raw, &items) != nil {
			return ErrCAPEConfig
		}
		for _, value := range items {
			if capeConfigKeys(value, typ.Elem()) != nil {
				return ErrCAPEConfig
			}
		}
	}
	return nil
}

// Duplicate keys are configuration ambiguity, including inside maps. Bound
// nesting independently of file bytes before decoding the typed configuration.
func capeJSONValue(d *json.Decoder, depth int) error {
	if depth > 16 {
		return ErrCAPEConfig
	}
	t, err := d.Token()
	if err != nil {
		return ErrCAPEConfig
	}
	switch t {
	case json.Delim('{'):
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			name, ok := key.(string)
			if err != nil || !ok || seen[name] {
				return ErrCAPEConfig
			}
			seen[name] = true
			if capeJSONValue(d, depth+1) != nil {
				return ErrCAPEConfig
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') {
			return ErrCAPEConfig
		}
	case json.Delim('['):
		for d.More() {
			if capeJSONValue(d, depth+1) != nil {
				return ErrCAPEConfig
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return ErrCAPEConfig
		}
	}
	return nil
}

func (c *capeDaemonConfig) validate() error {
	if c.validateService() != nil || c.validateReferences() != nil || c.validateEndpoints() != nil || c.validateSignalPolicies() != nil || c.validateProfiles() != nil || c.validateTenants() != nil || c.validateStore() != nil {
		return ErrCAPEConfig
	}
	return nil
}

func (c *capeDaemonConfig) validateService() error {
	if c.Version != 1 || verdict.ValidateReportOnlyPolicy(c.Policy) != nil || c.Workers < 1 || c.Workers > cape.MaxSchedulerWorkers || c.AcceptLimit < 1 || c.AcceptLimit > 4096 {
		return ErrCAPEConfig
	}
	if _, err := netip.ParseAddrPort(c.Listen); err != nil {
		return ErrCAPEConfig
	}
	if len(c.References) < 1 || len(c.References) > 256 || len(c.Endpoints) < 1 || len(c.Endpoints) > 16 || len(c.Profiles) < 1 || len(c.Profiles) > 128 || len(c.Tenants) < 1 || len(c.Tenants) > 128 || len(c.SignalPolicies) < 1 || len(c.SignalPolicies) > 128 {
		return ErrCAPEConfig
	}
	return nil
}

func (c *capeDaemonConfig) validateReferences() error {
	for name, ref := range c.References {
		if !capeName(name) || (ref.File == "") == (ref.Env == "") {
			return ErrCAPEConfig
		}
		if ref.File != "" && !filepath.IsAbs(ref.File) {
			return ErrCAPEConfig
		}
		if ref.Env != "" {
			for i, r := range ref.Env {
				if !(r >= 'A' && r <= 'Z' || r == '_' || i > 0 && r >= '0' && r <= '9') {
					return ErrCAPEConfig
				}
			}
		}
	}
	if !c.hasReference(c.TLSCertRef) || !c.hasReference(c.TLSKeyRef) {
		return ErrCAPEConfig
	}
	return nil
}

func (c *capeDaemonConfig) validateEndpoints() error {
	for name, endpoint := range c.Endpoints {
		if !capeName(name) || !capeName(endpoint.Generation) || !capeName(endpoint.Account) || !c.hasReference(endpoint.CredentialRef) || (endpoint.CARef != "" && !c.hasReference(endpoint.CARef)) {
			return ErrCAPEConfig
		}
		destination, err := netip.ParseAddrPort(endpoint.Destination)
		if err != nil {
			return ErrCAPEConfig
		}
		client, err := cape.New(cape.Config{Origin: endpoint.Origin, AllowedDestination: destination, Generation: "validation", Machine: endpoint.Machine, CredentialReference: endpoint.CredentialRef}, capeCredentials{})
		if err != nil {
			return ErrCAPEConfig
		}
		_ = client.Close()
	}
	return nil
}

func (c *capeDaemonConfig) validateSignalPolicies() error {
	for name, rules := range c.SignalPolicies {
		if _, err := capeSignatureMapper(name, rules); err != nil {
			return ErrCAPEConfig
		}
	}
	return nil
}

func (c *capeDaemonConfig) validateProfiles() error {
	for name, p := range c.Profiles {
		_, endpoint := c.Endpoints[p.Endpoint]
		_, policy := c.SignalPolicies[p.ResultPolicy]
		if !capeName(name) || !capeName(p.SubmissionPolicy) || !endpoint || !policy || p.StaticPolicy != capeStaticPolicy || !p.AllowUnknown {
			return ErrCAPEConfig
		}
	}
	return nil
}

func (c *capeDaemonConfig) validateTenants() error {
	endpointCredentialRefs := make(map[string]struct{}, len(c.Endpoints))
	for _, endpoint := range c.Endpoints {
		endpointCredentialRefs[endpoint.CredentialRef] = struct{}{}
	}
	for name, tenant := range c.Tenants {
		if !capeName(name) || len(tenant.TokenRefs) < 1 || len(tenant.TokenRefs) > 2 || len(tenant.Profiles) < 1 || len(tenant.Profiles) > 128 {
			return ErrCAPEConfig
		}
		seen := map[string]bool{}
		for _, ref := range tenant.TokenRefs {
			_, endpointCredential := endpointCredentialRefs[ref]
			if !c.hasReference(ref) || seen[ref] || endpointCredential {
				return ErrCAPEConfig
			}
			seen[ref] = true
		}
		seen = map[string]bool{}
		for _, profile := range tenant.Profiles {
			if _, ok := c.Profiles[profile]; !ok || seen[profile] {
				return ErrCAPEConfig
			}
			seen[profile] = true
		}
	}
	return nil
}

func (c *capeDaemonConfig) validateStore() error {
	if !filepath.IsAbs(c.Store.Directory) || len(c.Store.Tenants) != 0 {
		return ErrCAPEConfig
	}
	store := c.Store
	if cape.ValidateStoreLimits(&store) != nil {
		return ErrCAPEConfig
	}
	return nil
}
func (c *capeDaemonConfig) hasReference(name string) bool {
	_, ok := c.References[name]
	return capeName(name) && ok
}

type capeResolver func(context.Context, string) ([]byte, error)

func (c *capeDaemonConfig) resolver() capeResolver {
	return func(ctx context.Context, name string) ([]byte, error) {
		if ctx.Err() != nil {
			return nil, ErrCAPEUnavailable
		}
		ref, ok := c.References[name]
		if !ok {
			return nil, ErrCAPEConfig
		}
		var b []byte
		if ref.File != "" {
			var err error
			b, err = capeReadFile(ref.File, capeReferenceLimit)
			if err != nil {
				return nil, ErrCAPEUnavailable
			}
		} else {
			b = []byte(os.Getenv(ref.Env))
		}
		if len(b) == 0 || len(b) > capeReferenceLimit || ctx.Err() != nil {
			return nil, ErrCAPEUnavailable
		}
		return b, nil
	}
}

func capeToken(raw []byte) (string, error) {
	token := strings.TrimSpace(string(raw))
	if len(token) < 1 || len(token) > 4096 {
		return "", ErrCAPEUnavailable
	}
	for _, r := range token {
		if r <= 32 || r >= 127 {
			return "", ErrCAPEUnavailable
		}
	}
	return token, nil
}
