package mailstrix

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"sort"

	"github.com/myguard-labs/mailstrix/internal/cape"
)

type capeRuntime struct {
	handler http.Handler
	run     func(context.Context) error
	close   func() error
}
type capeCredentials map[string]string

func (p capeCredentials) Token(ctx context.Context, ref string) (string, error) {
	token, ok := p[ref]
	if ctx.Err() != nil || !ok {
		return "", ErrCAPEUnavailable
	}
	return token, nil
}

type capePolicyMappers map[string]*cape.SignatureMapper

func capeSignatureMapper(id string, rules []capeSignalRule) (*cape.SignatureMapper, error) {
	converted := make([]cape.SignatureRule, len(rules))
	for i, r := range rules {
		converted[i] = cape.SignatureRule{Name: r.Name, Signal: r.Signal, Evidence: r.Evidence}
	}
	return cape.NewSignatureMapper(id, converted)
}

func capeBuildPolicyMappers(policies map[string][]capeSignalRule) (capePolicyMappers, map[string]string, error) {
	mappers := capePolicyMappers{}
	identities := map[string]string{}
	for label, rules := range policies {
		id := capeResultIdentity(label, rules)
		mapper, err := capeSignatureMapper(id, rules)
		if err != nil {
			return nil, nil, ErrCAPEConfig
		}
		mappers[id] = mapper
		identities[label] = id
	}
	return mappers, identities, nil
}

func (m capePolicyMappers) Normalize(ctx context.Context, r *cape.Report, policy string) (cape.NormalizedResult, error) {
	mapper := m[policy]
	if mapper == nil {
		return cape.NormalizedResult{}, ErrCAPEConfig
	}
	return mapper.Normalize(ctx, r, policy)
}

func capeIdentity(prefix string, value any) string {
	// All callers use fixed JSON-serializable structs, never credential values.
	b, _ := json.Marshal(value)
	sum := sha256.Sum256(b)
	return prefix + hex.EncodeToString(sum[:])
}

func capeGenerationID(e capeEndpoint, ca []byte) string {
	destination, _ := netip.ParseAddrPort(e.Destination)
	trust := sha256.Sum256(ca)
	return capeIdentity("g-", struct{ Generation, Account, Origin, Destination, Machine, CredentialRef, CARef, Trust string }{e.Generation, e.Account, e.Origin, destination.String(), e.Machine, e.CredentialRef, e.CARef, hex.EncodeToString(trust[:])})
}

func capeResultIdentity(label string, rules []capeSignalRule) string {
	ordered := append([]capeSignalRule(nil), rules...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Name < ordered[j].Name })
	return capeIdentity("r-", struct {
		Label string
		Rules []capeSignalRule
	}{label, ordered})
}
func capeSubmissionIdentity(p capeAdmissionProfile) string {
	return capeIdentity("s-", struct {
		Label, StaticPolicy string
		AllowUnknown        bool
	}{p.SubmissionPolicy, p.StaticPolicy, p.AllowUnknown})
}

type capeAuthEntry struct {
	tenant string
	digest [32]byte
}

func buildCAPEAuth(ctx context.Context, c *capeDaemonConfig, resolve capeResolver, upstreamDigests map[[32]byte]struct{}) (func(*http.Request) (string, error), error) {
	entries := []capeAuthEntry{}
	seen := map[[32]byte]bool{}
	for tenant, config := range c.Tenants {
		for _, ref := range config.TokenRefs {
			raw, err := resolve(ctx, ref)
			if err != nil {
				return nil, ErrCAPEUnavailable
			}
			token, err := capeToken(raw)
			if err != nil {
				return nil, ErrCAPEUnavailable
			}
			digest := sha256.Sum256([]byte(token))
			_, upstreamCredential := upstreamDigests[digest]
			if seen[digest] || upstreamCredential {
				return nil, ErrCAPEConfig
			}
			seen[digest] = true
			entries = append(entries, capeAuthEntry{tenant, digest})
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].tenant < entries[j].tenant })
	return func(r *http.Request) (string, error) {
		values := r.Header.Values("Authorization")
		if len(values) != 1 || len(values[0]) > 4096+7 {
			return "", ErrCAPEUnavailable
		}
		token, ok := bearerToken(values[0])
		if !ok {
			return "", ErrCAPEUnavailable
		}
		digest := sha256.Sum256([]byte(token))
		tenant := ""
		for _, entry := range entries {
			if subtle.ConstantTimeCompare(digest[:], entry.digest[:]) == 1 {
				tenant = entry.tenant
			}
		}
		if tenant == "" {
			return "", ErrCAPEUnavailable
		}
		return tenant, nil
	}, nil
}

func buildCAPERuntime(ctx context.Context, c *capeDaemonConfig, resolve capeResolver, scan func(context.Context, string, io.Reader) (string, error)) (_ *capeRuntime, retErr error) {
	clients := map[string]*cape.Client{}
	defer func() {
		if retErr != nil {
			for _, client := range clients {
				_ = client.Close()
			}
		}
	}()
	generations := map[string]string{}
	credentials := capeCredentials{}
	upstreamDigests := map[[32]byte]struct{}{}
	for name, endpoint := range c.Endpoints {
		if _, ok := credentials[endpoint.CredentialRef]; !ok {
			raw, err := resolve(ctx, endpoint.CredentialRef)
			if err != nil {
				return nil, ErrCAPEUnavailable
			}
			token, err := capeToken(raw)
			if err != nil {
				return nil, ErrCAPEUnavailable
			}
			credentials[endpoint.CredentialRef] = token
			upstreamDigests[sha256.Sum256([]byte(token))] = struct{}{}
		}
		var ca []byte
		if endpoint.CARef != "" {
			var err error
			ca, err = resolve(ctx, endpoint.CARef)
			if err != nil {
				return nil, ErrCAPEUnavailable
			}
		}
		generation := capeGenerationID(endpoint, ca)
		if clients[generation] != nil {
			return nil, ErrCAPEConfig
		}
		destination, _ := netip.ParseAddrPort(endpoint.Destination)
		client, err := cape.New(cape.Config{Origin: endpoint.Origin, AllowedDestination: destination, Generation: generation, Machine: endpoint.Machine, CredentialReference: endpoint.CredentialRef, CAPEM: ca}, credentials)
		if err != nil {
			return nil, ErrCAPEConfig
		}
		clients[generation] = client
		generations[name] = generation
	}
	authenticate, err := buildCAPEAuth(ctx, c, resolve, upstreamDigests)
	if err != nil {
		return nil, err
	}
	mappers, resultPolicies, err := capeBuildPolicyMappers(c.SignalPolicies)
	if err != nil {
		return nil, err
	}
	profiles := map[string]cape.APIProfile{}
	for name, p := range c.Profiles {
		profiles[name] = cape.APIProfile{Generation: generations[p.Endpoint], SubmissionPolicy: capeSubmissionIdentity(p), ResultPolicy: resultPolicies[p.ResultPolicy], AllowUnknown: p.AllowUnknown}
	}
	storeConfig := c.Store
	for tenant := range c.Tenants {
		storeConfig.Tenants = append(storeConfig.Tenants, tenant)
	}
	sort.Strings(storeConfig.Tenants)
	store, err := cape.OpenStore(ctx, storeConfig)
	if err != nil {
		var local *cape.Error
		if errors.As(err, &local) && local.Code == cape.Invalid {
			return nil, ErrCAPEConfig
		}
		return nil, ErrCAPEUnavailable
	}
	defer func() {
		if retErr != nil {
			_ = store.Close()
		}
	}()
	handler, err := cape.NewAPIHandler(cape.APIConfig{Enabled: true, Store: store, Authenticate: authenticate, StaticScan: scan, Profile: func(_ context.Context, tenant, name string) (cape.APIProfile, error) {
		for _, allowed := range c.Tenants[tenant].Profiles {
			if allowed == name {
				return profiles[name], nil
			}
		}
		return cape.APIProfile{}, ErrCAPEConfig
	}})
	if err != nil {
		return nil, ErrCAPEConfig
	}
	scheduler, err := cape.NewScheduler(store, clients, mappers, c.Workers)
	if err != nil {
		return nil, ErrCAPEConfig
	}
	return &capeRuntime{handler: handler, run: scheduler.Run, close: func() error {
		err := store.Close()
		for _, client := range clients {
			_ = client.Close()
		}
		return err
	}}, nil
}
