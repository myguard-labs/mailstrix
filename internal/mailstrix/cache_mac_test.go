package mailstrix

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

const testMACKey = "0123456789abcdef0123456789abcdef" // 32 bytes

// fakeStore is an in-memory Redis stand-in installed as a go-redis hook, so
// get/put run through the real redisLayer code without a server.
type fakeStore struct {
	mu sync.Mutex
	m  map[string][]byte
}

func (f *fakeStore) DialHook(next redis.DialHook) redis.DialHook { return next }
func (f *fakeStore) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}
func (f *fakeStore) ProcessHook(redis.ProcessHook) redis.ProcessHook {
	return func(_ context.Context, cmd redis.Cmder) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		a := cmd.Args()
		switch strings.ToLower(a[0].(string)) {
		case "get":
			v, ok := f.m[a[1].(string)]
			if !ok {
				cmd.SetErr(redis.Nil)
				return redis.Nil
			}
			cmd.(*redis.StringCmd).SetVal(string(v))
		case "set":
			switch v := a[2].(type) {
			case []byte:
				f.m[a[1].(string)] = append([]byte(nil), v...)
			case string:
				f.m[a[1].(string)] = []byte(v)
			}
			cmd.(*redis.StatusCmd).SetVal("OK")
		}
		return nil
	}
}

func newMACLayer(key string) (*redisLayer, *fakeStore, *[]string) {
	fs := &fakeStore{m: map[string][]byte{}}
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	rdb.AddHook(fs)
	var logs []string
	rl := &redisLayer{rdb: rdb, prefix: "p:", logf: func(f string, _ ...any) { logs = append(logs, f) }}
	if key != "" {
		rl.macKey = []byte(key)
	}
	return rl, fs, &logs
}

var macMatches = []Match{{Rule: "r1"}}

func TestRedisMACRoundTrip(t *testing.T) {
	rl, fs, _ := newMACLayer(testMACKey)
	rl.put("k", macMatches, time.Minute)
	raw := fs.m["p:k"]
	if len(raw) == 0 || raw[0] != macVersion {
		t.Fatalf("stored value not MAC framed: %q", raw)
	}
	m, ok := rl.get("k")
	if !ok || len(m) != 1 || m[0].Rule != "r1" {
		t.Fatalf("round trip = %v, %v", m, ok)
	}
}

func TestRedisMACRejects(t *testing.T) {
	seed := func() (*redisLayer, *fakeStore, *[]string) {
		rl, fs, logs := newMACLayer(testMACKey)
		rl.put("k", macMatches, time.Minute)
		rl.put("other", []Match{{Rule: "r2"}}, time.Minute)
		return rl, fs, logs
	}
	cases := map[string]func(fs *fakeStore){
		"tampered value": func(fs *fakeStore) {
			b := fs.m["p:k"]
			b[len(b)-3] ^= 0x01
		},
		"tampered mac": func(fs *fakeStore) { fs.m["p:k"][5] ^= 0x01 },
		"mac from another redis key": func(fs *fakeStore) {
			fs.m["p:k"] = fs.m["p:other"]
		},
		"legacy unmaced value": func(fs *fakeStore) {
			fs.m["p:k"] = mustJSON(t, macMatches)
		},
		"legacy null value": func(fs *fakeStore) { fs.m["p:k"] = []byte(`null`) },
		"truncated framing": func(fs *fakeStore) { fs.m["p:k"] = fs.m["p:k"][:10] },
		"version byte only": func(fs *fakeStore) { fs.m["p:k"] = []byte{macVersion} },
		"mac only":          func(fs *fakeStore) { fs.m["p:k"] = fs.m["p:k"][:1+macLen] },
		"empty value":       func(fs *fakeStore) { fs.m["p:k"] = []byte{} },
		"bad version":       func(fs *fakeStore) { fs.m["p:k"][0] = 0x02 },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			rl, fs, logs := seed()
			mut(fs)
			if m, ok := rl.get("k"); ok {
				t.Fatalf("accepted bad value: %v", m)
			}
			if len(*logs) != 1 || strings.Contains((*logs)[0], testMACKey) {
				t.Fatalf("expected one key-free warning, got %v", *logs)
			}
			rl.get("k") // warning is once-only
			if len(*logs) != 1 {
				t.Fatalf("warning repeated: %v", *logs)
			}
			if rl.br.isOpen() {
				t.Fatal("MAC rejection must not trip the breaker")
			}
		})
	}
}

func TestRedisMACWrongKey(t *testing.T) {
	rl, fs, _ := newMACLayer(testMACKey)
	rl.put("k", macMatches, time.Minute)
	rl2, fs2, _ := newMACLayer(strings.Repeat("z", 40))
	fs2.m = fs.m
	if _, ok := rl2.get("k"); ok {
		t.Fatal("wrong key accepted value")
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRedisNoKeyLegacyIdentical(t *testing.T) {
	rl, fs, _ := newMACLayer("")
	rl.put("k", macMatches, time.Minute)
	if got, want := fs.m["p:k"], mustJSON(t, macMatches); !bytes.Equal(got, want) {
		t.Fatalf("no-key value changed: %q", got)
	}
	if _, ok := rl.get("k"); !ok {
		t.Fatal("no-key round trip failed")
	}
	// A MACed value is not readable without a key (JSON decode fails => miss).
	rl2, fs2, _ := newMACLayer(testMACKey)
	rl2.put("k", macMatches, time.Minute)
	fs.m["p:k"] = fs2.m["p:k"]
	if _, ok := rl.get("k"); ok {
		t.Fatal("framed value decoded without key")
	}
}

func TestSealOpenHelpers(t *testing.T) {
	v := []byte("payload")
	if !bytes.Equal(sealRedisValue(nil, "k", v), v) {
		t.Fatal("nil key must not alter value")
	}
	if out, ok := openRedisValue(nil, "k", v); !ok || !bytes.Equal(out, v) {
		t.Fatal("nil key open must pass through")
	}
	k := []byte(testMACKey)
	if out, ok := openRedisValue(k, "k", sealRedisValue(k, "k", v)); !ok || !bytes.Equal(out, v) {
		t.Fatal("seal/open mismatch")
	}
	if _, ok := openRedisValue(k, "k2", sealRedisValue(k, "k", v)); ok {
		t.Fatal("redis key not bound")
	}
}

func TestValidateRedisMAC(t *testing.T) {
	for _, tc := range []struct {
		key string
		ok  bool
	}{
		{"", true},
		{strings.Repeat("a", 31), false},
		{strings.Repeat("a", 32), true},
		{strings.Repeat("a", 64), true},
	} {
		err := (&Config{RedisMACKey: tc.key}).ValidateRedisMAC()
		if (err == nil) != tc.ok {
			t.Errorf("len %d: err=%v want ok=%v", len(tc.key), err, tc.ok)
		}
		if err != nil && tc.key != "" && strings.Contains(err.Error(), tc.key) {
			t.Error("error leaks key")
		}
	}
}

func TestRedisMACKeyFromEnvAndFile(t *testing.T) {
	t.Setenv("MAILSTRIX_REDIS_MAC_KEY", testMACKey)
	if got := LoadConfig().RedisMACKey; got != testMACKey {
		t.Fatalf("env key = %q", got)
	}
	f := t.TempDir() + "/k"
	if err := os.WriteFile(f, []byte("  "+strings.Repeat("q", 33)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MAILSTRIX_REDIS_MAC_KEY_FILE", f)
	if got := LoadConfig().RedisMACKey; got != strings.Repeat("q", 33) {
		t.Fatalf("file key = %q", got)
	}
	t.Setenv("MAILSTRIX_REDIS_MAC_KEY", "")
	t.Setenv("MAILSTRIX_REDIS_MAC_KEY_FILE", "")
	if LoadConfig().RedisMACKey != "" {
		t.Fatal("unset key must be empty")
	}
}
