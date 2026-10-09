package mailstrix

import (
	"bufio"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeRedis speaks enough RESP2 for go-redis GET/SET and counts SETs.
type fakeRedis struct {
	addr string
	sets atomic.Int64
	gets atomic.Int64
	val  string
}

func startFakeRedis(t *testing.T, val string) *fakeRedis {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	f := &fakeRedis{addr: ln.Addr().String(), val: val}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f
}

func (f *fakeRedis) serve(c net.Conn) {
	defer func() { _ = c.Close() }()
	r := bufio.NewReader(c)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		n, _ := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "*")))
		var args []string
		for i := 0; i < n; i++ {
			if _, err := r.ReadString('\n'); err != nil { // $len
				return
			}
			a, err := r.ReadString('\n')
			if err != nil {
				return
			}
			args = append(args, strings.TrimSpace(a))
		}
		if len(args) == 0 {
			return
		}
		switch strings.ToUpper(args[0]) {
		case "HELLO":
			_, _ = fmt.Fprint(c, "-ERR unknown command\r\n")
		case "GET":
			f.gets.Add(1)
			_, _ = fmt.Fprintf(c, "$%d\r\n%s\r\n", len(f.val), f.val)
		case "SET":
			f.sets.Add(1)
			_, _ = fmt.Fprint(c, "+OK\r\n")
		default:
			_, _ = fmt.Fprint(c, "+OK\r\n")
		}
	}
}

// TestRedisHitDoesNotWriteBack (PERF-56): an L2 hit is promoted into L1 only;
// a Put still writes through to Redis (control).
func TestRedisHitDoesNotWriteBack(t *testing.T) {
	f := startFakeRedis(t, `[{"rule":"R"}]`)
	c := NewCache(&Config{CacheTTL: time.Minute, CacheSize: 8, RedisURL: "redis://" + f.addr, RedisPrefix: "t:"}, func(string, ...any) {})
	m, ok := c.Get("k")
	if !ok || len(m) != 1 || m[0].Rule != "R" {
		t.Fatalf("L2 hit = %v, %v", m, ok)
	}
	if f.sets.Load() != 0 {
		t.Fatalf("L2 hit wrote back %d SETs", f.sets.Load())
	}
	if m, ok := c.Get("k"); !ok || len(m) != 1 || f.gets.Load() != 1 {
		t.Fatalf("second Get not served from L1: %v %v gets=%d", m, ok, f.gets.Load())
	}
	c.Put("other", []Match{{Rule: "X"}})
	if f.sets.Load() != 1 {
		t.Fatalf("Put did not write through: %d SETs", f.sets.Load())
	}
}

// TestMetaString (PERF-65): typed meta values render as before.
func TestMetaString(t *testing.T) {
	for v, want := range map[any]string{
		"s": "s", 42: "42", int64(-7): "-7", int32(3): "3", true: "true", 1.5: "1.5",
	} {
		if got := metaString(v); got != want || got != fmt.Sprintf("%v", v) {
			t.Errorf("metaString(%#v) = %q, want %q", v, got, want)
		}
	}
}
