package mailstrix

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const icapIdentityBody = "inert identical ICAP body"

type icapIdentityEngine struct {
	*fakeEngine
	entered chan int
	release <-chan struct{}
}

func (e *icapIdentityEngine) Scan(body []byte, meta ScanMeta) ([]Match, error) {
	matches, err := e.fakeEngine.Scan(body, meta)
	if e.entered != nil {
		e.entered <- meta.Effort
		<-e.release
	}
	if err != nil {
		return matches, err
	}
	if meta.Effort == 4 {
		return []Match{{Rule: "ICAP_IDENTITY_EFFORT_4"}}, nil
	}
	return nil, nil
}

func icapIdentityServer(engine ScanEngine, effort int, auto bool) *Server {
	return NewServer(&Config{
		MaxConcurrent: 4, MaxInflight: 64, MaxBody: 4096,
		BackendTimeout: 5 * time.Second, ScanTimeout: 5 * time.Second,
		CacheTTL: time.Minute, CacheSize: 8,
		Effort: effort, EffortMax: 4, EffortAuto: auto,
	}, engine)
}

type icapIdentityReply struct {
	text string
	err  error
}

func icapIdentityRequest(s *Server, method, headers string) icapIdentityReply {
	request := icapRESPMODRequest("fixture", icapIdentityBody, true)
	if method == "REQMOD" {
		request = icapREQMODRequest("fixture", icapIdentityBody, true)
	}
	request = strings.Replace(request, "Encapsulated:", headers+"Encapsulated:", 1)
	var response bytes.Buffer
	err := s.handleICAPRequest(&response, bufio.NewReader(strings.NewReader(request)))
	return icapIdentityReply{response.String(), err}
}

func checkICAPIdentityReply(t *testing.T, reply icapIdentityReply, effort int) {
	t.Helper()
	if reply.err != nil {
		t.Fatal(reply.err)
	}
	want := "ICAP/1.0 204 No Modification"
	if effort == 4 {
		want = "ICAP/1.0 200 OK"
	}
	if !strings.HasPrefix(reply.text, want) || strings.Contains(reply.text, "ICAP_IDENTITY_EFFORT_4") != (effort == 4) {
		t.Fatalf("effort %d received an incompatible verdict: %q", effort, reply.text)
	}
}

// Set the atomic hysteresis history and actual admission pressure. No config
// mutation or new ICAP effort header is needed: both levels are reachable in
// the existing auto mode. At capacity64 two active requests still target4.
func icapIdentityPressure(s *Server, effort int) func() {
	fillers := 0
	if effort == 1 {
		fillers = cap(s.admit) - len(s.admit) - 1
		for range fillers {
			s.admit <- struct{}{}
		}
	}
	s.autoEffort.Store(int64(effort))
	return func() {
		for range fillers {
			<-s.admit
		}
	}
}

func TestICAPIdentityEffortCacheSeparation(t *testing.T) {
	for _, method := range []string{"REQMOD", "RESPMOD"} {
		for _, order := range [][]int{{1, 4, 1, 4}, {4, 1, 4, 1}} {
			t.Run(fmt.Sprintf("%s/%d-first", method, order[0]), func(t *testing.T) {
				engine := &icapIdentityEngine{fakeEngine: &fakeEngine{fp: "identity"}}
				s := icapIdentityServer(engine, 4, true)
				for _, effort := range order {
					release := icapIdentityPressure(s, effort)
					reply := icapIdentityRequest(s, method, "")
					release()
					checkICAPIdentityReply(t, reply, effort)
				}
				if got := engine.scans.Load(); got != 2 {
					t.Fatalf("different effective efforts need two scans, same effort must reuse: got %d", got)
				}
				if got := s.metrics.cacheHit.Load(); got != 2 {
					t.Fatalf("same-effort repeats must hit their own cached verdict: hits=%d", got)
				}
			})
		}
	}
}

func TestICAPIdentityDefaultsAndHeaders(t *testing.T) {
	for _, tc := range []struct{ configured, effective int }{{0, 4}, {-7, 1}, {1, 1}, {4, 4}, {99, 4}} {
		t.Run(fmt.Sprint(tc.configured), func(t *testing.T) {
			engine := &icapIdentityEngine{fakeEngine: &fakeEngine{fp: "identity"}}
			s := icapIdentityServer(engine, tc.configured, false)
			for _, raw := range []string{"", "0", "1", "4", "-1", "not-an-integer"} {
				headers := effortHeaderName + ": " + raw + "\r\n" + filenameHeader + ": !!!invalid-base64!!!\r\n"
				checkICAPIdentityReply(t, icapIdentityRequest(s, "RESPMOD", headers), tc.effective)
			}
			if got := engine.scans.Load(); got != 1 {
				t.Fatalf("unsupported ICAP metadata must not split equivalent effective defaults: scans=%d", got)
			}
			meta := engine.lastMeta.Load()
			if meta.Effort != tc.effective || meta.Filename != "" || meta.Extension != "" || meta.FileType != "" || len(meta.PWCandidates) != 0 || meta.RawKey != streamDedupKey([]byte(icapIdentityBody)) {
				t.Fatalf("ICAP must key the normalized metadata it actually scans: %+v", meta)
			}
		})
	}
	engine := &icapIdentityEngine{fakeEngine: &fakeEngine{fp: "identity"}}
	s := icapIdentityServer(engine, 4, true)
	for _, history := range []int64{0, 4, -1, 4} {
		s.autoEffort.Store(history)
		checkICAPIdentityReply(t, icapIdentityRequest(s, "RESPMOD", ""), 4)
	}
	if got := engine.scans.Load(); got != 1 {
		t.Fatalf("equivalent normalized auto defaults must reuse: scans=%d", got)
	}
	reply := icapIdentityRequest(s, "RESPMOD", "malformed metadata without a colon\r\n")
	if reply.err == nil || !strings.HasPrefix(reply.text, "ICAP/1.0 400") || engine.scans.Load() != 1 {
		t.Fatalf("malformed ICAP headers must fail before lookup/scan: %+v", reply)
	}
}

func icapIdentityJoiners(s *Server) int {
	s.flights.mu.Lock()
	defer s.flights.mu.Unlock()
	n := 0
	for _, flight := range s.flights.m {
		n += flight.joiners
	}
	return n
}

func TestICAPIdentityConcurrentEfforts(t *testing.T) {
	for _, different := range []bool{false, true} {
		t.Run(fmt.Sprintf("different=%t", different), func(t *testing.T) {
			release := make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			engine := &icapIdentityEngine{fakeEngine: &fakeEngine{fp: "identity"}, entered: make(chan int, 2), release: release}
			s := icapIdentityServer(engine, 4, different)
			firstEffort := 4
			if different {
				firstEffort = 1
			}
			replies := make([]chan icapIdentityReply, 0, 2)
			t.Cleanup(func() {
				unblock()
				for _, reply := range replies {
					select {
					case <-reply:
					case <-time.After(10 * time.Second):
						t.Error("ICAP identity request did not drain")
					}
				}
			})
			start := func() chan icapIdentityReply {
				done := make(chan icapIdentityReply, 1)
				replies = append(replies, done)
				go func() { done <- icapIdentityRequest(s, "RESPMOD", "") }()
				return done
			}
			clearPressure := icapIdentityPressure(s, firstEffort)
			first := start()
			select {
			case got := <-engine.entered:
				if got != firstEffort {
					t.Fatalf("first scan effort=%d, want%d", got, firstEffort)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("first scan never entered")
			}
			clearPressure()
			s.autoEffort.Store(4)
			second := start()
			deadline := time.Now().Add(10 * time.Second)
			for {
				joiners := icapIdentityJoiners(s)
				select {
				case got := <-engine.entered:
					if !different || got != 4 {
						t.Fatalf("unexpected second native scan: different=%t effort=%d", different, got)
					}
					goto observed
				default:
				}
				if joiners > 0 {
					if different {
						t.Fatal("different effective efforts incorrectly coalesced")
					}
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("neither a second scan nor a joined flight was observed")
				}
				time.Sleep(time.Millisecond)
			}
		observed:
			unblock()
			firstReply, secondReply := <-first, <-second
			replies = nil // both requests drained before assertions can stop the test
			checkICAPIdentityReply(t, firstReply, firstEffort)
			checkICAPIdentityReply(t, secondReply, 4)
			wantScans := int64(1)
			if different {
				wantScans = 2
			}
			if got := engine.scans.Load(); got != wantScans {
				t.Fatalf("scans=%d want%d", got, wantScans)
			}
		})
	}
}

func TestICAPIdentityIncompleteNeverCached(t *testing.T) {
	engine := &fakeEngine{fp: "identity", matches: []Match{scanIncompleteMatch()}, err: ErrScanIncomplete}
	s := icapIdentityServer(engine, 4, false)
	for range 2 {
		reply := icapIdentityRequest(s, "RESPMOD", "")
		if reply.err == nil || !strings.HasPrefix(reply.text, "ICAP/1.0 500") {
			t.Fatalf("incomplete scan must not become a clean/cacheable verdict: %+v", reply)
		}
	}
	if got := engine.scans.Load(); got != 2 {
		t.Fatalf("incomplete result reused: scans=%d", got)
	}
}

func TestICAPIdentityProtocolNamespace(t *testing.T) {
	for _, method := range []string{"REQMOD", "RESPMOD"} {
		for _, filename := range []string{"icap", "icap:"} {
			for _, httpFirst := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/http-first=%t", method, filename, httpFirst), func(t *testing.T) {
					engine := &icapIdentityEngine{fakeEngine: &fakeEngine{fp: "identity"}}
					s := icapIdentityServer(engine, 4, false)
					httpRequest := func() {
						req := httptest.NewRequest("POST", "/scan", strings.NewReader(icapIdentityBody))
						req.Header.Set("Content-Length", fmt.Sprint(len(icapIdentityBody)))
						req.Header.Set(filenameHeader, base64.StdEncoding.EncodeToString([]byte(filename)))
						response := httptest.NewRecorder()
						s.handleScan(response, req)
						if response.Code != 200 {
							t.Fatalf("HTTP control status=%d: %s", response.Code, response.Body.String())
						}
					}
					icapRequest := func() { checkICAPIdentityReply(t, icapIdentityRequest(s, method, ""), 4) }
					first, second := icapRequest, httpRequest
					wantLastName := filename
					if httpFirst {
						first, second = httpRequest, icapRequest
						wantLastName = ""
					}
					first()
					second()
					if engine.scans.Load() != 2 || engine.lastMeta.Load().Filename != wantLastName {
						t.Fatalf("ICAP namespace collided with HTTP filename: scans=%d meta=%+v", engine.scans.Load(), engine.lastMeta.Load())
					}
					first()
					second()
					if engine.scans.Load() != 2 || s.metrics.cacheHit.Load() != 2 {
						t.Fatalf("same-protocol repeats must reuse: scans=%d hits=%d", engine.scans.Load(), s.metrics.cacheHit.Load())
					}
				})
			}
		}
	}
}
