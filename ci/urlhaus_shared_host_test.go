package ci

import (
	"bufio"
	"bytes"
	"context"
	"flag"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/myguard-labs/mailstrix/internal/urlhaus"
)

func TestURLhausURLDerivedSharedHosts(t *testing.T) {
	if os.Getenv("MAILSTRIX_URLHAUS_TEST_CHILD") != "1" {
		runURLhausSharedHostsChild(t)
		return
	}
	if !strings.HasPrefix(os.Getenv("HTTPS_PROXY"), "http://127.0.0.1:") {
		t.Fatal("fixture child requires a loopback HTTPS proxy")
	}
	dir := t.TempDir()
	// The two shared-host URLs are URLhaus csv_online rows 3928575 and 3928281
	// from the 2026-10-04 snapshot; the remaining rows are inert test fixtures.
	const csv = `# id,dateadded,url,url_status
"3928575","2026-10-04 14:10:39","https://github.com/niehgns/yo/raw/refs/heads/main/corzclient-1.21.11.jar","online"
"3928281","2026-10-04 06:58:19","https://raw.githubusercontent.com/snipezcyka091111/Krypton-updated-crack/refs/heads/main/Krypton_crack-1.21.11.jar","online"
"3","2026-10-04 00:00:00","https://evil.example/payload","online"
"4","2026-10-04 00:00:00","https://github.com.evil.test/payload","online"
"5","2026-10-04 00:00:00","not-a-url","online"
`
	if err := os.WriteFile(filepath.Join(dir, "urlhaus.csv"), []byte(csv), 0o600); err != nil {
		t.Fatal(err)
	}
	c := urlhaus.New("test-key", time.Hour, dir, func(string, ...any) {})
	if c == nil {
		t.Fatal("checker disabled despite a key")
	}
	t.Cleanup(c.Close)
	// The parent proxy answers the immediate fetch with 502; wait for that
	// failure before checking the warm-start snapshot or exiting the child.
	deadline := time.Now().Add(5 * time.Second)
	for c.Metrics().RefreshFailures == 0 {
		if time.Now().After(deadline) {
			t.Fatal("background feed fetch did not finish through local proxy")
		}
		time.Sleep(time.Millisecond)
	}
	if metrics := c.Metrics(); metrics.FeedURLs != 4 || metrics.FeedHosts != 2 {
		t.Fatalf("malformed feed row was not skipped: urls=%d hosts=%d", metrics.FeedURLs, metrics.FeedHosts)
	}

	for _, tc := range []struct {
		name, input, url, rule string
		host                   bool
	}{
		{"github exact IOC", "https://github.com/niehgns/yo/raw/refs/heads/main/corzclient-1.21.11.jar", "https://github.com/niehgns/yo/raw/refs/heads/main/corzclient-1.21.11.jar", "URLHAUS_MALWARE_URL", false},
		{"raw exact IOC", "https://raw.githubusercontent.com/snipezcyka091111/Krypton-updated-crack/refs/heads/main/Krypton_crack-1.21.11.jar", "https://raw.githubusercontent.com/snipezcyka091111/Krypton-updated-crack/refs/heads/main/Krypton_crack-1.21.11.jar", "URLHAUS_MALWARE_URL", false},
		{"github unrelated", "https://github.com/golang/go", "", "", false},
		{"raw unrelated", "https://raw.githubusercontent.com/golang/go/master/README.md", "", "", false},
		{"ordinary host fallback", "https://evil.example/other", "evil.example", "URLHAUS_MALWARE_HOST", true},
		{"lookalike host fallback", "https://github.com.evil.test/other", "github.com.evil.test", "URLHAUS_MALWARE_HOST", true},
		{"malformed URL on listed host", "http://evil.example/%zz", "", "", false},
		{"absent URL", "no URL here", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hits := c.Check([]byte(tc.input), 64)
			if tc.url == "" {
				if len(hits) != 0 {
					t.Fatalf("unexpected hits: %+v", hits)
				}
				return
			}
			if len(hits) != 1 || hits[0].URL != tc.url || hits[0].Host != tc.host || hits[0].Rule() != tc.rule {
				t.Fatalf("hits=%+v, want URL=%q host=%t rule=%q", hits, tc.url, tc.host, tc.rule)
			}
		})
	}
	budgetInput := []byte("https://github.com/golang/go https://evil.example/payload")
	if hits := c.Check(budgetInput, 1); len(hits) != 0 {
		t.Fatalf("URL budget bypassed: %+v", hits)
	}
	if hits := c.Check(budgetInput, 2); len(hits) != 1 || hits[0].URL != "https://evil.example/payload" || hits[0].Host || hits[0].Rule() != "URLHAUS_MALWARE_URL" {
		t.Fatalf("second candidate missed at URL budget boundary: %+v", hits)
	}
}

func runURLhausSharedHostsChild(t *testing.T) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := listener.Close(); err != nil {
			t.Errorf("close local proxy listener: %v", err)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	proxy := "http://" + listener.Addr().String()
	selector := "^TestURLhausURLDerivedSharedHosts$"
	if runFlag := flag.Lookup("test.run"); runFlag != nil {
		if _, subtests, ok := strings.Cut(runFlag.Value.String(), "/"); ok {
			selector += "/" + subtests
		}
	}
	t.Logf("fixture child selector: %s", selector)
	// #nosec G204 G702 -- os.Args[0] is this test binary; the variable flag is only its test.run selector, with no shell.
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command -- same test binary and selector; no untrusted executable.
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run="+selector, "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(),
		"MAILSTRIX_URLHAUS_TEST_CHILD=1", "HTTPS_PROXY="+proxy, "https_proxy="+proxy,
		"NO_PROXY=example.invalid", "no_proxy=example.invalid")
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})
	if err := listener.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	conn, acceptErr := listener.Accept()
	if acceptErr != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("feed fetch did not reach local proxy: %v; child: %s", acceptErr, output.String())
	}
	requestLine := answerURLhausProxy(t, conn)
	childErr := cmd.Wait()
	if !strings.HasPrefix(requestLine, "CONNECT urlhaus.abuse.ch:443 HTTP/1.1") {
		t.Fatalf("unexpected local proxy request %q; child: %s", requestLine, output.String())
	}
	if childErr != nil {
		t.Fatalf("URLhaus fixture child failed: %v; output: %s", childErr, output.String())
	}
	t.Logf("blocked local proxy request: %s", strings.TrimSpace(requestLine))
}

func answerURLhausProxy(t *testing.T, conn net.Conn) string {
	t.Helper()
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		if closeErr := conn.Close(); closeErr != nil {
			t.Errorf("close local proxy connection after deadline failure: %v", closeErr)
		}
		t.Fatal(err)
	}
	requestLine, readErr := bufio.NewReader(conn).ReadString('\n')
	response := []byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
	written, writeErr := conn.Write(response)
	if writeErr == nil && written != len(response) {
		writeErr = io.ErrShortWrite
	}
	closeErr := conn.Close()
	if readErr != nil || writeErr != nil || closeErr != nil {
		t.Fatalf("local proxy I/O failed (read=%v write=%v close=%v)", readErr, writeErr, closeErr)
	}
	return requestLine
}
