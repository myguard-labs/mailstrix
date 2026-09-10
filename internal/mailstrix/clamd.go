package mailstrix

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	clamdCommandTimeout = 5 * time.Second
	clamdBodyTimeout    = 30 * time.Second
	clamdWriteTimeout   = time.Second
	clamdScanSlack      = 2 * time.Second
	clamdCommandLimit   = 64
	clamdChunkLimit     = 1 << 20
)

// ClamdService owns opt-in listeners and their native scan lifetimes.
// State is running -> stopping -> done; mu serializes stopping, listener
// admission and the connection registry. Shutdown never resumes a service.
// Accept loops keep wg nonzero while handlers can be added; a handler keeps
// it nonzero while transferring body/admission/CPU ownership to a scan worker.
// Workers release those resources only when dispatch actually returns, even
// after their connection times out. done therefore certifies engine safety.
// Every wire reply is terminal: no handler parses a second request.
type ClamdService struct {
	s         *Server
	mu        sync.Mutex
	stopping  bool
	listeners []net.Listener
	conns     map[net.Conn]struct{}
	slots     chan struct{}
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	done      chan struct{}
	forced    chan struct{}
	forceOnce sync.Once
	cleanup   func()
}

// StartClamd binds all configured endpoints before serving any requests.
// A nil service means both endpoints are disabled. Startup errors are fatal
// to this adapter; an already occupied Unix path is never replaced.
func (s *Server) StartClamd() (*ClamdService, error) {
	if s.cfg.ClamdTCPAddr == "" && s.cfg.ClamdUnixPath == "" {
		return nil, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	c := &ClamdService{s: s, ctx: ctx, cancel: cancel, done: make(chan struct{}), forced: make(chan struct{}),
		conns: make(map[net.Conn]struct{}), slots: make(chan struct{}, s.cfg.ClamdMaxConns)}
	fail := func(err error) (*ClamdService, error) {
		cancel()
		for _, ln := range c.listeners {
			_ = ln.Close()
		} // cleanup after startup failure
		return nil, err
	}
	if addr := s.cfg.ClamdTCPAddr; addr != "" {
		host, port, err := net.SplitHostPort(addr)
		if err != nil || host == "" || port == "" {
			return fail(errors.New("clamd TCP requires explicit host:port"))
		}
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fail(fmt.Errorf("clamd TCP listen: %w", err))
		}
		c.listeners = append(c.listeners, ln)
	}
	if path := s.cfg.ClamdUnixPath; path != "" {
		ln, cleanup, err := listenClamdUnix(path)
		if err != nil {
			return fail(fmt.Errorf("clamd Unix listen: %w", err))
		}
		c.listeners = append(c.listeners, ln)
		c.cleanup = cleanup
	}
	c.wg.Add(len(c.listeners))
	for _, ln := range c.listeners {
		go c.accept(ln)
	}
	go func() {
		c.wg.Wait()
		if c.cleanup != nil {
			c.cleanup()
		}
		close(c.done)
	}()
	return c, nil
}

// listenClamdUnix publishes an already private socket without a process-wide
// umask change or a bind/chmod exposure window. Hard-link publication fails if
// path exists. The parent must support Unix sockets and filesystem hard links.
func listenClamdUnix(path string) (net.Listener, func(), error) {
	if !filepath.IsAbs(path) {
		return nil, nil, errors.New("clamd Unix path must be absolute")
	}
	const pathCapacity = len(syscall.RawSockaddrUnix{}.Path) - 1
	if len(path) > pathCapacity || strings.IndexByte(path, 0) >= 0 {
		return nil, nil, errors.New("clamd Unix path exceeds socket address capacity or contains NUL")
	}
	dir, err := os.MkdirTemp(filepath.Dir(path), ".clamd-")
	if err != nil {
		return nil, nil, err
	}
	tmp := filepath.Join(dir, "s")
	var stage *os.File
	defer func() {
		_ = os.Remove(tmp)
		_ = os.Remove(dir)
		if stage != nil {
			_ = stage.Close()
		}
	}() // private staging paths only; hold the directory FD through cleanup
	bindPath := tmp
	if len(bindPath) > pathCapacity {
		if runtime.GOOS != "linux" {
			return nil, nil, errors.New("clamd Unix staging path exceeds socket address capacity")
		}
		stage, err = os.Open(dir)
		if err != nil {
			return nil, nil, err
		}
		// Linux resolves this short alias to the same private staging directory.
		// Long final paths therefore do not need room for our staging suffix.
		bindPath = fmt.Sprintf("/proc/self/fd/%d/s", stage.Fd())
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: bindPath, Net: "unix"})
	if err != nil {
		return nil, nil, fmt.Errorf("bind private clamd socket at %q: %w", bindPath, err)
	}
	ln.SetUnlinkOnClose(false)
	if err = os.Chmod(tmp, 0600); err != nil {
		_ = ln.Close()
		return nil, nil, err
	}
	identity, err := os.Lstat(tmp)
	if err != nil {
		_ = ln.Close()
		return nil, nil, err
	}
	if err = os.Link(tmp, path); err != nil {
		_ = ln.Close()
		return nil, nil, err
	}
	cleanup := func() {
		// The operator owns the parent directory; preserve a replaced path.
		if current, err := os.Lstat(path); err == nil && os.SameFile(identity, current) {
			_ = os.Remove(path)
		}
	}
	return ln, cleanup, nil
}

func (c *ClamdService) accept(ln net.Listener) {
	defer c.wg.Done()
	var retryDelay time.Duration
	for {
		conn, err := ln.Accept()
		acceptedAt := time.Now()
		if err != nil {
			c.mu.Lock()
			stopping := c.stopping
			c.mu.Unlock()
			if !stopping {
				if errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE) ||
					errors.Is(err, syscall.ENOBUFS) || errors.Is(err, syscall.ENOMEM) {
					if retryDelay == 0 {
						retryDelay = 5 * time.Millisecond
					} else {
						retryDelay = min(retryDelay*2, time.Second)
					}
					timer := time.NewTimer(retryDelay)
					select {
					case <-c.ctx.Done():
						timer.Stop()
						return
					case <-timer.C:
						continue
					}
				}
				c.s.metrics.clamdAcceptErrors.Add(1)
				c.s.errf("clamd accept: %v", err)
				c.stop()
			}
			return
		}
		retryDelay = 0
		c.mu.Lock()
		if c.stopping {
			c.mu.Unlock()
			_ = conn.Close()
			return
		}
		select {
		case c.slots <- struct{}{}:
			c.conns[conn] = struct{}{}
			c.wg.Add(1)
			go c.serve(conn, acceptedAt)
		default:
			c.s.metrics.busy.Add(1)
			_ = conn.Close() // no refusal work beyond the connection cap
		}
		c.mu.Unlock()
	}
}

func (c *ClamdService) stop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stopping {
		return
	}
	c.stopping = true
	c.cancel()
	for _, ln := range c.listeners {
		_ = ln.Close()
	}
	for conn := range c.conns {
		_ = conn.SetReadDeadline(time.Now())
	}
}

// Shutdown cancels accept/upload/admission work and drains native scans.
// A timeout closes transports but leaves scan ownership intact. Callers must
// not close the engine until a subsequent Shutdown returns nil.
func (c *ClamdService) Shutdown(ctx context.Context) error {
	if c == nil {
		return nil
	}
	c.stop()
	select {
	case <-c.done:
		return nil
	default:
	}
	select {
	case <-c.done:
		return nil
	case <-ctx.Done():
		select {
		case <-c.done:
			return nil
		default:
		}
		c.forceOnce.Do(func() { close(c.forced) })
		c.mu.Lock()
		for conn := range c.conns {
			_ = conn.Close()
		}
		c.mu.Unlock()
		return fmt.Errorf("clamd drain: %w", ctx.Err())
	}
}

// readDeadline cannot restore a future deadline after Shutdown canceled reads.
func (c *ClamdService) readDeadline(conn net.Conn, at time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stopping {
		return context.Canceled
	}
	return conn.SetReadDeadline(at)
}

func (c *ClamdService) serve(conn net.Conn, acceptedAt time.Time) {
	defer c.wg.Done()
	defer func() {
		_ = conn.Close()
		c.mu.Lock()
		delete(c.conns, conn)
		c.mu.Unlock()
		<-c.slots
	}()
	if err := c.readDeadline(conn, acceptedAt.Add(clamdCommandTimeout)); err != nil {
		return
	}
	br := bufio.NewReaderSize(conn, 4096)
	cmd, term, reply := readClamdCommand(br)
	if reply != "" {
		c.reply(conn, reply, term)
		return
	}
	switch cmd {
	case "PING":
		c.reply(conn, "PONG", term)
	case "VERSION":
		c.reply(conn, "Mailstrix "+clamdVersion(c.s.cfg.Version), term)
	case "VERSIONCOMMANDS":
		c.reply(conn, "Mailstrix "+clamdVersion(c.s.cfg.Version)+" COMMANDS: PING VERSION VERSIONCOMMANDS INSTREAM", term)
	case "INSTREAM":
		c.stream(conn, br, term)
	default:
		c.reply(conn, "UNKNOWN COMMAND", term)
	}
}

func readClamdCommand(br *bufio.Reader) (command string, term byte, reply string) {
	first, err := br.ReadByte()
	if err != nil {
		return "", '\n', "COMMAND READ ERROR"
	}
	term = '\n'
	if first == 'z' {
		term = 0
	} else if first != 'n' {
		return "", term, "UNKNOWN COMMAND"
	}
	// Reserve one byte each for the framing prefix and terminating delimiter.
	var buf [clamdCommandLimit - 2]byte
	for i := 0; ; i++ {
		b, err := br.ReadByte()
		if err != nil {
			return "", term, "COMMAND READ ERROR"
		}
		if b == term {
			return string(buf[:i]), term, ""
		}
		if i == len(buf) || b < 32 || b > 126 {
			return "", term, "COMMAND PARSE ERROR"
		}
		buf[i] = b
	}
}

// readClamdStream stores at most limit bytes, with geometric growth explicitly
// capped at limit. A resize temporarily retains old+new capacity (at most 2*limit);
// there is no final copy. The caller holds shared admission throughout.
func readClamdStream(r io.Reader, limit int64) ([]byte, string) {
	var body []byte
	var header [4]byte
	for {
		if _, err := io.ReadFull(r, header[:]); err != nil {
			return nil, "stream: truncated stream ERROR"
		}
		n := int64(binary.BigEndian.Uint32(header[:]))
		if n == 0 {
			return body, ""
		}
		if n > limit-int64(len(body)) {
			return nil, "INSTREAM size limit exceeded. ERROR"
		}
		if n > clamdChunkLimit {
			return nil, "stream: chunk size limit exceeded ERROR"
		}
		end := len(body) + int(n) // n bounded by limit <= 1 GiB before conversion
		if end > cap(body) {
			capacity := min(limit, max(int64(end), 4096, int64(cap(body))*2))
			grown := make([]byte, len(body), int(capacity))
			copy(grown, body)
			body = grown
		}
		start := len(body)
		body = body[:end]
		if _, err := io.ReadFull(r, body[start:]); err != nil {
			return nil, "stream: truncated stream ERROR"
		}
	}
}

func (c *ClamdService) stream(conn net.Conn, br *bufio.Reader, term byte) {
	if err := c.readDeadline(conn, time.Now().Add(clamdBodyTimeout)); err != nil {
		return
	}
	if c.ctx.Err() != nil || !c.s.acquireOn(c.ctx, c.s.admit) {
		if c.ctx.Err() == nil {
			c.s.metrics.busy.Add(1)
		}
		c.reply(conn, "stream: busy ERROR", term)
		return
	}
	owned := true
	defer func() {
		if owned {
			<-c.s.admit
		}
	}()
	body, reply := readClamdStream(br, min(c.s.cfg.MaxBody, int64(maxBodyHardLimit)))
	if reply != "" {
		c.reply(conn, reply, term)
		return
	}
	if c.ctx.Err() != nil || !c.s.acquireOn(c.ctx, c.s.sem) {
		if c.ctx.Err() == nil {
			c.s.metrics.busy.Add(1)
		}
		c.reply(conn, "stream: busy ERROR", term)
		return
	}
	if c.ctx.Err() != nil {
		<-c.s.sem
		return
	}
	result := make(chan string, 1)
	c.wg.Add(1)
	owned = false // native worker now owns the body and both gates
	go func() {
		defer c.wg.Done()
		defer func() { <-c.s.sem; <-c.s.admit }()
		c.s.metrics.scans.Add(1)
		meta := ScanMeta{RawKey: streamDedupKey(body),
			Effort: ResolveEffortLevel(0, false, c.s.autoEnvDefault(true), c.s.cfg.EffortMax)}
		matches, err := c.s.dispatch(body, meta)
		if err != nil {
			c.s.metrics.errors.Add(1)
			c.s.errf("clamd scan failed: %q", err)
			result <- "stream: scan failed ERROR"
		} else {
			if len(matches) > 0 {
				c.s.metrics.matches.Add(1)
				if c.s.cfg.Verbose {
					c.s.vlogf("clamd %dB matches=%q", len(body), ruleNames(matches))
				}
			}
			actionable := false
			for _, match := range matches {
				if !matchIsLogOnly(match) {
					actionable = true
					break
				}
			}
			if actionable {
				result <- "stream: Mailstrix.Match FOUND"
			} else {
				result <- "stream: OK"
			}
		}
	}()
	timer := time.NewTimer(c.s.cfg.ScanTimeout + clamdScanSlack)
	defer timer.Stop()
	select {
	case reply = <-result:
	case <-timer.C:
		reply = "stream: scan timed out ERROR"
	case <-c.forced:
		return
	}
	c.reply(conn, reply, term)
}

func (c *ClamdService) reply(conn net.Conn, payload string, term byte) {
	// All payloads are fixed except the bounded sanitized build version.
	if len(payload) > 255 {
		payload = "stream: internal error ERROR"
	}
	// Native failures are counted by their worker even after transport timeout;
	// capacity refusals belong to busy, not scan/read/length errors.
	if strings.HasSuffix(payload, "ERROR") && payload != "stream: scan failed ERROR" && payload != "stream: busy ERROR" {
		c.s.metrics.errors.Add(1)
	}
	if err := conn.SetWriteDeadline(time.Now().Add(clamdWriteTimeout)); err != nil {
		return
	}
	if _, err := io.WriteString(conn, payload+string(term)); err != nil {
		c.s.metrics.canceled.Add(1)
	}
}

func clamdVersion(version string) string {
	if version == "" {
		return "unknown"
	}
	b := []byte(version[:min(len(version), 64)])
	for i, v := range b {
		switch {
		case v >= 'a' && v <= 'z', v >= 'A' && v <= 'Z', v >= '0' && v <= '9', strings.ContainsRune("._+-", rune(v)):
		default:
			b[i] = '_'
		}
	}
	return string(b)
}
