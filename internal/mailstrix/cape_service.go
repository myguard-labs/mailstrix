package mailstrix

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

type capeFactory func(context.Context, *capeDaemonConfig, capeResolver, func(context.Context, string, io.Reader) (string, error)) (*capeRuntime, error)
type capeServiceDeps struct {
	resolve capeResolver
	build   capeFactory
	listen  func(string, string) (net.Listener, error)
}

const capeReadHeaderTimeout = 10 * time.Second

type capeAcceptListener struct {
	net.Listener
	slots   chan struct{}
	mu      sync.Mutex
	conns   map[net.Conn]struct{}
	preHTTP map[net.Conn]struct{}
	closing bool
}

type capeAcceptConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *capeAcceptConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

func newCAPEAcceptListener(listener net.Listener, limit int) *capeAcceptListener {
	return &capeAcceptListener{Listener: listener, slots: make(chan struct{}, limit), conns: make(map[net.Conn]struct{}, limit), preHTTP: make(map[net.Conn]struct{}, limit)}
}

func (l *capeAcceptListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		l.mu.Lock()
		if l.closing {
			l.mu.Unlock()
			_ = conn.Close()
			return nil, net.ErrClosed
		}
		select {
		case l.slots <- struct{}{}:
			wrapped := &capeAcceptConn{Conn: conn}
			wrapped.release = func() { l.release(wrapped) }
			l.conns[wrapped] = struct{}{}
			l.preHTTP[wrapped] = struct{}{}
			l.mu.Unlock()
			return wrapped, nil
		default:
			l.mu.Unlock()
			_ = conn.Close()
		}
	}
}

func (l *capeAcceptListener) release(conn net.Conn) {
	l.mu.Lock()
	if _, ok := l.conns[conn]; ok {
		delete(l.conns, conn)
		delete(l.preHTTP, conn)
		<-l.slots
	}
	l.mu.Unlock()
}

func (l *capeAcceptListener) promoted(conn net.Conn) {
	if tlsConn, ok := conn.(*tls.Conn); ok {
		conn = tlsConn.NetConn()
	}
	l.mu.Lock()
	delete(l.preHTTP, conn)
	l.mu.Unlock()
}

func (l *capeAcceptListener) closePreHTTP() {
	l.mu.Lock()
	l.closing = true
	conns := make([]net.Conn, 0, len(l.preHTTP))
	for conn := range l.preHTTP {
		conns = append(conns, conn)
	}
	l.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
}

// CAPEService owns only the opt-in TLS listener and detonation runtime. A failed
// drain means native scanning can remain live: the daemon must not close its
// scanner. The background owner retains resources until those calls finish.
type CAPEService struct {
	http                             *http.Server
	listener                         net.Listener
	accepts                          *capeAcceptListener
	runtime                          *capeRuntime
	cancelHTTP, cancelScheduler      context.CancelFunc
	httpDone, schedulerDone, stopped chan struct{}
	stopOnce                         sync.Once
	mu                               sync.Mutex
	stopping                         bool
	handlers                         sync.WaitGroup
	available                        atomic.Bool
	schedulerErr, closeErr           error // published through schedulerDone / stopped
}

// StartCAPE starts the separate HTTPS API only when explicitly configured.
// ErrCAPEConfig is fatal configuration; ErrCAPEUnavailable is operational and
// must not disable static scanning. A nonnil service may still expose 503.
func (s *Server) StartCAPE() (*CAPEService, error) {
	if s.cfg.capeConfig == nil {
		if err := s.cfg.ValidateCAPE(); err != nil {
			return nil, err
		}
	}
	if s.cfg.capeConfig == nil {
		return nil, nil
	}
	return s.startCAPE(s.cfg.capeConfig, capeServiceDeps{resolve: s.cfg.capeConfig.resolver(), build: buildCAPERuntime, listen: net.Listen})
}

func (s *Server) startCAPE(c *capeDaemonConfig, deps capeServiceDeps) (*CAPEService, error) {
	if c.validate() != nil || deps.resolve == nil || deps.build == nil || deps.listen == nil {
		return nil, ErrCAPEConfig
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cert, err := deps.resolve(ctx, c.TLSCertRef)
	if err != nil {
		return nil, ErrCAPEUnavailable
	}
	key, err := deps.resolve(ctx, c.TLSKeyRef)
	if err != nil {
		return nil, ErrCAPEUnavailable
	}
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return nil, ErrCAPEConfig
	}
	runtime, buildErr := deps.build(ctx, c, deps.resolve, s.capeStaticScan)
	if errors.Is(buildErr, ErrCAPEConfig) {
		return nil, ErrCAPEConfig
	}
	if runtime != nil && (runtime.handler == nil || runtime.run == nil || runtime.close == nil) {
		if runtime.close != nil {
			// The malformed runtime cannot be served; closing is best-effort cleanup.
			_ = runtime.close()
		}
		return nil, ErrCAPEConfig
	}
	if buildErr == nil && runtime == nil {
		return nil, ErrCAPEConfig
	}
	listener, err := deps.listen("tcp", c.Listen)
	if err != nil {
		if runtime != nil {
			_ = runtime.close()
		}
		return nil, ErrCAPEUnavailable
	}
	httpCtx, cancelHTTP := context.WithCancel(context.Background())
	schedulerCtx, cancelScheduler := context.WithCancel(context.Background())
	service := &CAPEService{runtime: runtime, cancelHTTP: cancelHTTP, cancelScheduler: cancelScheduler, httpDone: make(chan struct{}), schedulerDone: make(chan struct{}), stopped: make(chan struct{})}
	service.accepts = newCAPEAcceptListener(listener, c.AcceptLimit)
	service.listener = tls.NewListener(service.accepts, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}})
	service.http = &http.Server{Handler: service, ReadHeaderTimeout: capeReadHeaderTimeout, ReadTimeout: 35 * time.Second, WriteTimeout: 40 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10, BaseContext: func(net.Listener) context.Context { return httpCtx }, ConnState: func(conn net.Conn, state http.ConnState) {
		if state == http.StateActive || state == http.StateHijacked || state == http.StateClosed {
			service.accepts.promoted(conn)
		}
	}}
	service.available.Store(buildErr == nil)
	if buildErr == nil {
		go func() {
			defer close(service.schedulerDone)
			service.schedulerErr = runtime.run(schedulerCtx)
			service.available.Store(false)
		}()
	} else {
		close(service.schedulerDone)
	}
	go func() {
		defer close(service.httpDone)
		if service.http.Serve(service.listener) != nil {
			service.available.Store(false)
		}
	}()
	if buildErr != nil {
		return service, ErrCAPEUnavailable
	}
	return service, nil
}

func (s *CAPEService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	if s.stopping || !s.available.Load() {
		s.mu.Unlock()
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Retry-After", "5")
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "unavailable"})
		return
	}
	s.handlers.Add(1)
	s.mu.Unlock()
	defer s.handlers.Done()
	s.runtime.handler.ServeHTTP(w, r)
}

// Shutdown stops new requests and cancels ingress, then joins HTTP/classifiers,
// scheduler and store cleanup in order. Caller timeout never releases native
// ownership. Repeated calls may observe completion after a prior bounded timeout.
func (s *CAPEService) Shutdown(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.stopOnce.Do(func() {
		s.mu.Lock()
		s.stopping = true
		s.mu.Unlock()
		s.cancelHTTP()
		s.accepts.closePreHTTP()
		go func() {
			defer close(s.stopped)
			_ = s.http.Shutdown(context.Background())
			<-s.httpDone
			s.handlers.Wait()
			s.cancelScheduler()
			<-s.schedulerDone
			// Failed scheduler persistence retains pending outcomes in its owner.
			// Do not discard that owner/store or claim a completed clean drain.
			if s.runtime != nil && s.schedulerErr == nil {
				s.closeErr = s.runtime.close()
			}
		}()
	})
	select {
	case <-s.stopped:
		if s.schedulerErr != nil || s.closeErr != nil {
			return ErrCAPEDrain
		}
		return nil
	case <-ctx.Done():
		_ = s.http.Close()
		return ErrCAPEDrain
	}
}
