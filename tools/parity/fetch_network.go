package main

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// Require canonical ASCII HTTPS authority spelling, with an optional explicit
// port. Omitted :443 and explicit :443 are intentionally distinct origins.
func fetchURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("invalid fetch URL")
	}
	if u.Scheme != "https" || u.Host == "" || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || strings.Contains(raw, "#") || u.Host != strings.ToLower(u.Host) {
		return nil, errors.New("invalid fetch URL")
	}
	host := u.Hostname()
	authority := host
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Zone() != "" || host != ip.String() {
			return nil, errors.New("invalid fetch host")
		}
		if ip.Is6() {
			authority = "[" + host + "]"
		}
	} else {
		if len(host) == 0 || len(host) > 253 {
			return nil, errors.New("invalid fetch host")
		}
		for _, label := range strings.Split(host, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return nil, errors.New("invalid fetch host")
			}
			for _, c := range label {
				if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
					return nil, errors.New("invalid fetch host")
				}
			}
		}
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return nil, errors.New("invalid fetch port")
		}
		authority += ":" + port
	} else if strings.HasSuffix(u.Host, ":") {
		return nil, errors.New("invalid fetch port")
	}
	if u.Host != authority {
		return nil, errors.New("invalid fetch host")
	}
	return u, nil
}

// Conservative exclusions include reserved/documentation/transition networks,
// not just RFC1918. IPv6 is restricted to global allocation space; future
// special-purpose assignments require revisiting this policy.
var fetchDeniedNetworks = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
}

func publicFetchIP(ip netip.Addr) bool {
	if !ip.IsValid() || ip.Zone() != "" {
		return false
	}
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	if ip.Is6() && !netip.MustParsePrefix("2000::/3").Contains(ip) {
		return false
	}
	for _, blocked := range fetchDeniedNetworks {
		if blocked.Contains(ip) {
			return false
		}
	}
	return true
}

type fetchDialer struct {
	lookup func(context.Context, string, string) ([]netip.Addr, error)
	dial   func(context.Context, string, string) (net.Conn, error)
}

func netFetchDialer() fetchDialer {
	d := &net.Dialer{Timeout: fetchRequestTimeout}
	return fetchDialer{lookup: net.DefaultResolver.LookupNetIP, dial: d.DialContext}
}

// Resolve once under the request deadline, reject the entire mixed answer, and
// dial an IP literal. The HTTP transport still verifies TLS against the URL host.
func (d fetchDialer) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, fetchRequestTimeout)
	defer cancel()
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, errors.New("invalid fetch endpoint")
	}
	var ips []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		ips = []netip.Addr{ip}
	} else {
		ips, err = d.lookup(ctx, "ip", host)
		if err != nil {
			return nil, errors.New("fetch resolution failed")
		}
	}
	if len(ips) == 0 {
		return nil, errors.New("fetch resolution failed")
	}
	for _, ip := range ips {
		if !publicFetchIP(ip) {
			return nil, errors.New("fetch endpoint is not public")
		}
	}
	// One connection attempt, no retries or alternate-address fallback.
	conn, err := d.dial(ctx, network, net.JoinHostPort(ips[0].Unmap().String(), port))
	if err != nil {
		return nil, errors.New("fetch connection failed")
	}
	return conn, nil
}

func newFetchClient(d fetchDialer) *http.Client {
	return &http.Client{
		Timeout:       fetchRequestTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			Proxy: nil, DialContext: d.dialContext,
			DisableCompression: true, DisableKeepAlives: true,
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout: fetchRequestTimeout, ResponseHeaderTimeout: fetchRequestTimeout,
			MaxResponseHeaderBytes: 64 << 10,
		},
	}
}

func fetchBytes(ctx context.Context, client *http.Client, url string, s sample) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, fetchRequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, errors.New("invalid fetch request")
	}
	req.Header.Set("Accept-Encoding", "identity")
	response, err := client.Do(req)
	if err != nil {
		return nil, errors.New("fetch request failed")
	}
	if response.StatusCode != http.StatusOK || response.Uncompressed || len(response.Header.Values("Content-Encoding")) > 1 || (response.Header.Get("Content-Encoding") != "" && response.Header.Get("Content-Encoding") != "identity") || (response.ContentLength >= 0 && response.ContentLength != s.Size) {
		_ = response.Body.Close()
		return nil, errors.New("invalid fetch response")
	}
	b, err := io.ReadAll(io.LimitReader(response.Body, s.Size+1))
	closeErr := response.Body.Close()
	if err != nil || closeErr != nil || ctx.Err() != nil || int64(len(b)) != s.Size || digest(b) != s.SHA256 {
		return nil, errors.New("fetch integrity failed")
	}
	return b, nil
}
