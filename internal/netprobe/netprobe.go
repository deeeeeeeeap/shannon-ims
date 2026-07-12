package netprobe

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"syscall"
	"time"
)

type Family int

const (
	FamilyAny Family = iota
	FamilyV4
	FamilyV6
)

type Config struct {
	Interface string
	URLs      []string
	Timeout   time.Duration
	Lookup    func(ctx context.Context, host string) ([]string, error)
}

type Prober struct {
	cfg    Config
	client *http.Client
}

type familyKey struct{}

func New(cfg Config) *Prober {
	p := &Prober{cfg: cfg}
	p.client = &http.Client{
		Transport: &http.Transport{
			DialContext:       p.dialContext,
			DisableKeepAlives: true,
		},
		Timeout: cfg.Timeout,
	}
	return p
}

func (p *Prober) Probe(parent context.Context, fam Family) string {
	ctx, cancel := context.WithTimeout(parent, p.cfg.Timeout)
	defer cancel()
	results := make(chan string, len(p.cfg.URLs))
	for _, target := range p.cfg.URLs {
		go func(target string) {
			req, err := http.NewRequestWithContext(withFamily(ctx, fam), http.MethodGet, target, nil)
			if err != nil {
				return
			}
			resp, err := p.client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			content := string(body)
			ip := extractResponseIP(target, content)
			if net.ParseIP(ip) != nil {
				select {
				case results <- ip:
				case <-ctx.Done():
				}
			}
		}(target)
	}

	select {
	case ip := <-results:
		return ip
	case <-ctx.Done():
		return ""
	}
}

func (p *Prober) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := p.lookupHost(ctx, host)
	if err != nil {
		return nil, err
	}
	ips = filterFamily(ips, familyFromContext(ctx))
	if len(ips) == 0 {
		return nil, fmt.Errorf("host %s: no address for family", host)
	}

	d := p.boundDialer()
	var lastErr error
	for _, ip := range ips {
		conn, err := d.DialContext(ctx, network, net.JoinHostPort(ip, port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func (p *Prober) lookupHost(ctx context.Context, host string) ([]string, error) {
	if ip := net.ParseIP(strings.TrimSpace(host)); ip != nil {
		return []string{ip.String()}, nil
	}
	if p.cfg.Lookup != nil {
		return p.cfg.Lookup(ctx, host)
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.IP.String())
	}
	return out, nil
}

func (p *Prober) boundDialer() *net.Dialer {
	d := &net.Dialer{Timeout: p.cfg.Timeout}
	if strings.TrimSpace(p.cfg.Interface) == "" {
		return d
	}
	d.Control = func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, p.cfg.Interface)
		}); err != nil {
			return err
		}
		return serr
	}
	return d
}

func withFamily(ctx context.Context, fam Family) context.Context {
	return context.WithValue(ctx, familyKey{}, fam)
}

func familyFromContext(ctx context.Context) Family {
	if fam, ok := ctx.Value(familyKey{}).(Family); ok {
		return fam
	}
	return FamilyAny
}

func filterFamily(ips []string, fam Family) []string {
	if fam == FamilyAny {
		return ips
	}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			continue
		}
		isV4 := parsed.To4() != nil
		if (fam == FamilyV4 && isV4) || (fam == FamilyV6 && !isV4) {
			out = append(out, ip)
		}
	}
	return out
}

func extractResponseIP(target, content string) string {
	if strings.Contains(target, "trace") {
		if m := regexp.MustCompile(`(?m)^ip=([^\r\n]+)`).FindStringSubmatch(content); len(m) > 1 {
			return extractIP(m[1])
		}
	}
	return extractIP(content)
}

func extractIP(content string) string {
	content = strings.TrimSpace(content)
	if ip := net.ParseIP(content); ip != nil {
		return ip.String()
	}
	if m := regexp.MustCompile(`[0-9a-fA-F:.]{2,45}`).FindString(content); m != "" {
		if ip := net.ParseIP(m); ip != nil {
			return ip.String()
		}
	}
	return ""
}
