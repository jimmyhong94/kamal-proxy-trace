package server

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

type TLSPreflight struct {
	hosts       []string
	manager     *autocert.Manager
	httpHandler http.Handler
	cachePath   string
	timeout     time.Duration
}

func NewTLSPreflight(hosts []string, acmeCachePath string, timeout time.Duration) (*TLSPreflight, error) {
	cachePath, err := os.MkdirTemp(acmeCachePath, "tls-preflight-*")
	if err != nil {
		return nil, fmt.Errorf("creating preflight cache dir: %w", err)
	}

	manager := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(cachePath),
		HostPolicy: autocert.HostWhitelist(hosts...),
		Client:     &acme.Client{DirectoryURL: ACMEStagingDirectoryURL},
	}

	return &TLSPreflight{
		hosts:       hosts,
		manager:     manager,
		httpHandler: manager.HTTPHandler(nil),
		cachePath:   cachePath,
		timeout:     timeout,
	}, nil
}

func (p *TLSPreflight) Run() error {
	defer os.RemoveAll(p.cachePath)

	type result struct {
		host string
		err  error
	}

	results := make(chan result, len(p.hosts))

	for _, host := range p.hosts {
		go func() {
			slog.Info("TLS preflight: verifying host", "host", host)
			hello := &tls.ClientHelloInfo{ServerName: host}
			_, err := p.manager.GetCertificate(hello)
			results <- result{host: host, err: err}
		}()
	}

	timer := time.NewTimer(p.timeout)
	defer timer.Stop()

	var errs []error
	remaining := len(p.hosts)

	for remaining > 0 {
		select {
		case r := <-results:
			remaining--
			if r.err != nil {
				errs = append(errs, fmt.Errorf("host %q: %w", r.host, r.err))
				slog.Error("TLS preflight: verification failed", "host", r.host, "error", r.err)
			} else {
				slog.Info("TLS preflight: verification succeeded", "host", r.host)
			}
		case <-timer.C:
			return fmt.Errorf("TLS preflight timed out after %v with %d host(s) still pending", p.timeout, remaining)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("TLS preflight failed for %d host(s): %v", len(errs), errs)
	}

	return nil
}

func (p *TLSPreflight) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	for _, host := range p.hosts {
		if hello.ServerName == host {
			return p.manager.GetCertificate(hello)
		}
	}
	return nil, nil
}

func (p *TLSPreflight) HTTPHandler() http.Handler {
	return p.httpHandler
}

func (p *TLSPreflight) HandlesHost(host string) bool {
	for _, h := range p.hosts {
		if h == host {
			return true
		}
	}
	return false
}
