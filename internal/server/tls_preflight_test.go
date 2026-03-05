package server

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/acme/autocert"
)

func TestTLSPreflight_HandlesHost(t *testing.T) {
	pf := &TLSPreflight{
		hosts: []string{"a.example.com", "b.example.com"},
	}

	assert.True(t, pf.HandlesHost("a.example.com"))
	assert.True(t, pf.HandlesHost("b.example.com"))
	assert.False(t, pf.HandlesHost("c.example.com"))
	assert.False(t, pf.HandlesHost(""))
}

func TestTLSPreflight_GetCertificateRouting(t *testing.T) {
	pf := &TLSPreflight{
		hosts: []string{"a.example.com"},
	}

	// Non-preflight host returns nil cert and nil error (falls through)
	cert, err := pf.GetCertificate(&tls.ClientHelloInfo{ServerName: "other.example.com"})
	assert.Nil(t, cert)
	assert.NoError(t, err)
}

func TestTLSPreflight_ChallengeInterception(t *testing.T) {
	router := testRouter(t)
	_, target := testBackend(t, "normal", http.StatusOK)

	serviceOptions := defaultServiceOptions
	serviceOptions.Hosts = []string{"existing.example.com"}
	require.NoError(t, router.DeployService("svc", []string{target}, defaultEmptyReaders, serviceOptions, defaultTargetOptions, defaultDeploymentOptions))

	// Register a preflight with a mock HTTP handler
	pf := &TLSPreflight{
		hosts:       []string{"preflight.example.com"},
		httpHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }),
	}
	router.registerPreflight(pf)
	defer router.unregisterPreflight()

	// ACME challenge request for preflight host should be intercepted
	req := httptest.NewRequest(http.MethodGet, "http://preflight.example.com/.well-known/acme-challenge/test-token", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Result().StatusCode)

	// ACME challenge request for non-preflight host should pass through to normal routing
	req = httptest.NewRequest(http.MethodGet, "http://existing.example.com/.well-known/acme-challenge/test-token", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Result().StatusCode)

	// Normal request to preflight host should not be intercepted (no service registered for it)
	req = httptest.NewRequest(http.MethodGet, "http://preflight.example.com/normal-path", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Result().StatusCode)

	// GetCertificate for non-preflight host should return nil (falls through)
	pf2 := &TLSPreflight{
		hosts: []string{"preflight.example.com"},
	}
	router.registerPreflight(pf2)
	cert, err := pf2.GetCertificate(&tls.ClientHelloInfo{ServerName: "other.example.com"})
	assert.Nil(t, cert)
	assert.NoError(t, err)
}

func TestTLSPreflight_GetCertificate_NonTLSServiceFallsThroughToPreflight(t *testing.T) {
	router := testRouter(t)
	_, target := testBackend(t, "non-tls", http.StatusOK)

	// Deploy a non-TLS service
	serviceOptions := defaultServiceOptions
	serviceOptions.Hosts = []string{"upgrade.example.com"}
	serviceOptions.TLSEnabled = false
	require.NoError(t, router.DeployService("svc", []string{target}, defaultEmptyReaders, serviceOptions, defaultTargetOptions, defaultDeploymentOptions))

	// Without preflight, GetCertificate returns ErrorUnknownServerName
	hello := &tls.ClientHelloInfo{ServerName: "upgrade.example.com"}
	_, err := router.GetCertificate(hello)
	assert.ErrorIs(t, err, ErrorUnknownServerName)

	// Register preflight for the same host (simulating TLS upgrade)
	pf, pfErr := NewTLSPreflight([]string{"upgrade.example.com"}, t.TempDir(), time.Second)
	require.NoError(t, pfErr)
	router.registerPreflight(pf)
	defer router.unregisterPreflight()

	// With preflight, GetCertificate should fall through to preflight
	// (not short-circuit to ErrorUnknownServerName)
	_, err = router.GetCertificate(hello)
	assert.NotErrorIs(t, err, ErrorUnknownServerName)
}

func TestTLSPreflight_GetCertificate_TLSServiceBypassesPreflight(t *testing.T) {
	router := testRouter(t)
	_, target := testBackend(t, "tls", http.StatusOK)

	// Deploy a TLS-enabled service
	serviceOptions := defaultServiceOptions
	serviceOptions.Hosts = []string{"tls-bypass.example.com"}
	serviceOptions.TLSEnabled = true
	serviceOptions.TLSRedirect = false
	serviceOptions.ACMECachePath = t.TempDir()
	require.NoError(t, router.DeployService("svc", []string{target}, defaultEmptyReaders, serviceOptions, defaultTargetOptions, defaultDeploymentOptions))

	// Register preflight for the same host
	preflightHit := false
	pf := &TLSPreflight{
		hosts: []string{"tls-bypass.example.com"},
		manager: &autocert.Manager{
			Prompt: autocert.AcceptTOS,
			Cache:  autocert.DirCache(t.TempDir()),
			HostPolicy: func(_ context.Context, host string) error {
				preflightHit = true
				return nil
			},
		},
	}
	router.registerPreflight(pf)
	defer router.unregisterPreflight()

	// GetCertificate should use service's certManager, not preflight
	hello := &tls.ClientHelloInfo{ServerName: "tls-bypass.example.com"}
	router.GetCertificate(hello)
	assert.False(t, preflightHit, "preflight should not be consulted for TLS-capable service")
}

func TestTLSPreflight_NonTLSServiceUpgrade(t *testing.T) {
	router := testRouter(t)
	_, target := testBackend(t, "non-tls", http.StatusOK)

	// Deploy a non-TLS service on the host
	serviceOptions := defaultServiceOptions
	serviceOptions.Hosts = []string{"upgrade.example.com"}
	serviceOptions.TLSEnabled = false
	require.NoError(t, router.DeployService("svc", []string{target}, defaultEmptyReaders, serviceOptions, defaultTargetOptions, defaultDeploymentOptions))

	// Register preflight for the same host (simulating TLS upgrade)
	preflightCalled := false
	pf := &TLSPreflight{
		hosts:       []string{"upgrade.example.com"},
		httpHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { preflightCalled = true; w.WriteHeader(http.StatusOK) }),
	}
	router.registerPreflight(pf)
	defer router.unregisterPreflight()

	// ACME challenge should route to preflight (non-TLS service doesn't handle ACME)
	req := httptest.NewRequest(http.MethodGet, "http://upgrade.example.com/.well-known/acme-challenge/test-token", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.True(t, preflightCalled, "preflight should handle ACME challenge for non-TLS service host")
	assert.Equal(t, http.StatusOK, w.Result().StatusCode)
}

func TestTLSPreflight_TLSServiceBypassesPreflight(t *testing.T) {
	router := testRouter(t)
	_, target := testBackend(t, "tls-svc", http.StatusOK)

	// Deploy a TLS-enabled service
	serviceOptions := defaultServiceOptions
	serviceOptions.Hosts = []string{"tls.example.com"}
	serviceOptions.TLSEnabled = true
	serviceOptions.TLSRedirect = false
	serviceOptions.ACMECachePath = t.TempDir()
	require.NoError(t, router.DeployService("svc", []string{target}, defaultEmptyReaders, serviceOptions, defaultTargetOptions, defaultDeploymentOptions))

	// Register preflight for the same host
	preflightCalled := false
	pf := &TLSPreflight{
		hosts:       []string{"tls.example.com"},
		httpHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { preflightCalled = true; w.WriteHeader(http.StatusOK) }),
	}
	router.registerPreflight(pf)
	defer router.unregisterPreflight()

	// ACME challenge should NOT route to preflight (TLS service handles its own ACME)
	req := httptest.NewRequest(http.MethodGet, "http://tls.example.com/.well-known/acme-challenge/test-token", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.False(t, preflightCalled, "preflight should not intercept ACME for TLS-capable service")
}
