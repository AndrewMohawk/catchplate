package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func environment() map[string]string {
	return map[string]string{
		"SERVERWARE_PROXY_URL":    "https://proxy.example.test:8443",
		"SERVERWARE_APP_ID":       "11111111-1111-4111-8111-111111111111",
		"SERVERWARE_PROXY_TOKEN":  base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)),
		"SERVERWARE_CA_FILE":      "/synthetic/serverware-ca.pem",
		"SERVERWARE_GITHUB_OWNER": "example-owner",
		"SERVERWARE_GITHUB_REPO":  "example-repo",
		"GITHUB_TOKEN":            "must-not-be-used", "GH_TOKEN": "must-not-be-used",
		"HTTPS_PROXY": "http://must-not-be-used.invalid", "NO_PROXY": "*",
	}
}

func configForTest(t *testing.T) config {
	t.Helper()
	env := environment()
	c, err := readConfig(func(key string) string { return env[key] })
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestConfigRequiresExplicitBoundedInputs(t *testing.T) {
	c := configForTest(t)
	if c.proxy.User != nil || c.owner != "example-owner" || c.repo != "example-repo" {
		t.Fatal("unexpected explicit configuration")
	}
	for _, tc := range []struct{ key, value string }{
		{"SERVERWARE_PROXY_URL", "http://proxy.example.test"},
		{"SERVERWARE_PROXY_URL", "https://user:secret@proxy.example.test"},
		{"SERVERWARE_PROXY_URL", "https://proxy.example.test/path"},
		{"SERVERWARE_PROXY_URL", "https://proxy.example.test?"},
		{"SERVERWARE_PROXY_URL", "https://proxy.example.test#fragment"},
		{"SERVERWARE_PROXY_URL", "https://proxy.example.test:0"},
		{"SERVERWARE_PROXY_URL", "https://proxy.example.test:65536"},
		{"SERVERWARE_PROXY_URL", "https://proxy.example.test:"},
		{"SERVERWARE_PROXY_URL", "https://api.github.com"},
		{"SERVERWARE_PROXY_URL", "https://127.0.0.1"},
		{"SERVERWARE_PROXY_URL", "https://[::1]"},
		{"SERVERWARE_PROXY_URL", "https://Proxy.example.test"},
		{"SERVERWARE_APP_ID", "not-an-application-id"},
		{"SERVERWARE_PROXY_TOKEN", "not-an-issued-app-token"},
		{"SERVERWARE_CA_FILE", ""},
		{"SERVERWARE_GITHUB_OWNER", "../other"},
		{"SERVERWARE_GITHUB_REPO", "../other"},
		{"SERVERWARE_GITHUB_REPO", ".."},
	} {
		t.Run(tc.key+"/"+tc.value, func(t *testing.T) {
			env := environment()
			env[tc.key] = tc.value
			if _, err := readConfig(func(key string) string { return env[key] }); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
}

func TestProxyAuthenticationIsCONNECTOnly(t *testing.T) {
	c := configForTest(t)
	transport := proxyTransport(c, &tls.Config{})
	req, _ := http.NewRequest("GET", "https://api.github.com/repos/example-owner/example-repo/issues", nil)
	proxy, err := transport.Proxy(req)
	if err != nil || proxy.String() != c.proxy.String() || proxy.User != nil {
		t.Fatal("explicit credential-free HTTPS proxy not selected")
	}
	headers, err := transport.GetProxyConnectHeader(context.Background(), proxy, "api.github.com:443")
	if err != nil {
		t.Fatal(err)
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte(c.appID+":"+c.proxyToken))
	if headers.Get("Proxy-Authorization") != want || len(headers) != 1 || len(req.Header) != 0 {
		t.Fatal("CONNECT auth missing or leaked to inner request")
	}
	for _, target := range []string{"api.github.com:80", "other.example.test:443"} {
		if _, err := transport.GetProxyConnectHeader(context.Background(), proxy, target); err == nil {
			t.Fatal("unexpected CONNECT target accepted")
		}
	}
	wrongProxy, _ := url.Parse("https://other.example.test")
	if _, err := transport.GetProxyConnectHeader(context.Background(), wrongProxy, "api.github.com:443"); err == nil {
		t.Fatal("unexpected proxy accepted")
	}
	for _, target := range []string{"http://api.github.com", "https://api.github.com:444", "https://example.test"} {
		r, _ := http.NewRequest("GET", target, nil)
		if _, err := transport.Proxy(r); err == nil {
			t.Fatal("unexpected origin accepted")
		}
	}
	if !transport.DisableCompression || !transport.DisableKeepAlives {
		t.Fatal("unexpected automatic compression or reused-connection retry path")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func response(r *http.Request, code int, body, link string) *http.Response {
	h := http.Header{"Content-Type": {"application/json; charset=utf-8"}}
	if link != "" {
		h.Set("Link", link)
	}
	return &http.Response{StatusCode: code, Header: h, Body: io.NopCloser(strings.NewReader(body)), Request: r}
}

func TestStockSDKPaginationAndFixedAuthentication(t *testing.T) {
	requests := 0
	client := sdkClient(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		requests++
		if r.Method != "GET" || r.URL.Scheme != "https" || r.URL.Host != githubHost ||
			r.URL.Path != "/repos/example-owner/example-repo/issues" {
			t.Fatal("SDK escaped selected read-only repository")
		}
		if r.Header.Get("Authorization") != "token "+dummyToken || r.Header.Get("Proxy-Authorization") != "" {
			t.Fatal("SDK auth not fixed dummy, or CONNECT credentials leaked")
		}
		// This is the actual v74 SDK value, without a +json suffix. Never rewrite it.
		if r.Header.Get("Accept") != "application/vnd.github.squirrel-girl-preview" ||
			r.Header.Get("X-Github-Api-Version") != "2022-11-28" || r.Header.Get("User-Agent") != "go-github/v74.0.0" {
			t.Fatal("unexpected stock SDK headers; review compatibility before upgrading")
		}
		q := r.URL.Query()
		if q.Get("state") != "open" || q.Get("per_page") != "100" || len(q) != 3 {
			t.Fatal("unexpected SDK list query")
		}
		switch requests {
		case 1:
			if q.Get("page") != "1" {
				t.Fatal("first page not explicit")
			}
			return response(r, 200, `[{"number":1},{"number":2,"pull_request":{}}]`,
				`<https://api.github.com/repos/example-owner/example-repo/issues?page=2>; rel="next"`), nil
		case 2:
			if q.Get("page") != "2" {
				t.Fatal("SDK next page not used")
			}
			return response(r, 200, `[{"number":3}]`, ""), nil
		default:
			t.Fatal("unexpected retry")
			return nil, errors.New("unexpected retry")
		}
	}))
	got, err := listIssues(context.Background(), client, "example-owner", "example-repo", maxPages)
	if err != nil || got != (summary{Pages: 2, Issues: 2, PullRequests: 1}) || requests != 2 {
		t.Fatalf("unexpected counts or completion: %+v %v", got, err)
	}
}

func TestPaginationRefusesRepeatsAndBoundsWork(t *testing.T) {
	for _, tc := range []struct {
		name, link   string
		limit, calls int
	}{
		{"repeat", `<https://api.github.com/repos/example-owner/example-repo/issues?page=1>; rel="next"`, 100, 1},
		{"oversize", `<https://api.github.com/repos/example-owner/example-repo/issues?page=1000001>; rel="next"`, 100, 1},
		{"limit", `<https://api.github.com/repos/example-owner/example-repo/issues?page=2>; rel="next"`, 1, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			client := sdkClient(roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				return response(r, 200, `[]`, tc.link), nil
			}))
			if _, err := listIssues(context.Background(), client, "example-owner", "example-repo", tc.limit); err == nil || calls != tc.calls {
				t.Fatal("unsafe pagination accepted")
			}
		})
	}
}

func TestFailureDoesNotRetryOrExposeProviderBody(t *testing.T) {
	calls := 0
	client := sdkClient(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		return response(r, 403, `{"message":"private-provider-detail"}`, ""), nil
	}))
	_, err := listIssues(context.Background(), client, "example-owner", "example-repo", maxPages)
	if err == nil || strings.Contains(err.Error(), "private-provider-detail") || calls != 1 {
		t.Fatal("failure retried or exposed provider response")
	}
}

type testCA struct {
	cert *x509.Certificate
	key  ed25519.PrivateKey
	pem  []byte
}

func makeCA(t *testing.T, name string) testCA {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return testCA{cert, private, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func makeLeaf(t *testing.T, ca testCA, name string) *x509.Certificate {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, public, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestTLSRequiresCorrectCAForEachHop(t *testing.T) {
	outer, inner := makeCA(t, "synthetic outer"), makeCA(t, "synthetic inner")
	outerRoots := x509.NewCertPool()
	outerRoots.AddCert(outer.cert)
	tlsConfig, err := clientTLS("proxy.example.test", outerRoots, inner.pem)
	if err != nil {
		t.Fatal(err)
	}
	if tlsConfig.InsecureSkipVerify || tlsConfig.ServerName != "" || tlsConfig.MinVersion < tls.VersionTLS12 {
		t.Fatal("normal TLS verification was weakened")
	}
	for _, tc := range []struct {
		name, hostname string
		ca             testCA
		allowed        bool
	}{
		{"outer", "proxy.example.test", outer, true},
		{"inner", githubHost, inner, true},
		{"crossed outer CA", githubHost, outer, false},
		{"crossed inner CA", "proxy.example.test", inner, false},
		{"unexpected hostname", "other.example.test", outer, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			leaf := makeLeaf(t, tc.ca, tc.hostname)
			// All these valid synthetic chains pass the shared initial trust pool.
			// The extra standard verification callback must reject crossed roles.
			chains, err := leaf.Verify(x509.VerifyOptions{Roots: tlsConfig.RootCAs, DNSName: tc.hostname})
			if err != nil {
				t.Fatal(err)
			}
			err = tlsConfig.VerifyConnection(tls.ConnectionState{ServerName: tc.hostname,
				PeerCertificates: []*x509.Certificate{leaf, tc.ca.cert}, VerifiedChains: chains})
			if (err == nil) != tc.allowed {
				t.Fatal("wrong per-hop trust result")
			}
		})
	}
	if err := tlsConfig.VerifyConnection(tls.ConnectionState{ServerName: githubHost}); err == nil {
		t.Fatal("unverified peer accepted")
	}
	if _, err := clientTLS("proxy.example.test", outerRoots, []byte("not a CA")); err == nil {
		t.Fatal("invalid inner CA accepted")
	}
}
