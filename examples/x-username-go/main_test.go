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
		"CATCHPLATE_PROXY_URL":   "https://proxy.example.test:8443",
		"CATCHPLATE_APP_ID":      "11111111-1111-4111-8111-111111111111",
		"CATCHPLATE_PROXY_TOKEN": base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)),
		"CATCHPLATE_CA_FILE":     "/synthetic/catchplate-ca.pem",
		"CATCHPLATE_X_USERNAME":  "example_user",
		"X_BEARER_TOKEN":         "must-not-be-used", "TWITTER_BEARER_TOKEN": "must-not-be-used",
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
	if c.proxy.User != nil || c.username != "example_user" {
		t.Fatal("unexpected explicit configuration")
	}
	for _, tc := range []struct{ key, value string }{
		{"CATCHPLATE_PROXY_URL", "http://proxy.example.test"},
		{"CATCHPLATE_PROXY_URL", "https://user:secret@proxy.example.test"},
		{"CATCHPLATE_PROXY_URL", "https://proxy.example.test/path"},
		{"CATCHPLATE_PROXY_URL", "https://proxy.example.test?"},
		{"CATCHPLATE_PROXY_URL", "https://proxy.example.test#fragment"},
		{"CATCHPLATE_PROXY_URL", "https://proxy.example.test:0"},
		{"CATCHPLATE_PROXY_URL", "https://proxy.example.test:65536"},
		{"CATCHPLATE_PROXY_URL", "https://proxy.example.test:"},
		{"CATCHPLATE_PROXY_URL", "https://api.x.com"},
		{"CATCHPLATE_PROXY_URL", "https://127.0.0.1"},
		{"CATCHPLATE_PROXY_URL", "https://[::1]"},
		{"CATCHPLATE_PROXY_URL", "https://Proxy.example.test"},
		{"CATCHPLATE_APP_ID", "not-an-application-id"},
		{"CATCHPLATE_PROXY_TOKEN", "not-an-issued-app-token"},
		{"CATCHPLATE_CA_FILE", ""},
		{"CATCHPLATE_X_USERNAME", ""},
		{"CATCHPLATE_X_USERNAME", "Example_User"},
		{"CATCHPLATE_X_USERNAME", "../other"},
		{"CATCHPLATE_X_USERNAME", "name?user.fields=description"},
		{"CATCHPLATE_X_USERNAME", "sixteenlettersxx"},
		{"CATCHPLATE_X_USERNAME", "someone-else"},
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
	req, _ := http.NewRequest("GET", "https://api.x.com/2/users/by/username/example_user", nil)
	proxy, err := transport.Proxy(req)
	if err != nil || proxy.String() != c.proxy.String() || proxy.User != nil {
		t.Fatal("explicit credential-free HTTPS proxy not selected")
	}
	headers, err := transport.GetProxyConnectHeader(context.Background(), proxy, "api.x.com:443")
	if err != nil {
		t.Fatal(err)
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte(c.appID+":"+c.proxyToken))
	if headers.Get("Proxy-Authorization") != want || len(headers) != 1 || len(req.Header) != 0 {
		t.Fatal("CONNECT auth missing or leaked to inner request")
	}
	for _, target := range []string{"api.x.com:80", "other.example.test:443"} {
		if _, err := transport.GetProxyConnectHeader(context.Background(), proxy, target); err == nil {
			t.Fatal("unexpected CONNECT target accepted")
		}
	}
	wrongProxy, _ := url.Parse("https://other.example.test")
	if _, err := transport.GetProxyConnectHeader(context.Background(), wrongProxy, "api.x.com:443"); err == nil {
		t.Fatal("unexpected proxy accepted")
	}
	for _, target := range []string{
		"http://api.x.com/2/users/by/username/example_user",
		"https://api.x.com:444/2/users/by/username/example_user",
		"https://api.twitter.com/2/users/by/username/example_user",
		"https://api.x.com/2/users/by/username/other_user",
		"https://api.x.com/2/users/me",
		"https://api.x.com/2/users/by/username/example_user?user.fields=name",
		"https://api.x.com/2/users/by/username/example_user?",
		"https://api.x.com/2/users/by/username/example_user#ignored",
		"https://api.x.com/2/users/by/username/%65xample_user",
	} {
		r, _ := http.NewRequest("GET", target, nil)
		if _, err := transport.Proxy(r); err == nil {
			t.Fatal("unexpected origin, target, or query accepted")
		}
	}
	for _, method := range []string{"POST", "HEAD", "DELETE"} {
		r, _ := http.NewRequest(method, req.URL.String(), nil)
		if _, err := transport.Proxy(r); err == nil {
			t.Fatal("non-GET method accepted")
		}
	}
	bodyRequest, _ := http.NewRequest("GET", req.URL.String(), strings.NewReader("body"))
	if _, err := transport.Proxy(bodyRequest); err == nil {
		t.Fatal("GET with body accepted")
	}
	if !transport.DisableCompression || !transport.DisableKeepAlives {
		t.Fatal("unexpected automatic compression or reused-connection retry path")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func response(r *http.Request, code int, body string) *http.Response {
	return &http.Response{StatusCode: code, Header: http.Header{"Content-Type": {"application/json"}},
		Body: io.NopCloser(strings.NewReader(body)), Request: r}
}

func TestStockSDKUsesExactLookupAndPublicDummy(t *testing.T) {
	calls := 0
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client := sdkClient(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" || r.URL.String() != "https://api.x.com/2/users/by/username/example_user" ||
			r.Body != nil || r.ContentLength != 0 {
			t.Fatal("SDK escaped the exact empty-body username lookup")
		}
		if r.Header.Get("Authorization") != "Bearer "+dummyToken ||
			r.Header.Get("Accept") != "application/json" || len(r.Header) != 2 {
			t.Fatal("stock SDK headers changed or private credentials leaked")
		}
		if _, ok := r.Context().Deadline(); !ok {
			t.Fatal("SDK lost the context deadline")
		}
		return response(r, 200, `{"data":{"id":"123456789","username":"Example_User","name":"Not printed"}}`), nil
	}))
	got, err := lookupUsername(ctx, client, "example_user")
	if err != nil || got != (summary{Users: 1}) || calls != 1 {
		t.Fatal("lookup did not return exactly one matched user")
	}
	if client.Client.Timeout != 30*time.Second ||
		client.Client.CheckRedirect(nil, nil) != http.ErrUseLastResponse {
		t.Fatal("bounded timeout or redirect refusal changed")
	}
}

func TestFailureDoesNotRetryOrExposeProviderBody(t *testing.T) {
	for _, tc := range []struct {
		name string
		code int
		body string
	}{
		{"forbidden", 403, `{"detail":"private-provider-detail"}`},
		{"rate limited", 429, `{"detail":"private-provider-detail"}`},
		{"malformed", 200, `private-provider-detail`},
		{"missing data", 200, `{"errors":[{"detail":"private-provider-detail"}]}`},
		{"wrong user", 200, `{"data":{"id":"123","username":"other_user"}}`},
		{"invalid id", 200, `{"data":{"id":"private-provider-detail","username":"example_user"}}`},
		{"partial error", 200, `{"data":{"id":"123","username":"example_user"},"errors":[{}]}`},
		{"non-ASCII username", 200, `{"data":{"id":"123","username":"example_u\u017fer"}}`},
		{"redirect", 302, `{"detail":"private-provider-detail"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			client := sdkClient(roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				resp := response(r, tc.code, tc.body)
				resp.Header.Set("Location", "https://other.example.test/private-provider-detail")
				return resp, nil
			}))
			_, err := lookupUsername(context.Background(), client, "example_user")
			if err == nil || strings.Contains(err.Error(), "private-provider-detail") || calls != 1 {
				t.Fatal("failure retried, followed redirect, or exposed provider response")
			}
		})
	}
}

func TestInvalidUsernameAndTransportFailureAreSafe(t *testing.T) {
	calls := 0
	client := sdkClient(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("private-transport-detail")
	}))
	if _, err := lookupUsername(context.Background(), client, "not/lowercase"); err == nil || calls != 0 {
		t.Fatal("invalid username reached transport")
	}
	if _, err := lookupUsername(context.Background(), client, "example_user"); err == nil ||
		strings.Contains(err.Error(), "private-transport-detail") || calls != 1 {
		t.Fatal("transport failure was retried or exposed")
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
		{"inner", xHost, inner, true},
		{"crossed outer CA", xHost, outer, false},
		{"crossed inner CA", "proxy.example.test", inner, false},
		{"unexpected hostname", "other.example.test", outer, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			leaf := makeLeaf(t, tc.ca, tc.hostname)
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
	if err := tlsConfig.VerifyConnection(tls.ConnectionState{ServerName: xHost}); err == nil {
		t.Fatal("unverified peer accepted")
	}
	if _, err := clientTLS("proxy.example.test", outerRoots, []byte("not a CA")); err == nil {
		t.Fatal("invalid inner CA accepted")
	}
}
