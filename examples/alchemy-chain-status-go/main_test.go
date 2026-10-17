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
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
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
		"CATCHPLATE_PROXY_URL":     "https://proxy.example.test:8443",
		"CATCHPLATE_APP_ID":        "11111111-1111-4111-8111-111111111111",
		"CATCHPLATE_PROXY_TOKEN":   base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)),
		"CATCHPLATE_CA_FILE":       "/synthetic/catchplate-ca.pem",
		"CATCHPLATE_ALCHEMY_CHAIN": "eth-mainnet",
		"ALCHEMY_API_KEY":          "must-not-be-used", "WEB3_PROVIDER_URI": "https://must-not-be-used.invalid",
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
	if c.proxy.User != nil || c.providerHost != "eth-mainnet.g.alchemy.com" {
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
		{"CATCHPLATE_PROXY_URL", "https://eth-mainnet.g.alchemy.com"},
		{"CATCHPLATE_PROXY_URL", "https://eth-sepolia.g.alchemy.com"},
		{"CATCHPLATE_PROXY_URL", "https://127.0.0.1"},
		{"CATCHPLATE_PROXY_URL", "https://[::1]"},
		{"CATCHPLATE_PROXY_URL", "https://Proxy.example.test"},
		{"CATCHPLATE_APP_ID", "not-an-application-id"},
		{"CATCHPLATE_PROXY_TOKEN", "not-an-issued-app-token"},
		{"CATCHPLATE_CA_FILE", ""},
		{"CATCHPLATE_ALCHEMY_CHAIN", ""},
		{"CATCHPLATE_ALCHEMY_CHAIN", "mainnet"},
		{"CATCHPLATE_ALCHEMY_CHAIN", "ETH-MAINNET"},
		{"CATCHPLATE_ALCHEMY_CHAIN", "https://eth-mainnet.g.alchemy.com/v2/secret"},
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

func TestAmbientSystemTrustOverridesAreRefused(t *testing.T) {
	for _, variable := range []string{"SSL_CERT_FILE", "SSL_CERT_DIR"} {
		t.Run(variable, func(t *testing.T) {
			env := environment()
			env[variable] = "private-trust-override-value"
			_, err := readConfig(func(key string) string { return env[key] })
			if err == nil || strings.Contains(err.Error(), env[variable]) {
				t.Fatal("ambient root override accepted or exposed in error output")
			}
			if env[variable] != "private-trust-override-value" {
				t.Fatal("configuration silently modified the supplied environment")
			}
			env[variable] = ""
			if _, err := readConfig(func(key string) string { return env[key] }); err != nil {
				t.Fatal("empty ambient trust setting rejected")
			}
		})
	}
}

func TestProxyAuthenticationIsCONNECTOnly(t *testing.T) {
	c := configForTest(t)
	transport := proxyTransport(c, &tls.Config{})
	req, _ := http.NewRequest("POST", "https://eth-mainnet.g.alchemy.com/v2", strings.NewReader("{}"))
	proxy, err := transport.Proxy(req)
	if err != nil || proxy.String() != c.proxy.String() || proxy.User != nil {
		t.Fatal("explicit credential-free HTTPS proxy not selected")
	}
	headers, err := transport.GetProxyConnectHeader(context.Background(), proxy, c.providerHost+":443")
	if err != nil {
		t.Fatal(err)
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte(c.appID+":"+c.proxyToken))
	if headers.Get("Proxy-Authorization") != want || len(headers) != 1 || len(req.Header) != 0 {
		t.Fatal("CONNECT auth missing or leaked to inner request")
	}
	for _, target := range []string{c.providerHost + ":80", "eth-sepolia.g.alchemy.com:443", "other.example.test:443"} {
		if _, err := transport.GetProxyConnectHeader(context.Background(), proxy, target); err == nil {
			t.Fatal("unexpected CONNECT target accepted")
		}
	}
	wrongProxy, _ := url.Parse("https://other.example.test")
	if _, err := transport.GetProxyConnectHeader(context.Background(), wrongProxy, c.providerHost+":443"); err == nil {
		t.Fatal("unexpected proxy accepted")
	}
	for _, target := range []string{
		"http://eth-mainnet.g.alchemy.com/v2",
		"https://eth-mainnet.g.alchemy.com:444/v2",
		"https://eth-sepolia.g.alchemy.com/v2",
		"https://eth-mainnet.g.alchemy.com/v2/key-in-path",
		"https://eth-mainnet.g.alchemy.com/v2?apiKey=secret",
		"https://eth-mainnet.g.alchemy.com/v2?",
		"https://eth-mainnet.g.alchemy.com/v2#ignored",
		"https://eth-mainnet.g.alchemy.com/%762",
	} {
		r, _ := http.NewRequest("POST", target, strings.NewReader("{}"))
		if _, err := transport.Proxy(r); err == nil {
			t.Fatal("unexpected chain, target, or query accepted")
		}
	}
	for _, method := range []string{"GET", "HEAD", "DELETE"} {
		r, _ := http.NewRequest(method, req.URL.String(), nil)
		if _, err := transport.Proxy(r); err == nil {
			t.Fatal("non-POST method accepted")
		}
	}
	if !transport.DisableCompression || !transport.DisableKeepAlives {
		t.Fatal("automatic compression or reused-connection retry path enabled")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func response(r *http.Request, code int, body string) *http.Response {
	return &http.Response{StatusCode: code, Header: http.Header{"Content-Type": {"application/json"}},
		Body: io.NopCloser(strings.NewReader(body)), Request: r}
}

func TestStockRPCTwoBoundedCallsWithExplicitEmptyParams(t *testing.T) {
	for _, chain := range []string{"eth-mainnet", "eth-sepolia"} {
		t.Run(chain, func(t *testing.T) {
			host, expectedID, _ := selectChain(chain)
			calls := 0
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if calls > 2 || r.Method != "POST" || r.URL.String() != "https://"+host+"/v2" {
					t.Fatal("SDK changed the bounded fixed-origin call sequence")
				}
				if r.Header.Get("Authorization") != "Bearer "+dummyToken || r.Header.Get("Accept") != "application/json" ||
					r.Header.Get("Content-Type") != "application/json" || len(r.Header) != 3 {
					t.Fatal("SDK headers changed or private credentials leaked")
				}
				if _, ok := r.Context().Deadline(); !ok {
					t.Fatal("SDK lost the context deadline")
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Fatal(err)
				}
				var fields map[string]json.RawMessage
				if err := json.Unmarshal(body, &fields); err != nil || len(fields) != 4 ||
					string(fields["jsonrpc"]) != `"2.0"` || string(fields["id"]) != fmt.Sprint(calls) ||
					string(fields["params"]) != `[]` || r.ContentLength != int64(len(body)) {
					t.Fatal("SDK did not emit a single exact JSON-RPC envelope with params []")
				}
				method, result := `"eth_chainId"`, expectedID
				if calls == 2 {
					method, result = `"eth_blockNumber"`, "0x1234"
				}
				if string(fields["method"]) != method {
					t.Fatal("wrong method or method order")
				}
				return response(r, 200, fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"result":%q}`, calls, result)), nil
			})
			got, err := chainStatus(ctx, chain, transport)
			if err != nil || got != (summary{ChainID: expectedID, BlockNumber: 4660}) || calls != 2 {
				t.Fatal("RPC read did not produce the matched chain and bounded height")
			}
		})
	}
	client := httpClient(roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("unused") }))
	if client.Timeout != 30*time.Second || client.CheckRedirect(nil, nil) != http.ErrUseLastResponse {
		t.Fatal("bounded client timeout or redirect refusal changed")
	}
}

func TestFailuresStopWithoutRetryOrRawProviderErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		code int
		body string
	}{
		{"forbidden", 403, `{"detail":"private-provider-detail"}`},
		{"rate limited", 429, `{"detail":"private-provider-detail"}`},
		{"unavailable", 503, `{"detail":"private-provider-detail"}`},
		{"RPC error", 200, `{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"private-provider-detail"}}`},
		{"missing result", 200, `{"jsonrpc":"2.0","id":1}`},
		{"null result", 200, `{"jsonrpc":"2.0","id":1,"result":null}`},
		{"wrong chain", 200, `{"jsonrpc":"2.0","id":1,"result":"0xaa36a7"}`},
		{"non-quantity result", 200, `{"jsonrpc":"2.0","id":1,"result":"private-provider-detail"}`},
		{"malformed", 200, `private-provider-detail`},
		{"redirect", 302, `{"detail":"private-provider-detail"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				resp := response(r, tc.code, tc.body)
				resp.Header.Set("Location", "https://other.example.test/private-provider-detail")
				return resp, nil
			})
			_, err := chainStatus(context.Background(), "eth-mainnet", transport)
			if err == nil || strings.Contains(err.Error(), "private-provider-detail") || calls != 1 {
				t.Fatal("failure retried, continued, followed redirect, or exposed provider response")
			}
		})
	}
}

func TestBlockQuantityIsCanonicalBoundedAndRequired(t *testing.T) {
	for _, rawResult := range []string{`"0x"`, `"0x01"`, `"0X1"`, `"0xA"`, `"-1"`, `"0x10000000000000000"`, `null`, `3`, `{}`} {
		t.Run(rawResult, func(t *testing.T) {
			calls := 0
			transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if calls == 1 {
					return response(r, 200, `{"jsonrpc":"2.0","id":1,"result":"0x1"}`), nil
				}
				return response(r, 200, `{"jsonrpc":"2.0","id":2,"result":`+rawResult+`}`), nil
			})
			if _, err := chainStatus(context.Background(), "eth-mainnet", transport); err == nil || calls != 2 {
				t.Fatal("invalid block quantity accepted or request repeated")
			}
		})
	}
}

func TestInvalidChainAndTransportFailuresDoNotLeak(t *testing.T) {
	calls := 0
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("private-transport-detail")
	})
	if _, err := chainStatus(context.Background(), "other-chain", transport); err == nil || calls != 0 {
		t.Fatal("invalid chain reached transport")
	}
	if _, err := chainStatus(context.Background(), "eth-mainnet", transport); err == nil ||
		strings.Contains(err.Error(), "private-transport-detail") || calls != 1 {
		t.Fatal("transport failure retried or exposed")
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
	providerHost := "eth-mainnet.g.alchemy.com"
	tlsConfig, err := clientTLS("proxy.example.test", providerHost, outerRoots, inner.pem)
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
		{"inner", providerHost, inner, true},
		{"crossed outer CA", providerHost, outer, false},
		{"crossed inner CA", "proxy.example.test", inner, false},
		{"unselected chain", "eth-sepolia.g.alchemy.com", inner, false},
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
	if err := tlsConfig.VerifyConnection(tls.ConnectionState{ServerName: providerHost}); err == nil {
		t.Fatal("unverified peer accepted")
	}
	if _, err := clientTLS("proxy.example.test", providerHost, outerRoots, []byte("not a CA")); err == nil {
		t.Fatal("invalid inner CA accepted")
	}
}
