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
		"SERVERWARE_PROXY_URL":   "https://proxy.example.test:8443",
		"SERVERWARE_APP_ID":      "11111111-1111-4111-8111-111111111111",
		"SERVERWARE_PROXY_TOKEN": base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)),
		"SERVERWARE_CA_FILE":     "/synthetic/inner.pem", "SERVERWARE_PROXY_CA_FILE": "/synthetic/outer.pem",
		"SERVERWARE_X_POST_TEXT": "Synthetic post\nsecond line\ttext\r", "SERVERWARE_X_POST_CONFIRM": "post-once",
		"X_BEARER_TOKEN": "provider-canary", "TWITTER_BEARER_TOKEN": "provider-canary",
		"HTTPS_PROXY": "http://ambient-canary.invalid", "NO_PROXY": "*",
	}
}

func configForTest(t *testing.T) config {
	t.Helper()
	env := environment()
	c, err := readConfig(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestConfigIsExplicitAndRejectsAmbientRoots(t *testing.T) {
	c := configForTest(t)
	if c.proxy.User != nil || c.text != environment()["SERVERWARE_X_POST_TEXT"] {
		t.Fatal("configuration changed")
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
		{"SERVERWARE_PROXY_URL", "https://api.x.com"},
		{"SERVERWARE_PROXY_URL", "https://127.0.0.1"},
		{"SERVERWARE_PROXY_URL", "https://[::1]"},
		{"SERVERWARE_PROXY_URL", "https://Proxy.example.test"},
		{"SERVERWARE_APP_ID", "not-an-app"}, {"SERVERWARE_PROXY_TOKEN", "provider-canary"},
		{"SERVERWARE_CA_FILE", ""}, {"SERVERWARE_X_POST_TEXT", ""},
		{"SERVERWARE_X_POST_CONFIRM", ""}, {"SERVERWARE_X_POST_CONFIRM", "yes"},
		{"SSL_CERT_FILE", "/ambient/canary"}, {"SSL_CERT_DIR", "/ambient/canary"},
	} {
		t.Run(tc.key+"/"+tc.value, func(t *testing.T) {
			env := environment()
			env[tc.key] = tc.value
			_, err := readConfig(func(k string) string { return env[k] })
			if err == nil || strings.Contains(err.Error(), "canary") {
				t.Fatal("invalid config accepted or reflected")
			}
		})
	}
}

func TestTextAndSerializedBodyBounds(t *testing.T) {
	for _, text := range []string{"a", strings.Repeat("a", 16384), strings.Repeat("é", 8192), "line\n\t\r"} {
		body, err := postBody(text)
		var decoded map[string]string
		if err != nil || json.Unmarshal(body, &decoded) != nil || len(decoded) != 1 || decoded["text"] != text {
			t.Fatal("valid bounded text was changed or refused")
		}
	}
	for _, text := range []string{"", "a\x00b", string([]byte{0xff}), strings.Repeat("a", 16385), strings.Repeat("é", 8193), strings.Repeat("<", 6000)} {
		if _, err := postBody(text); err == nil {
			t.Fatal("invalid or oversized text/body accepted")
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func response(r *http.Request, code int, body string) *http.Response {
	return &http.Response{StatusCode: code, Header: http.Header{"Content-Type": {"application/json"}},
		Body: io.NopCloser(strings.NewReader(body)), Request: r}
}

func TestActualSDKPostsExactTextOnce(t *testing.T) {
	c := configForTest(t)
	transport := proxyTransport(c, &tls.Config{})
	calls := 0
	client := sdkClient(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "POST" || r.URL.String() != "https://api.x.com/2/tweets" {
			t.Fatal("wrong SDK operation")
		}
		if r.Header.Get("Authorization") != "Bearer serverware-x-post-placeholder-v1" ||
			r.Header.Get("Accept") != "application/json" || r.Header.Get("Content-Type") != "application/json" || len(r.Header) != 3 {
			t.Fatal("SDK headers changed or private credentials leaked")
		}
		if _, ok := r.Context().Deadline(); !ok {
			t.Fatal("missing deadline")
		}
		if proxy, err := transport.Proxy(r); err != nil || proxy.String() != c.proxy.String() {
			t.Fatal("SDK request failed exact transport admission")
		}
		body, err := io.ReadAll(r.Body)
		if err != nil || !bytes.Equal(body, c.body) {
			t.Fatal("post body changed")
		}
		return response(r, 201, `{"data":{"id":"123456789","text":"provider-canary"}}`), nil
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result, err := postText(ctx, client, c.text)
	if err != nil || result != (summary{Status: 201, ID: "123456789"}) || calls != 1 {
		t.Fatal("post not acknowledged exactly once")
	}
	out, err := json.Marshal(result)
	if err != nil || string(out) != `{"status":201,"id":"123456789"}` {
		t.Fatal("result exposed unexpected response data")
	}
	if client.Client.Timeout != 30*time.Second || client.Client.CheckRedirect(nil, nil) != http.ErrUseLastResponse {
		t.Fatal("unbounded client")
	}
}

func TestFailureIsUnknownWithoutRetryOrLeak(t *testing.T) {
	for _, tc := range []struct {
		name string
		code int
		body string
	}{
		{"wrong success", 200, `{"data":{"id":"1"}}`}, {"accepted", 202, `{"data":{"id":"1"}}`},
		{"empty success", 204, ""}, {"redirect", 307, `{"detail":"provider-canary"}`},
		{"forbidden", 403, `{"detail":"provider-canary"}`}, {"withheld", 409, `{"detail":"provider-canary"}`},
		{"rate limited", 429, `{"detail":"provider-canary"}`}, {"server failure", 500, `{"detail":"provider-canary"}`},
		{"bad JSON", 201, "provider-canary"}, {"missing data", 201, `{}`},
		{"missing id", 201, `{"data":{"text":"provider-canary"}}`}, {"invalid id", 201, `{"data":{"id":"provider-canary"}}`},
		{"numeric id", 201, `{"data":{"id":123}}`}, {"null data", 201, `{"data":null}`},
		{"oversized id", 201, `{"data":{"id":"123456789012345678901"}}`},
		{"data and errors", 201, `{"data":{"id":"123"},"errors":[{"detail":"provider-canary"}]}`},
		{"malformed errors", 201, `{"data":{"id":"123"},"errors":{"detail":"provider-canary"}}`},
		{"duplicate errors", 201, `{"data":{"id":"123"},"errors":[{}],"errors":[]}`},
		{"duplicate data", 201, `{"data":null,"data":{"id":"123"}}`},
		{"trailing JSON", 201, `{"data":{"id":"123"}} {"detail":"provider-canary"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			client := sdkClient(roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				resp := response(r, tc.code, tc.body)
				resp.Header.Set("Location", "https://other.example.test/provider-canary")
				return resp, nil
			}))
			_, err := postText(context.Background(), client, "synthetic")
			if err == nil || err.Error() != unknownOutcome || exitCode(err) != 2 || calls != 1 {
				t.Fatal("failure retried or diagnostic was not closed")
			}
		})
	}
}

func TestInvalidTextNeverReachesSDKAndTransportErrorIsUnknown(t *testing.T) {
	calls := 0
	client := sdkClient(roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("transport-provider-canary")
	}))
	for _, text := range []string{"", "\x00", string([]byte{0xff}), strings.Repeat("a", 16385)} {
		if _, err := postText(context.Background(), client, text); err == nil || exitCode(err) != 1 || calls != 0 {
			t.Fatal("invalid text reached transport")
		}
	}
	if _, err := postText(context.Background(), client, "synthetic"); err == nil || err.Error() != unknownOutcome || exitCode(err) != 2 || calls != 1 {
		t.Fatal("transport failure not closed")
	}
}

type trackedBody struct {
	io.Reader
	closed bool
}

func (b *trackedBody) Close() error { b.closed = true; return nil }

func TestResponseGuardPreservesBytesAndClosesBody(t *testing.T) {
	for _, body := range []string{` {"data":{"id":"123"}} `, `{"data":{"id":"123"},"errors":[]}`, `{"data":{"id":"123"},"errors":null}`} {
		original := &trackedBody{Reader: strings.NewReader(body)}
		calls := 0
		g := responseGuard{roundTripFunc(func(r *http.Request) (*http.Response, error) {
			calls++
			resp := response(r, 201, body)
			resp.Body = original
			return resp, nil
		})}
		r, _ := http.NewRequest("POST", "https://api.x.com/2/tweets", nil)
		got, err := g.RoundTrip(r)
		if err != nil || got.StatusCode != 201 || got.Request != r || !original.closed || calls != 1 {
			t.Fatal("response guard changed transport contract")
		}
		raw, err := io.ReadAll(got.Body)
		got.Body.Close()
		if err != nil || string(raw) != body {
			t.Fatal("response guard rewrote SDK input")
		}
		client := sdkClient(roundTripFunc(func(r *http.Request) (*http.Response, error) { return response(r, 201, body), nil }))
		if got, err := postText(context.Background(), client, "synthetic"); err != nil || got.ID != "123" {
			t.Fatal("clean empty-error response refused")
		}
	}
}

func TestResponseGuardBoundsAllStatuses(t *testing.T) {
	for _, status := range []int{201, 400, 409, 500} {
		original := &trackedBody{Reader: strings.NewReader(strings.Repeat(" ", 65537))}
		calls := 0
		client := sdkClient(roundTripFunc(func(r *http.Request) (*http.Response, error) {
			calls++
			resp := response(r, status, "")
			resp.Body = original
			return resp, nil
		}))
		_, err := postText(context.Background(), client, "synthetic")
		if err == nil || err.Error() != unknownOutcome || exitCode(err) != 2 || calls != 1 || !original.closed {
			t.Fatal("oversized response not closed and classified")
		}
	}
}

type failedWriter struct{}

func (failedWriter) Write([]byte) (int, error) { return 0, errors.New("private-output-canary") }

func TestOutcomeExitClassifierAndOutputFailure(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want int
	}{
		{nil, 0}, {errors.New(unknownOutcome), 1}, {&outcomeError{}, 2},
		{fmt.Errorf("wrapped: %w", &outcomeError{}), 2},
	} {
		if exitCode(tc.err) != tc.want {
			t.Fatal("exit classification relied on message text")
		}
	}
	err := writeSummary(failedWriter{}, summary{Status: 201, ID: "123"})
	if exitCode(err) != 2 || strings.Contains(err.Error(), "canary") || !strings.Contains(err.Error(), "acknowledged") {
		t.Fatal("post-output failure not classified safely")
	}
	var out bytes.Buffer
	if err := writeSummary(&out, summary{Status: 201, ID: "123"}); err != nil || out.String() != "{\"status\":201,\"id\":\"123\"}\n" {
		t.Fatal("successful output changed")
	}
}

func TestProxyIsExactAndAuthenticationIsCONNECTOnly(t *testing.T) {
	c := configForTest(t)
	tr := proxyTransport(c, &tls.Config{})
	request := func(method, target string, body []byte) *http.Request {
		r, err := http.NewRequest(method, target, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	r := request("POST", "https://api.x.com/2/tweets", c.body)
	p, err := tr.Proxy(r)
	if err != nil || p.User != nil {
		t.Fatal("explicit proxy not selected")
	}
	headers, err := tr.GetProxyConnectHeader(context.Background(), p, "api.x.com:443")
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte(c.appID+":"+c.proxyToken))
	if err != nil || headers.Get("Proxy-Authorization") != want || len(headers) != 1 || len(r.Header) != 0 {
		t.Fatal("app credentials escaped CONNECT")
	}
	for _, target := range []string{"api.x.com:80", "other.example.test:443"} {
		if _, err := tr.GetProxyConnectHeader(context.Background(), p, target); err == nil {
			t.Fatal("wrong CONNECT target")
		}
	}
	other, _ := url.Parse("https://other.example.test")
	if _, err := tr.GetProxyConnectHeader(context.Background(), other, "api.x.com:443"); err == nil {
		t.Fatal("wrong proxy")
	}
	for _, target := range []string{"http://api.x.com/2/tweets", "https://api.x.com:444/2/tweets", "https://api.twitter.com/2/tweets", "https://api.x.com/2/users/me", "https://api.x.com/2/tweets?x=1", "https://api.x.com/2/tweets?", "https://api.x.com/2/tweets#f", "https://api.x.com/2/%74weets"} {
		if _, err := tr.Proxy(request("POST", target, c.body)); err == nil {
			t.Fatal("wrong origin/path accepted")
		}
	}
	for _, method := range []string{"GET", "PUT", "DELETE"} {
		if _, err := tr.Proxy(request(method, r.URL.String(), c.body)); err == nil {
			t.Fatal("wrong method")
		}
	}
	for _, body := range [][]byte{nil, []byte(`{"text":"different"}`), bytes.Repeat([]byte("a"), 32769)} {
		if _, err := tr.Proxy(request("POST", r.URL.String(), body)); err == nil {
			t.Fatal("wrong body accepted")
		}
	}
	r.GetBody = nil
	if _, err := tr.Proxy(r); err == nil {
		t.Fatal("unverifiable body accepted")
	}
	if !tr.DisableCompression || !tr.DisableKeepAlives || tr.DialContext != nil || tr.DialTLSContext != nil {
		t.Fatal("transport policy changed")
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
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
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
	template := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
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

func TestEachTLSHopRequiresItsOwnVerifiedRoots(t *testing.T) {
	outer, inner := makeCA(t, "outer"), makeCA(t, "inner")
	roots := x509.NewCertPool()
	roots.AddCert(outer.cert)
	c, err := clientTLS("proxy.example.test", roots, inner.pem)
	if err != nil {
		t.Fatal(err)
	}
	if c.InsecureSkipVerify || c.ServerName != "" || c.MinVersion < tls.VersionTLS12 {
		t.Fatal("TLS weakened")
	}
	for _, tc := range []struct {
		name    string
		ca      testCA
		allowed bool
	}{
		{"proxy.example.test", outer, true}, {xHost, inner, true}, {xHost, outer, false}, {"proxy.example.test", inner, false}, {"other.example.test", outer, false},
	} {
		leaf := makeLeaf(t, tc.ca, tc.name)
		chains, err := leaf.Verify(x509.VerifyOptions{Roots: c.RootCAs, DNSName: tc.name})
		if err != nil {
			t.Fatal(err)
		}
		err = c.VerifyConnection(tls.ConnectionState{ServerName: tc.name, PeerCertificates: []*x509.Certificate{leaf, tc.ca.cert}, VerifiedChains: chains})
		if (err == nil) != tc.allowed {
			t.Fatal("incorrect per-hop root verification")
		}
	}
	if err := c.VerifyConnection(tls.ConnectionState{ServerName: xHost}); err == nil {
		t.Fatal("unverified connection accepted")
	}
	if _, err := clientTLS("proxy.example.test", roots, []byte("bad")); err == nil {
		t.Fatal("invalid PEM accepted")
	}
}
