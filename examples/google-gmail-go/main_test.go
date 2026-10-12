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

	"google.golang.org/api/gmail/v1"
)

func environment() map[string]string {
	return map[string]string{
		"SERVERWARE_PROXY_URL":           "https://proxy.example.test:8443",
		"SERVERWARE_APP_ID":              "11111111-1111-4111-8111-111111111111",
		"SERVERWARE_PROXY_TOKEN":         base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)),
		"SERVERWARE_CA_FILE":             "/synthetic/serverware-ca.pem",
		"GOOGLE_APPLICATION_CREDENTIALS": "/must-not-be-read/credentials.json",
		"HTTPS_PROXY":                    "http://must-not-be-used.invalid", "NO_PROXY": "*",
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

func TestConfigRequiresExplicitInputs(t *testing.T) {
	if configForTest(t).proxy.User != nil {
		t.Fatal("application credentials entered a URL")
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
		{"SERVERWARE_PROXY_URL", "https://gmail.googleapis.com"},
		{"SERVERWARE_PROXY_URL", "https://127.0.0.1"},
		{"SERVERWARE_PROXY_URL", "https://[::1]"},
		{"SERVERWARE_PROXY_URL", "https://Proxy.example.test"},
		{"SERVERWARE_APP_ID", "invalid"},
		{"SERVERWARE_PROXY_TOKEN", "not-an-issued-app-token"},
		{"SERVERWARE_CA_FILE", ""},
		{"GOOGLE_API_USE_CLIENT_CERTIFICATE", "TRUE"},
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

func TestProxyAuthenticationOnlyForExactConnect(t *testing.T) {
	c := configForTest(t)
	transport := proxyTransport(c, &tls.Config{})
	request, _ := http.NewRequest("GET", "https://"+gmailHost+"/gmail/v1/users/me/messages", nil)
	p, err := transport.Proxy(request)
	if err != nil || p.String() != c.proxy.String() || p.User != nil {
		t.Fatal("explicit proxy selection failed")
	}
	headers, err := transport.GetProxyConnectHeader(context.Background(), p, gmailHost+":443")
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte(c.appID+":"+c.proxyToken))
	if err != nil || len(headers) != 1 || headers.Get("Proxy-Authorization") != want || len(request.Header) != 0 {
		t.Fatal("CONNECT authentication separation failed")
	}
	other, _ := url.Parse("https://other.example.test")
	for _, target := range []string{"other.example.test:443", gmailHost + ":80"} {
		if _, err := transport.GetProxyConnectHeader(context.Background(), p, target); err == nil {
			t.Fatal("wrong CONNECT target accepted")
		}
	}
	if _, err := transport.GetProxyConnectHeader(context.Background(), other, gmailHost+":443"); err == nil {
		t.Fatal("wrong proxy accepted")
	}
	for _, target := range []string{"http://" + gmailHost, "https://" + gmailHost + ":444", "https://other.example.test", "https://user@" + gmailHost} {
		request, _ := http.NewRequest("GET", target, nil)
		if _, err := transport.Proxy(request); err == nil {
			t.Fatal("non-Gmail destination accepted")
		}
	}
	if !transport.DisableCompression || !transport.DisableKeepAlives ||
		transport.TLSHandshakeTimeout != 10*time.Second || transport.ResponseHeaderTimeout != 20*time.Second {
		t.Fatal("transport bounds changed")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func response(r *http.Request, status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}},
		Body: io.NopCloser(strings.NewReader(body)), Request: r}
}

func clientForTest(t *testing.T, send roundTripFunc) *gmail.Service {
	t.Helper()
	// Explicitly hostile ambient provider configuration must not trigger ADC.
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "/must-not-be-read/credentials.json")
	t.Setenv("GOOGLE_API_USE_CLIENT_CERTIFICATE", "false")
	t.Setenv("GOOGLE_API_USE_MTLS_ENDPOINT", "always")
	t.Setenv("GOOGLE_SDK_GO_LOGGING_LEVEL", "debug")
	client, err := sdkClient(context.Background(), send)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestStockSDKListPaginationAndMetadataSerialization(t *testing.T) {
	paths := []string{
		"/gmail/v1/users/me/messages?alt=json&labelIds=INBOX&maxResults=5&prettyPrint=false",
		"/gmail/v1/users/me/messages/msg_1?alt=json&format=metadata&metadataHeaders=From&metadataHeaders=Subject&metadataHeaders=Date&prettyPrint=false",
		"/gmail/v1/users/me/messages?alt=json&labelIds=INBOX&maxResults=5&pageToken=next%2Bpage+%2F%3D&prettyPrint=false",
		"/gmail/v1/users/me/messages/msg-2?alt=json&format=metadata&metadataHeaders=From&metadataHeaders=Subject&metadataHeaders=Date&prettyPrint=false",
	}
	bodies := []string{
		`{"messages":[{"id":"msg_1"}],"nextPageToken":"next+page /="}`,
		`{"id":"msg_1","payload":{"headers":[{"name":"Subject","value":"private mail subject"}]}}`,
		`{"messages":[{"id":"msg-2"}]}`, `{"id":"msg-2"}`,
	}
	calls := 0
	client := clientForTest(t, func(r *http.Request) (*http.Response, error) {
		if calls >= len(paths) || r.Method != "GET" || r.URL.Scheme != "https" ||
			r.URL.Host != gmailHost || r.URL.RequestURI() != paths[calls] || r.Body != nil || r.URL.User != nil {
			t.Fatal("stock SDK request shape changed")
		}
		if r.Header.Get("Authorization") != "Bearer "+dummyToken || r.Header.Get("Proxy-Authorization") != "" ||
			r.Header.Get("User-Agent") == "" || !strings.Contains(r.Header.Get("X-Goog-Api-Client"), "gdcl/0.264.0") {
			t.Fatal("stock SDK authentication/header contract changed")
		}
		for key := range r.Header {
			if key != "Authorization" && key != "User-Agent" && key != "X-Goog-Api-Client" {
				t.Fatal("unreviewed stock SDK request header")
			}
		}
		body := bodies[calls]
		calls++
		return response(r, 200, body), nil
	})
	got, err := readMailbox(context.Background(), client)
	if err != nil || got != (summary{Pages: 2, MessagesRead: 2}) || calls != 4 {
		t.Fatal("bounded stock SDK sequence failed")
	}
}

func TestBoundedSampleNeverAutomaticallyContinues(t *testing.T) {
	calls := 0
	client := clientForTest(t, func(r *http.Request) (*http.Response, error) {
		calls++
		return response(r, 200, `{"messages":[],"nextPageToken":"page`+string(rune('0'+calls))+`"}`), nil
	})
	got, err := readMailbox(context.Background(), client)
	if err != nil || got != (summary{Pages: maxPages, MorePages: true}) || calls != maxPages {
		t.Fatal("page limit or honest more-pages marker failed")
	}
}

func TestUnsafeListNeverCreatesDetailRequest(t *testing.T) {
	for _, body := range []string{
		`{"messages":[null]}`, `{"messages":[{"id":"../other"}]}`,
		`{"messages":[{"id":"a"},{"id":"a"}]}`,
		`{"messages":[{"id":"1"},{"id":"2"},{"id":"3"},{"id":"4"},{"id":"5"},{"id":"6"}]}`,
		`{"nextPageToken":"bad\nvalue"}`,
	} {
		t.Run(body, func(t *testing.T) {
			calls := 0
			client := clientForTest(t, func(r *http.Request) (*http.Response, error) {
				calls++
				return response(r, 200, body), nil
			})
			if _, err := readMailbox(context.Background(), client); err == nil || calls != 1 {
				t.Fatal("unsafe list followed or retried")
			}
		})
	}
	if validPageToken(strings.Repeat("a", 4097)) || validPageToken("\\") || validPageToken(string([]byte{255})) {
		t.Fatal("invalid cursor accepted")
	}
}

func TestRepeatedCursorAndMismatchedDetailRefuse(t *testing.T) {
	for _, repeated := range []bool{true, false} {
		calls := 0
		client := clientForTest(t, func(r *http.Request) (*http.Response, error) {
			calls++
			body := `{"nextPageToken":"same"}`
			if !repeated {
				body = `{"messages":[{"id":"allowed"}]}`
				if calls == 2 {
					body = `{"id":"different"}`
				}
			}
			return response(r, 200, body), nil
		})
		if _, err := readMailbox(context.Background(), client); err == nil || calls != 2 {
			t.Fatal("repeated cursor or mismatched detail accepted")
		}
	}
}

func TestFailuresDoNotRetryOrExposeRawDetails(t *testing.T) {
	for _, status := range []int{401, 403, 429, 503, 302} {
		calls := 0
		client := clientForTest(t, func(r *http.Request) (*http.Response, error) {
			calls++
			rsp := response(r, status, `{"error":{"message":"private-provider-detail","code":403}}`)
			rsp.Header.Set("Location", "https://elsewhere.invalid/private")
			return rsp, nil
		})
		_, err := readMailbox(context.Background(), client)
		if err == nil || strings.Contains(err.Error(), "private-provider-detail") || calls != 1 {
			t.Fatal("provider refusal exposed, retried or redirected")
		}
	}
	calls := 0
	client := clientForTest(t, func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("private-transport-detail")
	})
	_, err := readMailbox(context.Background(), client)
	if err == nil || strings.Contains(err.Error(), "private-transport-detail") || calls != 1 {
		t.Fatal("transport error exposed or retried")
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

func TestTLSRequiresIndependentTrustForBothHops(t *testing.T) {
	outer, inner := makeCA(t, "synthetic outer"), makeCA(t, "synthetic inner")
	roots := x509.NewCertPool()
	roots.AddCert(outer.cert)
	tlsConfig, err := clientTLS("proxy.example.test", roots, inner.pem)
	if err != nil {
		t.Fatal(err)
	}
	if tlsConfig.InsecureSkipVerify || tlsConfig.ServerName != "" || tlsConfig.MinVersion < tls.VersionTLS12 {
		t.Fatal("ordinary TLS verification weakened")
	}
	for _, tc := range []struct {
		host    string
		ca      testCA
		allowed bool
	}{
		{"proxy.example.test", outer, true}, {gmailHost, inner, true},
		{"proxy.example.test", inner, false}, {gmailHost, outer, false},
		{"other.example.test", outer, false},
	} {
		leaf := makeLeaf(t, tc.ca, tc.host)
		chains, err := leaf.Verify(x509.VerifyOptions{Roots: tlsConfig.RootCAs, DNSName: tc.host})
		if err != nil {
			t.Fatal(err)
		}
		err = tlsConfig.VerifyConnection(tls.ConnectionState{ServerName: tc.host,
			PeerCertificates: []*x509.Certificate{leaf, tc.ca.cert}, VerifiedChains: chains})
		if (err == nil) != tc.allowed {
			t.Fatal("wrong per-hop trust result")
		}
	}
	if tlsConfig.VerifyConnection(tls.ConnectionState{}) == nil {
		t.Fatal("missing normal verification accepted")
	}
}
