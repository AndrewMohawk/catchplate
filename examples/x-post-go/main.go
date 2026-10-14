// Bounded, single-attempt plain-text posting with the community go-twitter SDK.
// See README.md for the isolated acceptance and live-provider boundary.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	twitter "github.com/g8rswimmer/go-twitter/v2"
)

const (
	xHost            = "api.x.com"
	dummyToken       = "serverware-x-post-placeholder-v1" // Public, never a provider credential.
	maxTextBytes     = 16384
	maxBodyBytes     = 32768
	maxResponseBytes = 65536
	unknownOutcome   = "X post outcome is unknown and it may already exist; inspect Serverware audit records and the X account before any further action; do not retry automatically"
)

// An outcome error means invocation began, not that the provider rejected a
// write. It must never be classified as a safe-to-replay preflight failure.
type outcomeError struct{ acknowledged bool }

func (e *outcomeError) Error() string {
	if e.acknowledged {
		return "X acknowledged the post but the summary could not be written; do not retry"
	}
	return unknownOutcome
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var outcome *outcomeError
	if errors.As(err, &outcome) {
		return 2
	}
	return 1
}

var (
	postIDPattern = regexp.MustCompile(`^[0-9]{1,20}$`)
	uuidPattern   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	dnsLabel      = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
)

type config struct {
	proxy               *url.URL
	appID, proxyToken   string
	caFile, proxyCAFile string
	text                string
	body                []byte
}

func postBody(text string) ([]byte, error) {
	if len(text) < 1 || len(text) > maxTextBytes || !utf8.ValidString(text) || strings.ContainsRune(text, '\x00') {
		return nil, errors.New("post text must contain 1-16384 UTF-8 bytes without NUL; no post attempted")
	}
	body, err := json.Marshal(twitter.CreateTweetRequest{Text: text})
	if err != nil || len(body) > maxBodyBytes {
		return nil, errors.New("encoded post body exceeds 32768 bytes; no post attempted")
	}
	return body, nil
}

func readConfig(getenv func(string) string) (config, error) {
	if getenv("SSL_CERT_FILE") != "" || getenv("SSL_CERT_DIR") != "" {
		return config{}, errors.New("unset SSL_CERT_FILE and SSL_CERT_DIR; use the explicit Serverware CA inputs")
	}
	if getenv("SERVERWARE_X_POST_CONFIRM") != "post-once" {
		return config{}, errors.New("single-post confirmation is required; no post attempted")
	}
	c := config{appID: getenv("SERVERWARE_APP_ID"), proxyToken: getenv("SERVERWARE_PROXY_TOKEN"),
		caFile: getenv("SERVERWARE_CA_FILE"), proxyCAFile: getenv("SERVERWARE_PROXY_CA_FILE"),
		text: getenv("SERVERWARE_X_POST_TEXT")}
	p, err := url.Parse(getenv("SERVERWARE_PROXY_URL"))
	if err != nil || p.Scheme != "https" || p.Opaque != "" || p.User != nil || p.Host == "" ||
		p.RawQuery != "" || p.ForceQuery || p.Fragment != "" || (p.Path != "" && p.Path != "/") || p.RawPath != "" {
		return config{}, errors.New("SERVERWARE_PROXY_URL must be an HTTPS origin without credentials, query, or fragment")
	}
	host := p.Hostname()
	if host == xHost || net.ParseIP(host) != nil || len(host) > 253 || !strings.Contains(host, ".") {
		return config{}, errors.New("proxy must have a distinct DNS hostname")
	}
	for _, label := range strings.Split(host, ".") {
		if !dnsLabel.MatchString(label) {
			return config{}, errors.New("proxy must have a lowercase DNS hostname")
		}
	}
	if port := p.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return config{}, errors.New("invalid proxy port")
		}
	} else if strings.HasSuffix(p.Host, ":") {
		return config{}, errors.New("invalid proxy port")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(c.proxyToken)
	if !uuidPattern.MatchString(c.appID) || err != nil || len(decoded) != 32 ||
		base64.RawURLEncoding.EncodeToString(decoded) != c.proxyToken {
		return config{}, errors.New("set the saved application UUID and its issued SERVERWARE_PROXY_TOKEN")
	}
	if c.caFile == "" {
		return config{}, errors.New("set SERVERWARE_CA_FILE")
	}
	c.body, err = postBody(c.text)
	if err != nil {
		return config{}, err
	}
	p.Path = ""
	c.proxy = p
	return c, nil
}

func readCAFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("could not open a configured CA file")
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 1048577))
	if err != nil || len(b) == 0 || len(b) > 1048576 {
		return nil, errors.New("configured CA file must contain at most 1 MiB of PEM certificates")
	}
	return b, nil
}

func clientTLS(proxyHost string, proxyRoots *x509.CertPool, innerPEM []byte) (*tls.Config, error) {
	innerRoots := x509.NewCertPool()
	if proxyRoots == nil || !innerRoots.AppendCertsFromPEM(innerPEM) {
		return nil, errors.New("configured Serverware CA file is not a PEM certificate bundle")
	}
	outerRoots := proxyRoots.Clone()
	combined := outerRoots.Clone()
	combined.AppendCertsFromPEM(innerPEM)
	return &tls.Config{
		MinVersion: tls.VersionTLS12, RootCAs: combined,
		// net/http shares this config across both TLS hops. Normal verification
		// stays enabled, followed by verification against each hop's own roots.
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 || len(cs.VerifiedChains) == 0 {
				return errors.New("TLS peer did not pass normal certificate verification")
			}
			var roots *x509.CertPool
			switch cs.ServerName {
			case proxyHost:
				roots = outerRoots
			case xHost:
				roots = innerRoots
			default:
				return errors.New("unexpected TLS peer hostname")
			}
			intermediates := x509.NewCertPool()
			for _, cert := range cs.PeerCertificates[1:] {
				intermediates.AddCert(cert)
			}
			_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{DNSName: cs.ServerName,
				Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
			if err != nil {
				return errors.New("TLS certificate does not match the expected hop and CA")
			}
			return nil
		},
	}, nil
}

func proxyTransport(c config, tlsConfig *tls.Config) *http.Transport {
	return &http.Transport{
		Proxy: func(req *http.Request) (*url.URL, error) {
			if req.Method != http.MethodPost || req.URL.Scheme != "https" || req.URL.Hostname() != xHost ||
				(req.URL.Port() != "" && req.URL.Port() != "443") || req.URL.User != nil || req.URL.Opaque != "" ||
				(req.Host != "" && req.Host != req.URL.Host) || req.URL.Path != "/2/tweets" || req.URL.RawPath != "" ||
				req.URL.RawQuery != "" || req.URL.ForceQuery || req.URL.Fragment != "" || req.Body == nil ||
				req.ContentLength != int64(len(c.body)) || req.ContentLength < 1 || req.GetBody == nil {
				return nil, errors.New("only the configured bounded X text POST is permitted")
			}
			// Inspect the SDK's replayable body without changing the transmitted body.
			copyBody, err := req.GetBody()
			if err != nil {
				return nil, errors.New("could not verify the SDK post body")
			}
			defer copyBody.Close()
			body, err := io.ReadAll(io.LimitReader(copyBody, maxBodyBytes+1))
			if err != nil || !bytes.Equal(body, c.body) {
				return nil, errors.New("unexpected SDK post body")
			}
			return c.proxy, nil
		},
		GetProxyConnectHeader: func(_ context.Context, proxyURL *url.URL, target string) (http.Header, error) {
			if proxyURL == nil || proxyURL.String() != c.proxy.String() || target != xHost+":443" {
				return nil, errors.New("unexpected proxy CONNECT destination")
			}
			return http.Header{"Proxy-Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte(c.appID+":"+c.proxyToken))}}, nil
		},
		TLSClientConfig: tlsConfig, DisableCompression: true, DisableKeepAlives: true,
		TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 20 * time.Second,
	}
}

type dummyAuthorizer struct{}

func (dummyAuthorizer) Add(req *http.Request) { req.Header.Set("Authorization", "Bearer "+dummyToken) }

// The pinned SDK omits the API's optional errors field from CreateTweetResponse.
// Inspect a bounded response before the SDK decodes the identical original
// bytes, so data plus errors cannot be mistaken for a confirmed clean result.
type responseGuard struct{ transport http.RoundTripper }

func (g responseGuard) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := g.transport.RoundTrip(req)
	if err != nil || resp == nil || resp.Body == nil {
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
		return nil, errors.New("X response was not available")
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	closeErr := resp.Body.Close()
	if readErr != nil || closeErr != nil || len(body) > maxResponseBytes ||
		(resp.StatusCode == http.StatusCreated && !unambiguousSuccess(body)) {
		return nil, errors.New("X response was oversized, unreadable or ambiguous")
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	return resp, nil
}

func unambiguousSuccess(body []byte) bool {
	d := json.NewDecoder(bytes.NewReader(body))
	opening, err := d.Token()
	if err != nil || opening != json.Delim('{') {
		return false
	}
	seen := make(map[string]bool)
	for d.More() {
		key, err := d.Token()
		name, ok := key.(string)
		if err != nil || !ok || seen[name] {
			return false
		}
		seen[name] = true
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return false
		}
		if name == "errors" {
			var entries []json.RawMessage
			if json.Unmarshal(value, &entries) != nil || len(entries) != 0 {
				return false
			}
		}
	}
	closing, err := d.Token()
	if err != nil || closing != json.Delim('}') {
		return false
	}
	_, err = d.Token()
	return err == io.EOF
}

func sdkClient(transport http.RoundTripper) *twitter.Client {
	return &twitter.Client{Host: "https://" + xHost, Authorizer: dummyAuthorizer{},
		Client: &http.Client{Timeout: 30 * time.Second, Transport: responseGuard{transport},
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}}
}

type summary struct {
	Status int    `json:"status"`
	ID     string `json:"id"`
}

func postText(ctx context.Context, client *twitter.Client, text string) (summary, error) {
	if _, err := postBody(text); err != nil {
		return summary{}, err
	}
	// One SDK invocation. A timeout, malformed response, withheld 409 or other
	// failure cannot establish that the provider did not create the post.
	result, err := client.CreateTweet(ctx, twitter.CreateTweetRequest{Text: text})
	if err != nil || result == nil || result.Tweet == nil || !postIDPattern.MatchString(result.Tweet.ID) {
		return summary{}, &outcomeError{}
	}
	return summary{Status: http.StatusCreated, ID: result.Tweet.ID}, nil
}

func run(getenv func(string) string, out io.Writer) error {
	c, err := readConfig(getenv)
	if err != nil {
		return err
	}
	innerPEM, err := readCAFile(c.caFile)
	if err != nil {
		return err
	}
	outerRoots, err := x509.SystemCertPool()
	if err != nil {
		return errors.New("could not load system trust roots")
	}
	if c.proxyCAFile != "" {
		outerPEM, err := readCAFile(c.proxyCAFile)
		if err != nil {
			return err
		}
		if !outerRoots.AppendCertsFromPEM(outerPEM) {
			return errors.New("configured proxy CA file is not a PEM certificate bundle")
		}
	}
	tlsConfig, err := clientTLS(c.proxy.Hostname(), outerRoots, innerPEM)
	if err != nil {
		return err
	}
	transport := proxyTransport(c, tlsConfig)
	defer transport.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result, err := postText(ctx, sdkClient(transport), c.text)
	if err != nil {
		return err
	}
	return writeSummary(out, result)
}

func writeSummary(out io.Writer, result summary) error {
	if err := json.NewEncoder(out).Encode(result); err != nil {
		return &outcomeError{acknowledged: true}
	}
	return nil
}

func main() {
	if err := runCLI(os.Args[1:], os.Getenv, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err.Error()) // Fixed messages only; never SDK errors, text or tokens.
		os.Exit(exitCode(err))
	}
}
