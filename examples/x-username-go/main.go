// Read one permitted X username with the unmodified community go-twitter SDK.
package main

import (
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

	twitter "github.com/g8rswimmer/go-twitter/v2"
)

const xHost = "api.x.com"
const dummyToken = "serverware-x-placeholder-v1" // Public placeholder, not a credential.

var (
	usernamePattern         = regexp.MustCompile(`^[a-z0-9_]{1,15}$`)
	responseUsernamePattern = regexp.MustCompile(`^[A-Za-z0-9_]{1,15}$`)
	userIDPattern           = regexp.MustCompile(`^[0-9]{1,32}$`)
	uuidPattern             = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	dnsLabel                = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
)

type config struct {
	proxy               *url.URL
	appID, proxyToken   string
	caFile, proxyCAFile string
	username            string
}

func readConfig(getenv func(string) string) (config, error) {
	c := config{
		appID: getenv("SERVERWARE_APP_ID"), proxyToken: getenv("SERVERWARE_PROXY_TOKEN"),
		caFile: getenv("SERVERWARE_CA_FILE"), proxyCAFile: getenv("SERVERWARE_PROXY_CA_FILE"),
		username: getenv("SERVERWARE_X_USERNAME"),
	}
	p, err := url.Parse(getenv("SERVERWARE_PROXY_URL"))
	if err != nil || p.Scheme != "https" || p.Opaque != "" || p.User != nil ||
		p.Host == "" || p.RawQuery != "" || p.ForceQuery || p.Fragment != "" ||
		(p.Path != "" && p.Path != "/") || p.RawPath != "" {
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
			return config{}, errors.New("proxy port must be between 1 and 65535")
		}
	} else if strings.HasSuffix(p.Host, ":") {
		return config{}, errors.New("proxy port must not be empty")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(c.proxyToken)
	if !uuidPattern.MatchString(c.appID) || err != nil || len(decoded) != 32 ||
		base64.RawURLEncoding.EncodeToString(decoded) != c.proxyToken {
		return config{}, errors.New("set the saved application UUID and its issued SERVERWARE_PROXY_TOKEN")
	}
	if c.caFile == "" || !usernamePattern.MatchString(c.username) {
		return config{}, errors.New("set SERVERWARE_CA_FILE and the exact permitted lowercase X username (1-15 letters, digits, or underscores)")
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
		MinVersion: tls.VersionTLS12,
		RootCAs:    combined,
		// net/http uses one config for BOTH TLS hops. Normal verification stays
		// enabled, then each exact hostname is re-verified against its own roots.
		// Leave ServerName empty: net/http sets the actual hostname for each hop.
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
			_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{
				DNSName: cs.ServerName, Roots: roots, Intermediates: intermediates,
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			})
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
			if req.Method != http.MethodGet || req.URL.Scheme != "https" || req.URL.Hostname() != xHost ||
				(req.URL.Port() != "" && req.URL.Port() != "443") || req.URL.User != nil ||
				req.URL.Opaque != "" || (req.Host != "" && req.Host != req.URL.Host) ||
				req.URL.Path != "/2/users/by/username/"+c.username || req.URL.RawPath != "" ||
				req.URL.RawQuery != "" || req.URL.ForceQuery || req.URL.Fragment != "" ||
				(req.Body != nil && req.Body != http.NoBody) || req.ContentLength != 0 {
				return nil, errors.New("only the configured X username HTTPS read is permitted")
			}
			return c.proxy, nil
		},
		GetProxyConnectHeader: func(_ context.Context, proxyURL *url.URL, target string) (http.Header, error) {
			if proxyURL == nil || proxyURL.String() != c.proxy.String() || target != xHost+":443" {
				return nil, errors.New("unexpected proxy CONNECT destination")
			}
			return http.Header{"Proxy-Authorization": {"Basic " +
				base64.StdEncoding.EncodeToString([]byte(c.appID+":"+c.proxyToken))}}, nil
		},
		TLSClientConfig:       tlsConfig,
		DisableCompression:    true,
		DisableKeepAlives:     true,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
	}
}

type dummyAuthorizer struct{}

func (dummyAuthorizer) Add(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+dummyToken)
}

func sdkClient(transport http.RoundTripper) *twitter.Client {
	return &twitter.Client{
		Host:       "https://" + xHost,
		Authorizer: dummyAuthorizer{},
		Client: &http.Client{
			Timeout:       30 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
			Transport:     transport,
		},
	}
}

type summary struct {
	Users int `json:"users"`
}

func lookupUsername(ctx context.Context, client *twitter.Client, username string) (summary, error) {
	if !usernamePattern.MatchString(username) {
		return summary{}, errors.New("invalid X username; no lookup attempted")
	}
	response, err := client.UserNameLookup(ctx, []string{username}, twitter.UserLookupOpts{})
	if err != nil || response == nil || response.Raw == nil || len(response.Raw.Errors) != 0 ||
		len(response.Raw.Users) != 1 || response.Raw.Users[0] == nil ||
		!userIDPattern.MatchString(response.Raw.Users[0].ID) ||
		!responseUsernamePattern.MatchString(response.Raw.Users[0].UserName) ||
		!strings.EqualFold(response.Raw.Users[0].UserName, username) {
		return summary{}, errors.New("X username read failed; inspect Serverware audit records and the saved permission (no automatic retry)")
	}
	return summary{Users: 1}, nil
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
	result, err := lookupUsername(ctx, sdkClient(transport), c.username)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(out).Encode(result); err != nil {
		return errors.New("could not write the user-count summary")
	}
	return nil
}

func main() {
	if err := runCLI(os.Args[1:], os.Getenv, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err.Error()) // Fixed errors only, never SDK/provider response bodies.
		os.Exit(1)
	}
}
