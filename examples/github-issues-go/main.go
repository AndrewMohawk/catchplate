// Read-only, exact-repository example using the unmodified go-github SDK.
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

	"github.com/google/go-github/v74/github"
	"golang.org/x/oauth2"
)

const githubHost = "api.github.com"
const dummyToken = "serverware-github-placeholder-v1" // Public placeholder, not a credential.
const maxPages = 100

var (
	ownerPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$`)
	repoPattern  = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}$`)
	uuidPattern  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	dnsLabel     = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
)

type config struct {
	proxy               *url.URL
	appID, proxyToken   string
	caFile, proxyCAFile string
	owner, repo         string
}

func readConfig(getenv func(string) string) (config, error) {
	c := config{
		appID: getenv("SERVERWARE_APP_ID"), proxyToken: getenv("SERVERWARE_PROXY_TOKEN"),
		caFile: getenv("SERVERWARE_CA_FILE"), proxyCAFile: getenv("SERVERWARE_PROXY_CA_FILE"),
		owner: getenv("SERVERWARE_GITHUB_OWNER"), repo: getenv("SERVERWARE_GITHUB_REPO"),
	}
	p, err := url.Parse(getenv("SERVERWARE_PROXY_URL"))
	if err != nil || p.Scheme != "https" || p.Opaque != "" || p.User != nil ||
		p.Host == "" || p.RawQuery != "" || p.ForceQuery || p.Fragment != "" ||
		(p.Path != "" && p.Path != "/") || p.RawPath != "" {
		return config{}, errors.New("SERVERWARE_PROXY_URL must be an HTTPS origin without credentials, query, or fragment")
	}
	// Exact DNS names let the TLS callback distinguish the proxy from GitHub.
	host := p.Hostname()
	if host == githubHost || net.ParseIP(host) != nil || len(host) > 253 || !strings.Contains(host, ".") {
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
	if c.caFile == "" || !ownerPattern.MatchString(c.owner) || !repoPattern.MatchString(c.repo) ||
		c.repo == "." || c.repo == ".." {
		return config{}, errors.New("set SERVERWARE_CA_FILE and the exact permitted GitHub owner and repository")
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
		// net/http uses this config for BOTH TLS hops. Normal verification remains
		// enabled; additionally re-verify against only the roots for this exact
		// hostname. A certificate trusted for one hop is not trusted for the other.
		// Leave ServerName empty so net/http sets the actual hostname per hop.
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 || len(cs.VerifiedChains) == 0 {
				return errors.New("TLS peer did not pass normal certificate verification")
			}
			var roots *x509.CertPool
			switch cs.ServerName {
			case proxyHost:
				roots = outerRoots
			case githubHost:
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
			if req.URL.Scheme != "https" || req.URL.Hostname() != githubHost ||
				(req.URL.Port() != "" && req.URL.Port() != "443") || req.URL.User != nil {
				return nil, errors.New("only the GitHub HTTPS origin is permitted")
			}
			return c.proxy, nil
		},
		GetProxyConnectHeader: func(_ context.Context, proxyURL *url.URL, target string) (http.Header, error) {
			if proxyURL == nil || proxyURL.String() != c.proxy.String() || target != githubHost+":443" {
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

func sdkClient(transport http.RoundTripper) *github.Client {
	return github.NewClient(&http.Client{
		Timeout:       30 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &oauth2.Transport{
			Base:   transport,
			Source: oauth2.StaticTokenSource(&oauth2.Token{TokenType: "token", AccessToken: dummyToken}),
		},
	})
}

type summary struct {
	Pages        int `json:"pages"`
	Issues       int `json:"issues"`
	PullRequests int `json:"pull_requests"`
}

func listIssues(ctx context.Context, client *github.Client, owner, repo string, pageLimit int) (summary, error) {
	var result summary
	options := &github.IssueListByRepoOptions{
		State: "open", ListOptions: github.ListOptions{Page: 1, PerPage: 100},
	}
	for result.Pages < pageLimit {
		issues, response, err := client.Issues.ListByRepo(ctx, owner, repo, options)
		if err != nil || response == nil || response.StatusCode != http.StatusOK {
			return summary{}, errors.New("GitHub issue read failed; inspect Serverware audit records and the saved permission (no automatic retry)")
		}
		result.Pages++
		for _, issue := range issues {
			if issue == nil {
				return summary{}, errors.New("unexpected GitHub issue response")
			}
			if issue.IsPullRequest() {
				result.PullRequests++
			} else {
				result.Issues++
			}
		}
		if response.NextPage == 0 {
			return result, nil
		}
		if response.NextPage <= options.ListOptions.Page || response.NextPage > 1000000 {
			return summary{}, errors.New("unexpected GitHub pagination; no request repeated")
		}
		// Use the SDK's parsed page number, never a response-provided URL.
		options.ListOptions.Page = response.NextPage
	}
	return summary{}, errors.New("read stopped at the page limit; no automatic continuation")
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
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	result, err := listIssues(ctx, sdkClient(transport), c.owner, c.repo, maxPages)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(out).Encode(result); err != nil {
		return errors.New("could not write the issue-count summary")
	}
	return nil
}

func main() {
	if err := run(os.Getenv, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err.Error()) // Only fixed errors; never raw SDK/provider responses.
		os.Exit(1)
	}
}
