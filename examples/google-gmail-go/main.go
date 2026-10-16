// Bounded, read-only Gmail example using the unmodified official Google SDK.
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
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/oauth2"
	"google.golang.org/api/gmail/v1"
	"google.golang.org/api/option"
)

const (
	gmailHost  = "gmail.googleapis.com"
	dummyToken = "serverware-gmail-placeholder-v1" // Public, not a Google credential.
	pageSize   = 5
	maxPages   = 2
)

var (
	uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	dnsLabel    = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	messageID   = regexp.MustCompile(`^[A-Za-z0-9_-]{1,512}$`)
)

type config struct {
	proxy               *url.URL
	appID, proxyToken   string
	caFile, proxyCAFile string
	maxAgeDays          int
}

func readConfig(getenv func(string) string) (config, error) {
	c := config{appID: getenv("SERVERWARE_APP_ID"), proxyToken: getenv("SERVERWARE_PROXY_TOKEN"),
		caFile: getenv("SERVERWARE_CA_FILE"), proxyCAFile: getenv("SERVERWARE_PROXY_CA_FILE")}
	if value := getenv("SERVERWARE_GMAIL_MAX_AGE_DAYS"); value != "" {
		days, err := strconv.Atoi(value)
		if err != nil || days < 1 || days > 3650 || strconv.Itoa(days) != value {
			return config{}, errors.New("invalid Gmail age hint")
		}
		c.maxAgeDays = days
	}
	// Google checks this setting before honoring WithHTTPClient. Refuse ambient
	// client-certificate discovery rather than inspecting local Google key files.
	if strings.EqualFold(getenv("GOOGLE_API_USE_CLIENT_CERTIFICATE"), "true") {
		return config{}, errors.New("unset GOOGLE_API_USE_CLIENT_CERTIFICATE for this example")
	}
	p, err := url.Parse(getenv("SERVERWARE_PROXY_URL"))
	if err != nil || p.Scheme != "https" || p.Opaque != "" || p.User != nil ||
		p.Host == "" || p.RawQuery != "" || p.ForceQuery || p.Fragment != "" ||
		(p.Path != "" && p.Path != "/") || p.RawPath != "" {
		return config{}, errors.New("SERVERWARE_PROXY_URL must be an HTTPS origin without credentials, query, or fragment")
	}
	host := p.Hostname()
	if host == gmailHost || net.ParseIP(host) != nil || len(host) > 253 || !strings.Contains(host, ".") {
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
		base64.RawURLEncoding.EncodeToString(decoded) != c.proxyToken || c.caFile == "" {
		return config{}, errors.New("set the saved application UUID, issued SERVERWARE_PROXY_TOKEN, and SERVERWARE_CA_FILE")
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
		// The standard transport uses this config for both TLS hops. Keep normal
		// verification enabled, then additionally verify the exact hop's roots.
		// ServerName stays empty: net/http sets the actual hostname per hop.
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 || len(cs.VerifiedChains) == 0 {
				return errors.New("TLS peer did not pass normal certificate verification")
			}
			var roots *x509.CertPool
			switch cs.ServerName {
			case proxyHost:
				roots = outerRoots
			case gmailHost:
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
			if req.URL.Scheme != "https" || req.URL.Hostname() != gmailHost ||
				(req.URL.Port() != "" && req.URL.Port() != "443") || req.URL.User != nil {
				return nil, errors.New("only the Gmail HTTPS origin is permitted")
			}
			return c.proxy, nil // Never ProxyFromEnvironment or a direct fallback.
		},
		GetProxyConnectHeader: func(_ context.Context, proxyURL *url.URL, target string) (http.Header, error) {
			if proxyURL == nil || proxyURL.String() != c.proxy.String() || target != gmailHost+":443" {
				return nil, errors.New("unexpected proxy CONNECT destination")
			}
			return http.Header{"Proxy-Authorization": {"Basic " +
				base64.StdEncoding.EncodeToString([]byte(c.appID+":"+c.proxyToken))}}, nil
		},
		TLSClientConfig: tlsConfig, DisableCompression: true, DisableKeepAlives: true,
		TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 20 * time.Second,
	}
}

func sdkClient(ctx context.Context, transport http.RoundTripper) (*gmail.Service, error) {
	client := &http.Client{
		Timeout:       30 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &oauth2.Transport{Base: transport,
			Source: oauth2.StaticTokenSource(&oauth2.Token{TokenType: "Bearer", AccessToken: dummyToken})},
	}
	service, err := gmail.NewService(ctx, option.WithHTTPClient(client),
		option.WithEndpoint("https://"+gmailHost+"/"),
		option.WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))))
	if err != nil {
		return nil, errors.New("could not initialize the Gmail client")
	}
	return service, nil
}

type summary struct {
	Pages        int  `json:"pages"`
	MessagesRead int  `json:"messages_read"`
	MorePages    bool `json:"more_pages"`
}

func validPageToken(token string) bool {
	if len(token) > 4096 || !utf8.ValidString(token) {
		return false
	}
	for _, r := range token {
		if r < 32 || (r >= 127 && r <= 159) || r == '\\' {
			return false
		}
	}
	return true
}

func sampleQuery(days int, now time.Time) (string, error) {
	if days < 0 || days > 3650 || now.UnixMilli() <= 0 || now.UnixMilli() > 9007199254740991 {
		return "", errors.New("invalid Gmail age hint or sample time")
	}
	if days == 0 {
		return "", nil
	}
	cutoff := now.UnixMilli() - int64(days)*86400000
	seconds := cutoff / 1000
	if cutoff%1000 > 0 {
		seconds++ // Integer ceil, including dates before the Unix epoch.
	}
	return "after:" + strconv.FormatInt(seconds, 10), nil
}

func readMailbox(ctx context.Context, client *gmail.Service) (summary, error) {
	return readMailboxQuery(ctx, client, "")
}

func readMailboxQuery(ctx context.Context, client *gmail.Service, query string) (summary, error) {
	var result summary
	seenIDs, seenPages := map[string]bool{}, map[string]bool{}
	page := ""
	for result.Pages < maxPages {
		call := client.Users.Messages.List("me").MaxResults(pageSize).LabelIds("INBOX").Context(ctx)
		if query != "" {
			call.Q(query)
		}
		if page != "" {
			call.PageToken(page)
		}
		listed, err := call.Do()
		if err != nil || listed == nil || listed.HTTPStatusCode != http.StatusOK {
			return summary{}, errors.New("Gmail list failed; inspect Serverware audit records and the saved permission (no automatic retry)")
		}
		if len(listed.Messages) > pageSize || !validPageToken(listed.NextPageToken) ||
			(listed.NextPageToken != "" && seenPages[listed.NextPageToken]) {
			return summary{}, errors.New("unexpected Gmail list or pagination response")
		}
		// Validate the entire page before reading details. Never take message IDs
		// or URLs from environment variables or follow a provider-supplied URL.
		for _, item := range listed.Messages {
			if item == nil || !messageID.MatchString(item.Id) || seenIDs[item.Id] {
				return summary{}, errors.New("unexpected Gmail message identity")
			}
			seenIDs[item.Id] = true
		}
		result.Pages++
		for _, item := range listed.Messages {
			detail, err := client.Users.Messages.Get("me", item.Id).Format("metadata").
				MetadataHeaders("From", "Subject", "Date").Context(ctx).Do()
			if err != nil || detail == nil || detail.HTTPStatusCode != http.StatusOK || detail.Id != item.Id {
				return summary{}, errors.New("Gmail metadata read failed; no automatic retry")
			}
			result.MessagesRead++ // Do not print mail headers, IDs, snippets or bodies.
		}
		result.MorePages = listed.NextPageToken != ""
		if !result.MorePages {
			return result, nil
		}
		page = listed.NextPageToken
		seenPages[page] = true
	}
	return result, nil // Explicit bounded sample, not a complete-mailbox claim.
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
	client, err := sdkClient(ctx, transport)
	if err != nil {
		return err
	}
	query, err := sampleQuery(c.maxAgeDays, time.Now())
	if err != nil {
		return err
	}
	result, err := readMailboxQuery(ctx, client, query)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(out).Encode(result); err != nil {
		return errors.New("could not write the message-count summary")
	}
	return nil
}

func main() {
	getenv, err := configurationEnvironment(os.Args[1:], os.Getenv, time.Now())
	if err == nil && len(os.Args) > 1 {
		err = replaceConfigurationEnvironment(getenv)
	}
	if err == nil {
		err = run(getenv, os.Stdout)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error()) // Only fixed errors, never SDK responses.
		os.Exit(1)
	}
}
