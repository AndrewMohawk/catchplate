// Read chain ID and block height with the ordinary go-ethereum RPC client.
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

	"github.com/ethereum/go-ethereum/rpc"
)

const dummyToken = "catchplate-alchemy-placeholder-v1" // Public placeholder, not a credential.

var (
	uuidPattern     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	dnsLabel        = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	quantityPattern = regexp.MustCompile(`^0x(?:0|[1-9a-f][0-9a-f]{0,15})$`)
)

type config struct {
	proxy               *url.URL
	appID, proxyToken   string
	caFile, proxyCAFile string
	chain, providerHost string
}

func selectChain(chain string) (host, id string, err error) {
	switch chain {
	case "eth-mainnet":
		return "eth-mainnet.g.alchemy.com", "0x1", nil
	case "eth-sepolia":
		return "eth-sepolia.g.alchemy.com", "0xaa36a7", nil
	default:
		return "", "", errors.New("CATCHPLATE_ALCHEMY_CHAIN must be eth-mainnet or eth-sepolia")
	}
}

func readConfig(getenv func(string) string) (config, error) {
	if getenv("SSL_CERT_FILE") != "" || getenv("SSL_CERT_DIR") != "" {
		return config{}, errors.New("unset SSL_CERT_FILE and SSL_CERT_DIR; use CATCHPLATE_PROXY_CA_FILE for an explicit outer proxy CA")
	}
	c := config{
		appID: getenv("CATCHPLATE_APP_ID"), proxyToken: getenv("CATCHPLATE_PROXY_TOKEN"),
		caFile: getenv("CATCHPLATE_CA_FILE"), proxyCAFile: getenv("CATCHPLATE_PROXY_CA_FILE"),
		chain: getenv("CATCHPLATE_ALCHEMY_CHAIN"),
	}
	var err error
	c.providerHost, _, err = selectChain(c.chain)
	if err != nil {
		return config{}, err
	}
	p, err := url.Parse(getenv("CATCHPLATE_PROXY_URL"))
	if err != nil || p.Scheme != "https" || p.Opaque != "" || p.User != nil ||
		p.Host == "" || p.RawQuery != "" || p.ForceQuery || p.Fragment != "" ||
		(p.Path != "" && p.Path != "/") || p.RawPath != "" {
		return config{}, errors.New("CATCHPLATE_PROXY_URL must be an HTTPS origin without credentials, query, or fragment")
	}
	host := p.Hostname()
	if host == "eth-mainnet.g.alchemy.com" || host == "eth-sepolia.g.alchemy.com" ||
		net.ParseIP(host) != nil || len(host) > 253 || !strings.Contains(host, ".") {
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
		return config{}, errors.New("set the saved application UUID and its issued CATCHPLATE_PROXY_TOKEN")
	}
	if c.caFile == "" {
		return config{}, errors.New("set CATCHPLATE_CA_FILE to the verified interception CA file")
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

func clientTLS(proxyHost, providerHost string, proxyRoots *x509.CertPool, innerPEM []byte) (*tls.Config, error) {
	innerRoots := x509.NewCertPool()
	if proxyRoots == nil || !innerRoots.AppendCertsFromPEM(innerPEM) {
		return nil, errors.New("configured Catchplate CA file is not a PEM certificate bundle")
	}
	outerRoots := proxyRoots.Clone()
	combined := outerRoots.Clone()
	combined.AppendCertsFromPEM(innerPEM)
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    combined,
		// net/http shares this config between both TLS hops. Normal verification
		// stays enabled, followed by standard chain verification for each role.
		// Leave ServerName empty so net/http selects the actual hostname per hop.
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 || len(cs.VerifiedChains) == 0 {
				return errors.New("TLS peer did not pass normal certificate verification")
			}
			var roots *x509.CertPool
			switch cs.ServerName {
			case proxyHost:
				roots = outerRoots
			case providerHost:
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
			if req.Method != http.MethodPost || req.URL.Scheme != "https" || req.URL.Hostname() != c.providerHost ||
				(req.URL.Port() != "" && req.URL.Port() != "443") || req.URL.User != nil ||
				req.URL.Opaque != "" || (req.Host != "" && req.Host != req.URL.Host) ||
				req.URL.Path != "/v2" || req.URL.RawPath != "" || req.URL.RawQuery != "" ||
				req.URL.ForceQuery || req.URL.Fragment != "" {
				return nil, errors.New("only the selected Alchemy HTTPS RPC origin is permitted")
			}
			return c.proxy, nil
		},
		GetProxyConnectHeader: func(_ context.Context, proxyURL *url.URL, target string) (http.Header, error) {
			if proxyURL == nil || proxyURL.String() != c.proxy.String() || target != c.providerHost+":443" {
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

func httpClient(transport http.RoundTripper) *http.Client {
	return &http.Client{
		Timeout:       30 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
		Transport:     transport,
	}
}

type summary struct {
	ChainID     string `json:"chain_id"`
	BlockNumber uint64 `json:"block_number"`
}

func chainStatus(ctx context.Context, chain string, transport http.RoundTripper) (summary, error) {
	host, expectedID, err := selectChain(chain)
	if err != nil {
		return summary{}, err
	}
	client, err := rpc.DialOptions(ctx, "https://"+host+"/v2",
		rpc.WithHTTPClient(httpClient(transport)),
		rpc.WithHeader("Authorization", "Bearer "+dummyToken))
	if err != nil {
		return summary{}, errors.New("could not initialize the Alchemy RPC client")
	}
	defer client.Close()
	// A non-nil empty variadic slice makes the SDK emit params: []. Omitting
	// all arguments would omit params altogether and not match the preset.
	params := []interface{}{}
	var chainID string
	if err := client.CallContext(ctx, &chainID, "eth_chainId", params...); err != nil || chainID != expectedID {
		return summary{}, errors.New("Alchemy chain ID read failed; inspect Catchplate audit records and the saved permission (no automatic retry)")
	}
	var block string
	if err := client.CallContext(ctx, &block, "eth_blockNumber", params...); err != nil || !quantityPattern.MatchString(block) {
		return summary{}, errors.New("Alchemy block height read failed; inspect Catchplate audit records and the saved permission (no automatic retry)")
	}
	height, err := strconv.ParseUint(block[2:], 16, 64)
	if err != nil {
		return summary{}, errors.New("Alchemy block height is outside the supported range")
	}
	return summary{ChainID: expectedID, BlockNumber: height}, nil
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
	tlsConfig, err := clientTLS(c.proxy.Hostname(), c.providerHost, outerRoots, innerPEM)
	if err != nil {
		return err
	}
	transport := proxyTransport(c, tlsConfig)
	defer transport.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	result, err := chainStatus(ctx, c.chain, transport)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(out).Encode(result); err != nil {
		return errors.New("could not write the chain-status summary")
	}
	return nil
}

func main() {
	if err := runCLI(os.Args[1:], os.Getenv, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err.Error()) // Fixed errors only, never raw SDK/provider data.
		os.Exit(1)
	}
}
