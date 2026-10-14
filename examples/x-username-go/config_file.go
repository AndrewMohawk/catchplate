package main

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"
)

const maxPrivateConfigBytes = 64 * 1024

// Read only the exported connection and named scope. Commands, headers, bodies,
// SDK tokens and recipe environment entries are inert, never executable input.
type downloadedConfig struct {
	ApplicationID       string   `json:"application_id"`
	AccessRuleID        string   `json:"access_rule_id"`
	ProxyURL            string   `json:"proxy_url"`
	ProxyAuthentication string   `json:"proxy_authentication"`
	ProxyUsername       string   `json:"proxy_username"`
	ProxyPassword       string   `json:"proxy_password"`
	TokenExpiresAt      int64    `json:"token_expires_at_epoch_ms"`
	CAFile              string   `json:"ca_file"`
	ProxyCAFile         string   `json:"proxy_ca_file"`
	UpstreamURL         string   `json:"upstream_url"`
	OperationBundle     string   `json:"operation_bundle"`
	Methods             []string `json:"methods"`
	Username            string   `json:"username"`
}

func configurationEnvironment(args []string, getenv func(string) string, now time.Time) (func(string) string, error) {
	if len(args) == 0 {
		return getenv, nil
	}
	if len(args) != 2 || args[0] != "--config" || args[1] == "" {
		return nil, errors.New("usage: x-username [--config PATH]; omit --config to use environment variables")
	}
	// SystemCertPool reads process environment, not the selected config getter.
	if getenv("SSL_CERT_FILE") != "" || getenv("SSL_CERT_DIR") != "" {
		return nil, errors.New("unset SSL_CERT_FILE and SSL_CERT_DIR; use the explicit Serverware CA inputs")
	}
	selected, err := downloadedEnvironment(args[1], now)
	if err != nil {
		return nil, err
	}
	if _, err := readConfig(selected); err != nil {
		return nil, err
	}
	return selected, nil
}

func downloadedEnvironment(path string, now time.Time) (func(string) string, error) {
	invalidFile := errors.New("private configuration must be a readable regular JSON file of at most 64 KiB")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxPrivateConfigBytes {
		return nil, invalidFile
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, invalidFile
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, invalidFile
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxPrivateConfigBytes+1))
	after, statErr := file.Stat()
	if err != nil || statErr != nil || len(raw) == 0 || len(raw) > maxPrivateConfigBytes ||
		int64(len(raw)) != opened.Size() || opened.Size() != after.Size() || !opened.ModTime().Equal(after.ModTime()) {
		return nil, invalidFile
	}
	var saved downloadedConfig
	if json.Unmarshal(raw, &saved) != nil {
		return nil, errors.New("private configuration is not a supported JSON document")
	}
	if saved.ProxyAuthentication != "basic_and_bearer_v1" || saved.ProxyUsername != saved.ApplicationID ||
		!uuidPattern.MatchString(saved.ApplicationID) || !uuidPattern.MatchString(saved.AccessRuleID) {
		return nil, errors.New("private configuration requires a saved application/rule and matching Basic proxy username")
	}
	if saved.TokenExpiresAt <= now.UnixMilli() || saved.TokenExpiresAt > 9007199254740991 {
		return nil, errors.New("private configuration requires a future safe-integer application-token expiry")
	}
	if saved.OperationBundle != "x_username_read_v1" || !usernamePattern.MatchString(saved.Username) ||
		saved.UpstreamURL != "https://"+xHost+"/2/users/by/username/"+saved.Username ||
		len(saved.Methods) != 1 || saved.Methods[0] != "GET" {
		return nil, errors.New("private configuration must grant only the exact exported X username read")
	}
	if !validCAPath(saved.CAFile) || (saved.ProxyCAFile != "" && !validCAPath(saved.ProxyCAFile)) {
		return nil, errors.New("private configuration requires printable CA paths of at most 512 bytes")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, invalidFile
	}
	resolveCA := func(value string) string {
		if value == "" || filepath.IsAbs(value) {
			return value
		}
		return filepath.Join(filepath.Dir(absolute), value)
	}
	values := map[string]string{
		"SERVERWARE_PROXY_URL": saved.ProxyURL, "SERVERWARE_APP_ID": saved.ApplicationID,
		"SERVERWARE_PROXY_TOKEN": saved.ProxyPassword, "SERVERWARE_CA_FILE": resolveCA(saved.CAFile),
		"SERVERWARE_PROXY_CA_FILE": resolveCA(saved.ProxyCAFile),
		"SERVERWARE_X_USERNAME":    saved.Username,
	}
	// No ambient connection fallback, even when the optional proxy CA is absent.
	return func(key string) string { return values[key] }, nil
}

func validCAPath(value string) bool {
	if value == "" || len(value) > 512 {
		return false
	}
	for _, r := range value {
		if r < 32 || r == 127 {
			return false
		}
	}
	return true
}

func runCLI(args []string, getenv func(string) string, out io.Writer) error {
	selected, err := configurationEnvironment(args, getenv, time.Now())
	if err != nil {
		return err
	}
	return run(selected, out)
}
