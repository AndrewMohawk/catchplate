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

// The console export is unversioned and contains other client recipes. Only
// these connection/scope fields are consumed; no commands or environment from
// the document are executed, and no GitHub provider credential is accepted.
type downloadedConfig struct {
	ApplicationID       string   `json:"application_id"`
	AccessRuleID        string   `json:"access_rule_id"`
	ProxyURL            string   `json:"proxy_url"`
	ProxyAuthentication string   `json:"proxy_authentication"`
	ProxyUsername       string   `json:"proxy_username"`
	ProxyPassword       string   `json:"proxy_password"`
	TokenExpiresAt      int64    `json:"token_expires_at_epoch_ms"`
	CAFile              string   `json:"ca_file"`
	UpstreamURL         string   `json:"upstream_url"`
	OperationBundle     string   `json:"operation_bundle"`
	Methods             []string `json:"methods"`
	Repository          struct {
		Owner string `json:"owner"`
		Name  string `json:"name"`
	} `json:"repository"`
	ClientRecipe struct {
		ProxyCAFile string `json:"proxy_ca_file"`
	} `json:"client_recipe"`
}

func configurationEnvironment(args []string, getenv func(string) string, now time.Time) (func(string) string, error) {
	if len(args) == 0 {
		return getenv, nil
	}
	if len(args) != 2 || args[0] != "--config" || args[1] == "" {
		return nil, errors.New("usage: github-issues [--config PATH]; omit --config to use environment variables")
	}
	return downloadedEnvironment(args[1], now)
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
	if (saved.OperationBundle != "github_issues_read_v1" && saved.OperationBundle != "github_issues_write_v1") ||
		!ownerPattern.MatchString(saved.Repository.Owner) || !repoPattern.MatchString(saved.Repository.Name) ||
		saved.Repository.Name == "." || saved.Repository.Name == ".." ||
		saved.UpstreamURL != "https://api.github.com/repos/"+saved.Repository.Owner+"/"+saved.Repository.Name+"/issues" {
		return nil, errors.New("private configuration must grant GitHub issues for the exact exported repository")
	}
	methods := make(map[string]bool)
	for _, method := range saved.Methods {
		if (method != "GET" && method != "POST") || methods[method] {
			return nil, errors.New("private configuration methods must match its GitHub issues permission")
		}
		methods[method] = true
	}
	if !methods["GET"] || methods["POST"] != (saved.OperationBundle == "github_issues_write_v1") {
		return nil, errors.New("private configuration methods must match its GitHub issues permission")
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
		"SERVERWARE_PROXY_CA_FILE": resolveCA(saved.ClientRecipe.ProxyCAFile),
		"SERVERWARE_GITHUB_OWNER":  saved.Repository.Owner, "SERVERWARE_GITHUB_REPO": saved.Repository.Name,
	}
	// Do not fall back to ambient values, including an absent optional proxy CA.
	selected := func(key string) string { return values[key] }
	if _, err := readConfig(selected); err != nil {
		return nil, err
	}
	return selected, nil
}
