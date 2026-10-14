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

// Only connection values are consumed. Language, entrypoint, arguments and
// other environment entries are inert, even when the recipe targets another SDK.
type gmailSDKRecipe struct {
	Schema         string `json:"schema"`
	AccessRuleID   string `json:"access_rule_id"`
	TokenExpiresAt int64  `json:"token_expires_at_epoch_ms"`
	Environment    struct {
		ProxyURL    string `json:"SERVERWARE_PROXY_URL"`
		AppID       string `json:"SERVERWARE_APP_ID"`
		ProxyToken  string `json:"SERVERWARE_PROXY_TOKEN"`
		CAFile      string `json:"SERVERWARE_CA_FILE"`
		ProxyCAFile string `json:"SERVERWARE_PROXY_CA_FILE"`
	} `json:"environment"`
}

// The private console download wraps the same recipe with duplicated scope and
// connection fields. Admit it only when those fields agree with the recipe.
type downloadedConfig struct {
	Schema              string          `json:"schema"`
	ClientRecipe        json.RawMessage `json:"client_recipe"`
	ApplicationID       string          `json:"application_id"`
	AccessRuleID        string          `json:"access_rule_id"`
	ProxyURL            string          `json:"proxy_url"`
	ProxyAuthentication string          `json:"proxy_authentication"`
	ProxyUsername       string          `json:"proxy_username"`
	ProxyPassword       string          `json:"proxy_password"`
	TokenExpiresAt      int64           `json:"token_expires_at_epoch_ms"`
	CAFile              string          `json:"ca_file"`
	ProxyCAFile         string          `json:"proxy_ca_file"`
	UpstreamURL         string          `json:"upstream_url"`
	OperationBundle     string          `json:"operation_bundle"`
	Methods             []string        `json:"methods"`
}

func configurationEnvironment(args []string, getenv func(string) string, now time.Time) (func(string) string, error) {
	if len(args) == 0 {
		return getenv, nil
	}
	if len(args) != 2 || args[0] != "--config" || args[1] == "" {
		return nil, errors.New("usage: gmail-example [--config PATH]; omit --config to use environment variables")
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
	recipeBytes := raw
	wrapped := len(saved.ClientRecipe) != 0
	if wrapped {
		if saved.Schema != "" {
			return nil, errors.New("private configuration must contain one Gmail SDK recipe")
		}
		recipeBytes = saved.ClientRecipe
	}
	var recipe gmailSDKRecipe
	if json.Unmarshal(recipeBytes, &recipe) != nil ||
		(recipe.Schema != "serverware.gmailSdkClient/v1" && recipe.Schema != "serverware.gmailSdkClient/v2") {
		return nil, errors.New("private configuration requires a Gmail SDK client v1 or v2 recipe")
	}
	if !uuidPattern.MatchString(recipe.AccessRuleID) {
		return nil, errors.New("private configuration requires a saved access-rule UUID")
	}
	if recipe.TokenExpiresAt <= now.UnixMilli() || recipe.TokenExpiresAt > 9007199254740991 {
		return nil, errors.New("private configuration requires a future safe-integer application-token expiry")
	}
	env := recipe.Environment
	if wrapped && (saved.ApplicationID != env.AppID || saved.AccessRuleID != recipe.AccessRuleID ||
		saved.ProxyURL != env.ProxyURL || saved.ProxyPassword != env.ProxyToken ||
		saved.ProxyUsername != env.AppID || saved.ProxyAuthentication != "basic_and_bearer_v1" ||
		saved.TokenExpiresAt != recipe.TokenExpiresAt || saved.CAFile != env.CAFile || saved.ProxyCAFile != env.ProxyCAFile ||
		saved.OperationBundle != "gmail_read_v1" || saved.UpstreamURL != "https://"+gmailHost+"/gmail/v1/users/me/messages" ||
		len(saved.Methods) != 1 || saved.Methods[0] != "GET") {
		return nil, errors.New("private configuration connection fields and Gmail read-only permission must match its SDK recipe")
	}
	if !validCAPath(env.CAFile) || (env.ProxyCAFile != "" && !validCAPath(env.ProxyCAFile)) {
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
		"LANG": "C.UTF-8", "SERVERWARE_PROXY_URL": env.ProxyURL, "SERVERWARE_APP_ID": env.AppID,
		"SERVERWARE_PROXY_TOKEN": env.ProxyToken, "SERVERWARE_CA_FILE": resolveCA(env.CAFile),
		"SERVERWARE_PROXY_CA_FILE": resolveCA(env.ProxyCAFile),
	}
	// Never fall back to ambient values, including an absent optional proxy CA.
	selected := func(key string) string { return values[key] }
	if _, err := readConfig(selected); err != nil {
		return nil, err
	}
	return selected, nil
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

// The Google SDK reads process environment before honoring WithHTTPClient.
// Only the --config CLI path replaces it; normal environment-based use is kept.
func replaceConfigurationEnvironment(getenv func(string) string) error {
	keys := []string{"LANG", "SERVERWARE_PROXY_URL", "SERVERWARE_APP_ID", "SERVERWARE_PROXY_TOKEN",
		"SERVERWARE_CA_FILE", "SERVERWARE_PROXY_CA_FILE"}
	values := make([]string, len(keys))
	for i, key := range keys {
		values[i] = getenv(key)
	}
	os.Clearenv()
	for i, key := range keys {
		if values[i] != "" {
			if err := os.Setenv(key, values[i]); err != nil {
				return errors.New("could not select the private configuration environment")
			}
		}
	}
	return nil
}
