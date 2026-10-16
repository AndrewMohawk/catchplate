package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

var configTestNow = time.UnixMilli(1800000000000)

func recipeForTest(schema, language string) map[string]any {
	return map[string]any{
		"schema": schema, "language": language, "example_directory": "ignored-directory",
		"entrypoint": "do-not-execute", "arguments": []string{"--do-not-execute"},
		"clear_environment": true, "resolve_ca_paths": true, "resolve_executable_from_path": true,
		"access_rule_id":            "22222222-2222-4222-8222-222222222222",
		"token_expires_at_epoch_ms": configTestNow.Add(time.Hour).UnixMilli(),
		"environment": map[string]any{
			"LANG": "ignored-locale", "SERVERWARE_PROXY_URL": "https://proxy.example:443",
			"SERVERWARE_APP_ID":      "11111111-1111-4111-8111-111111111111",
			"SERVERWARE_PROXY_TOKEN": strings.Repeat("A", 43), // Public synthetic token.
			"SERVERWARE_CA_FILE":     "./serverware-ca.pem", "SERVERWARE_PROXY_CA_FILE": "certs/proxy.pem",
			"GOOGLE_APPLICATION_CREDENTIALS": "do-not-read", "GOOGLE_API_USE_CLIENT_CERTIFICATE": "true",
			"HTTPS_PROXY": "do-not-use", "SSL_CERT_FILE": "do-not-use", "PATH": "do-not-use",
			"LD_PRELOAD": "do-not-use", "UNKNOWN_DATA": map[string]any{"inert": true},
		},
	}
}

func wrapperForTest(recipe map[string]any) map[string]any {
	env := recipe["environment"].(map[string]any)
	return map[string]any{
		"client_recipe": recipe, "application_id": env["SERVERWARE_APP_ID"],
		"access_rule_id": recipe["access_rule_id"], "proxy_url": env["SERVERWARE_PROXY_URL"],
		"proxy_authentication": "basic_and_bearer_v1", "proxy_username": env["SERVERWARE_APP_ID"],
		"proxy_password": env["SERVERWARE_PROXY_TOKEN"], "token_expires_at_epoch_ms": recipe["token_expires_at_epoch_ms"],
		"ca_file": env["SERVERWARE_CA_FILE"], "proxy_ca_file": env["SERVERWARE_PROXY_CA_FILE"],
		"operation_bundle": "gmail_read_v1", "methods": []string{"GET"},
		"upstream_url": "https://gmail.googleapis.com/gmail/v1/users/me/messages",
	}
}

func writeConfiguration(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal("could not encode synthetic configuration")
	}
	path := filepath.Join(t.TempDir(), "private.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal("could not write synthetic configuration")
	}
	return path
}

func TestDownloadedConfigurationAcceptsCommonRecipe(t *testing.T) {
	for _, schema := range []string{"serverware.gmailSdkClient/v1", "serverware.gmailSdkClient/v2"} {
		for _, language := range []string{"go", "node", "python"} {
			for _, wrapped := range []bool{false, true} {
				t.Run(schema+"/"+language+"/"+map[bool]string{false: "direct", true: "download"}[wrapped], func(t *testing.T) {
					recipe := recipeForTest(schema, language)
					value := recipe
					if wrapped {
						value = wrapperForTest(recipe)
					}
					path := writeConfiguration(t, value)
					getenv, err := downloadedEnvironment(path, configTestNow)
					if err != nil {
						t.Fatal("valid synthetic recipe was refused", err)
					}
					if getenv("LANG") != "C.UTF-8" || getenv("SERVERWARE_CA_FILE") != filepath.Join(filepath.Dir(path), "serverware-ca.pem") ||
						getenv("SERVERWARE_PROXY_CA_FILE") != filepath.Join(filepath.Dir(path), "certs", "proxy.pem") {
						t.Fatal("connection paths or fixed locale do not match")
					}
					for _, key := range []string{"GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_API_USE_CLIENT_CERTIFICATE", "HTTPS_PROXY", "SSL_CERT_FILE", "PATH", "LD_PRELOAD", "UNKNOWN_DATA"} {
						if getenv(key) != "" {
							t.Fatal("unselected environment entry escaped the allowlist")
						}
					}
				})
			}
		}
	}
}

func TestDownloadedConfigurationCAPaths(t *testing.T) {
	recipe := recipeForTest("serverware.gmailSdkClient/v2", "python")
	env := recipe["environment"].(map[string]any)
	absoluteCA := filepath.Join(t.TempDir(), "absolute-ca.pem")
	env["SERVERWARE_CA_FILE"] = absoluteCA
	delete(env, "SERVERWARE_PROXY_CA_FILE")
	wrapped := wrapperForTest(recipe)
	wrapped["proxy_ca_file"] = nil // The actual download uses null when absent.
	path := writeConfiguration(t, wrapped)
	getenv, err := configurationEnvironment([]string{"--config", path}, func(string) string { return "ambient-must-not-be-used" }, configTestNow)
	if err != nil || getenv("SERVERWARE_CA_FILE") != absoluteCA || getenv("SERVERWARE_PROXY_CA_FILE") != "" {
		t.Fatal("absolute CA or missing optional proxy CA did not remain explicit")
	}
}

func TestDownloadedConfigurationRejectsRecipeErrors(t *testing.T) {
	cases := map[string]func(map[string]any){
		"schema":     func(r map[string]any) { r["schema"] = "serverware.gmailSdkClient/v3" },
		"rule":       func(r map[string]any) { r["access_rule_id"] = "not-a-uuid" },
		"expiry":     func(r map[string]any) { r["token_expires_at_epoch_ms"] = configTestNow.UnixMilli() },
		"large":      func(r map[string]any) { r["token_expires_at_epoch_ms"] = int64(9007199254740992) },
		"fractional": func(r map[string]any) { r["token_expires_at_epoch_ms"] = 1800000000000.5 },
		"app":        func(r map[string]any) { r["environment"].(map[string]any)["SERVERWARE_APP_ID"] = "not-a-uuid" },
		"token":      func(r map[string]any) { delete(r["environment"].(map[string]any), "SERVERWARE_PROXY_TOKEN") },
		"bad-token":  func(r map[string]any) { r["environment"].(map[string]any)["SERVERWARE_PROXY_TOKEN"] = "not-a-token" },
		"proxy": func(r map[string]any) {
			r["environment"].(map[string]any)["SERVERWARE_PROXY_URL"] = "http://proxy.example"
		},
		"ca":         func(r map[string]any) { r["environment"].(map[string]any)["SERVERWARE_CA_FILE"] = "" },
		"ca-control": func(r map[string]any) { r["environment"].(map[string]any)["SERVERWARE_CA_FILE"] = "ca\n.pem" },
		"ca-limit": func(r map[string]any) {
			r["environment"].(map[string]any)["SERVERWARE_CA_FILE"] = strings.Repeat("x", 513)
		},
		"outer-ca": func(r map[string]any) { r["environment"].(map[string]any)["SERVERWARE_PROXY_CA_FILE"] = "ca\x00.pem" },
	}
	for name, modify := range cases {
		t.Run(name, func(t *testing.T) {
			recipe := recipeForTest("serverware.gmailSdkClient/v1", "go")
			modify(recipe)
			if _, err := downloadedEnvironment(writeConfiguration(t, recipe), configTestNow); err == nil {
				t.Fatal("invalid configuration was accepted")
			} else if strings.Contains(err.Error(), strings.Repeat("A", 43)) {
				t.Fatal("configuration error exposed the synthetic token")
			}
		})
	}
}

func TestDownloadedConfigurationRejectsConflictingWrapper(t *testing.T) {
	cases := map[string]any{
		"application_id": "33333333-3333-4333-8333-333333333333", "access_rule_id": "33333333-3333-4333-8333-333333333333",
		"proxy_url": "https://other.example", "proxy_authentication": "bearer_v1", "proxy_username": "different",
		"proxy_password": "different", "token_expires_at_epoch_ms": configTestNow.Add(2 * time.Hour).UnixMilli(),
		"ca_file": "different.pem", "proxy_ca_file": "different.pem", "operation_bundle": "other",
		"upstream_url": "https://gmail.googleapis.com/gmail/v1/users/other/messages", "methods": []string{"GET", "POST"},
		"schema": "serverware.gmailSdkClient/v1", "client_recipe": nil,
	}
	for key, value := range cases {
		t.Run(key, func(t *testing.T) {
			wrapped := wrapperForTest(recipeForTest("serverware.gmailSdkClient/v2", "node"))
			wrapped[key] = value
			if _, err := downloadedEnvironment(writeConfiguration(t, wrapped), configTestNow); err == nil {
				t.Fatal("conflicting private download was accepted")
			}
		})
	}
	for _, methods := range [][]string{nil, {}, {"POST"}, {"GET", "GET"}} {
		wrapped := wrapperForTest(recipeForTest("serverware.gmailSdkClient/v1", "go"))
		wrapped["methods"] = methods
		if _, err := downloadedEnvironment(writeConfiguration(t, wrapped), configTestNow); err == nil {
			t.Fatal("non-exact GET permission was accepted")
		}
	}
}

func TestDownloadedConfigurationRequiresBoundedRegularJSON(t *testing.T) {
	directory := t.TempDir()
	for _, raw := range []string{"", "{", "null", "[]", "{}", strings.Repeat("x", maxPrivateConfigBytes+1)} {
		path := filepath.Join(directory, "invalid.json")
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal("could not write synthetic invalid file")
		}
		if _, err := downloadedEnvironment(path, configTestNow); err == nil {
			t.Fatal("invalid JSON file was accepted")
		}
	}
	valid := writeConfiguration(t, recipeForTest("serverware.gmailSdkClient/v1", "go"))
	link := filepath.Join(directory, "symlink.json")
	if err := os.Symlink(valid, link); err != nil {
		t.Fatal("could not make synthetic symlink")
	}
	for _, path := range []string{directory, link, filepath.Join(directory, "missing.json")} {
		if _, err := downloadedEnvironment(path, configTestNow); err == nil {
			t.Fatal("non-regular configuration was accepted")
		}
	}
}

func TestConfigurationArgumentsPreserveEnvironmentDefault(t *testing.T) {
	getenv, err := configurationEnvironment(nil, func(key string) string { return "original-" + key }, configTestNow)
	if err != nil || getenv("ANY") != "original-ANY" {
		t.Fatal("default environment behavior changed")
	}
	for _, args := range [][]string{{"--config"}, {"--config", ""}, {"other"}, {"--config", "file", "extra"}, {"--serverware-child"}, {"--serverware-child", "--config", "file"}} {
		if _, err := configurationEnvironment(args, os.Getenv, configTestNow); err == nil {
			t.Fatal("unsupported arguments were accepted")
		}
	}
}

func TestConfigurationReplacesSDKProcessEnvironment(t *testing.T) {
	// No parallel tests: the CLI deliberately changes its own process environment.
	original := os.Environ()
	t.Cleanup(func() {
		os.Clearenv()
		for _, item := range original {
			key, value, _ := strings.Cut(item, "=")
			if err := os.Setenv(key, value); err != nil {
				t.Error("could not restore test environment")
			}
		}
	})
	if err := os.Setenv("GOOGLE_API_USE_CLIENT_CERTIFICATE", "true"); err != nil {
		t.Fatal("could not set synthetic ambient environment")
	}
	recipe := recipeForTest("serverware.gmailSdkClient/v1", "go")
	delete(recipe["environment"].(map[string]any), "SERVERWARE_PROXY_CA_FILE")
	getenv, err := downloadedEnvironment(writeConfiguration(t, recipe), configTestNow)
	if err != nil || replaceConfigurationEnvironment(getenv) != nil {
		t.Fatal("could not select configuration environment")
	}
	want := map[string]string{}
	for _, key := range []string{"LANG", "SERVERWARE_PROXY_URL", "SERVERWARE_APP_ID", "SERVERWARE_PROXY_TOKEN", "SERVERWARE_CA_FILE"} {
		want[key] = getenv(key)
	}
	actual := map[string]string{}
	for _, item := range os.Environ() {
		key, value, _ := strings.Cut(item, "=")
		actual[key] = value
	}
	if !reflect.DeepEqual(actual, want) {
		t.Fatal("actual SDK environment is not the closed connection allowlist")
	}
	if _, err := readConfig(os.Getenv); err != nil {
		t.Fatal("selected SDK process environment was refused")
	}
}

func TestOptionalAgePolicyPreservesLegacyAndRestrictedHints(t *testing.T) {
	legacy := recipeForTest("serverware.gmailSdkClient/v1", "go")
	legacy["environment"].(map[string]any)["SERVERWARE_GMAIL_MAX_AGE_DAYS"] = "9"
	for _, value := range []map[string]any{legacy, wrapperForTest(legacy)} {
		getenv, err := downloadedEnvironment(writeConfiguration(t, value), configTestNow)
		if err != nil || getenv("SERVERWARE_GMAIL_MAX_AGE_DAYS") != "" {
			t.Fatal("absent top-level age policy inherited a nested recipe hint")
		}
	}
	for _, days := range []int{1, 7, 3650} {
		wrapped := wrapperForTest(recipeForTest("serverware.gmailSdkClient/v2", "python"))
		wrapped["query_mode"] = "orderedFormV1"
		wrapped["age_policy"] = map[string]any{"mode": "recent_internal_date_v1", "max_age_days": days}
		getenv, err := downloadedEnvironment(writeConfiguration(t, wrapped), configTestNow)
		if err != nil {
			t.Fatal("valid age policy refused", err)
		}
		c, err := readConfig(getenv)
		if err != nil || c.maxAgeDays != days {
			t.Fatal("selected age policy was lost")
		}
	}
	for _, raw := range []string{`null`, `{}`, `[]`, `{"mode":"future"}`, `{"mode":"unrestricted","max_age_days":7}`,
		`{"mode":"recent_internal_date_v1","max_age_days":0}`, `{"mode":"recent_internal_date_v1","max_age_days":3651}`,
		`{"mode":"recent_internal_date_v1","max_age_days":true}`, `{"mode":"recent_internal_date_v1","max_age_days":"7"}`,
		`{"mode":"recent_internal_date_v1","max_age_days":1.5}`} {
		if _, err := agePolicyDays(json.RawMessage(raw)); err == nil {
			t.Fatal("invalid age policy accepted")
		}
	}
	for _, raw := range []json.RawMessage{nil, json.RawMessage(`{"mode":"unrestricted"}`)} {
		if days, err := agePolicyDays(raw); err != nil || days != 0 {
			t.Fatal("legacy unrestricted policy changed")
		}
	}
	wrapped := wrapperForTest(recipeForTest("serverware.gmailSdkClient/v2", "python"))
	wrapped["age_policy"] = map[string]any{"mode": "recent_internal_date_v1", "max_age_days": 7}
	if _, err := downloadedEnvironment(writeConfiguration(t, wrapped), configTestNow); err == nil {
		t.Fatal("recent policy without ordered query mode accepted")
	}
}
