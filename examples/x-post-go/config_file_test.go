package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var configTestNow = time.UnixMilli(1800000000000)

func downloadForTest() map[string]any {
	env := environment()
	return map[string]any{
		"application_id": env["CATCHPLATE_APP_ID"], "access_rule_id": "22222222-2222-4222-8222-222222222222",
		"proxy_url": env["CATCHPLATE_PROXY_URL"], "proxy_authentication": "basic_and_bearer_v1",
		"proxy_username": env["CATCHPLATE_APP_ID"], "proxy_password": env["CATCHPLATE_PROXY_TOKEN"],
		"token_expires_at_epoch_ms": configTestNow.Add(time.Hour).UnixMilli(),
		"ca_file":                   "./catchplate-ca.pem", "proxy_ca_file": "certs/proxy.pem",
		"operation_bundle": "x_text_post_v1", "upstream_url": "https://api.x.com/2/tweets", "methods": []string{"POST"},
		"request_headers":           map[string]string{"Authorization": "inert-provider-canary"},
		"request_body":              map[string]string{"method": "eth_sendRawTransaction", "text": "inert-file-post"},
		"CATCHPLATE_X_POST_CONFIRM": "post-once", "CATCHPLATE_X_POST_TEXT": "inert-file-post",
		"client_recipe": map[string]any{"entrypoint": "do-not-execute", "sdk_auth_token": "inert-provider-canary",
			"environment": map[string]string{"CATCHPLATE_X_POST_TEXT": "inert-file-post", "CATCHPLATE_X_POST_CONFIRM": "post-once"}},
	}
}

func writeConfiguration(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "private.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func localEnvironment(key string) string {
	if key == "CATCHPLATE_X_POST_TEXT" || key == "CATCHPLATE_X_POST_CONFIRM" {
		return environment()[key]
	}
	return ""
}

func TestDownloadedConfigurationUsesOnlyConnectionAndScope(t *testing.T) {
	path := writeConfiguration(t, downloadForTest())
	getenv, err := configurationEnvironment([]string{"--config", path}, localEnvironment, configTestNow)
	if err != nil {
		t.Fatal(err)
	}
	c, err := readConfig(getenv)
	if err != nil || c.appID != environment()["CATCHPLATE_APP_ID"] || c.proxyToken != environment()["CATCHPLATE_PROXY_TOKEN"] ||
		c.caFile != filepath.Join(filepath.Dir(path), "catchplate-ca.pem") ||
		c.proxyCAFile != filepath.Join(filepath.Dir(path), "certs", "proxy.pem") {
		t.Fatal("downloaded connection does not match")
	}
	if c.text != environment()["CATCHPLATE_X_POST_TEXT"] {
		t.Fatal("file content replaced explicit local text")
	}
	for _, key := range []string{"HTTPS_PROXY", "X_BEARER_TOKEN", "ALCHEMY_API_KEY", "request_body", "request_headers", "entrypoint", "PATH"} {
		if getenv(key) != "" {
			t.Fatal("unselected configuration escaped the allowlist")
		}
	}
	value := downloadForTest()
	value["ca_file"], value["proxy_ca_file"] = "/synthetic/absolute.pem", nil
	path = writeConfiguration(t, value)
	getenv, err = configurationEnvironment([]string{"--config", path}, func(key string) string {
		if key == "CATCHPLATE_PROXY_CA_FILE" || key == "CATCHPLATE_PROXY_TOKEN" {
			return "ambient-canary"
		}
		return localEnvironment(key)
	}, configTestNow)
	if err != nil || getenv("CATCHPLATE_CA_FILE") != "/synthetic/absolute.pem" || getenv("CATCHPLATE_PROXY_CA_FILE") != "" {
		t.Fatal("absolute CA or absent optional CA did not remain explicit")
	}
}

func TestDownloadedConfigurationRejectsInvalidPermissionAndIdentity(t *testing.T) {
	cases := map[string]func(map[string]any){
		"auth":              func(v map[string]any) { v["proxy_authentication"] = "bearer_v1" },
		"identity":          func(v map[string]any) { v["proxy_username"] = "33333333-3333-4333-8333-333333333333" },
		"app":               func(v map[string]any) { v["application_id"], v["proxy_username"] = "bad", "bad" },
		"rule":              func(v map[string]any) { v["access_rule_id"] = "bad" },
		"expiry":            func(v map[string]any) { v["token_expires_at_epoch_ms"] = configTestNow.UnixMilli() },
		"unsafe-expiry":     func(v map[string]any) { v["token_expires_at_epoch_ms"] = int64(9007199254740992) },
		"fractional-expiry": func(v map[string]any) { v["token_expires_at_epoch_ms"] = 1800000000000.5 },
		"bundle":            func(v map[string]any) { v["operation_bundle"] = "arbitrary_v1" },
		"upstream":          func(v map[string]any) { v["upstream_url"] = v["upstream_url"].(string) + "?other=1" },
		"methods":           func(v map[string]any) { v["methods"] = []string{"GET", "POST"} },
		"missing-methods":   func(v map[string]any) { delete(v, "methods") },
		"token":             func(v map[string]any) { v["proxy_password"] = "private-error-canary" },
		"proxy":             func(v map[string]any) { v["proxy_url"] = "https://user:private-error-canary@proxy.example.test" },
		"ca":                func(v map[string]any) { v["ca_file"] = "" },
		"ca-control":        func(v map[string]any) { v["ca_file"] = "private-error-canary\n.pem" },
		"ca-limit":          func(v map[string]any) { v["ca_file"] = strings.Repeat("a", 513) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			value := downloadForTest()
			mutate(value)
			_, err := configurationEnvironment([]string{"--config", writeConfiguration(t, value)}, localEnvironment, configTestNow)
			if err == nil || strings.Contains(err.Error(), "private-error-canary") {
				t.Fatal("invalid configuration accepted or reflected")
			}
		})
	}
}

func TestDownloadedConfigurationFileAndCLI(t *testing.T) {
	// Exercise the actual CLI handoff through config validation and CA loading,
	// stopping before any transport exists.
	value := downloadForTest()
	value["token_expires_at_epoch_ms"] = time.Now().Add(time.Hour).UnixMilli()
	value["ca_file"] = filepath.Join(t.TempDir(), "missing-ca.pem")
	if err := runCLI([]string{"--config", writeConfiguration(t, value)}, localEnvironment, io.Discard); err == nil ||
		err.Error() != "could not open a configured CA file" {
		t.Fatal("CLI did not use the downloaded connection before networking")
	}
	for _, raw := range []string{"", "{", "null", "[]", strings.Repeat("x", maxPrivateConfigBytes+1)} {
		path := filepath.Join(t.TempDir(), "private.json")
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := configurationEnvironment([]string{"--config", path}, localEnvironment, configTestNow); err == nil {
			t.Fatal("invalid file accepted")
		}
	}
	for _, args := range [][]string{{"--config"}, {"--config", ""}, {"--unknown", "private-path-canary"}, {"--config", "path", "extra"}} {
		if err := runCLI(args, localEnvironment, io.Discard); err == nil || strings.Contains(err.Error(), "private-path-canary") {
			t.Fatal("invalid CLI accepted or reflected")
		}
	}
	path := writeConfiguration(t, downloadForTest())
	link := filepath.Join(t.TempDir(), "link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{link, t.TempDir(), filepath.Join(t.TempDir(), "missing")} {
		if _, err := configurationEnvironment([]string{"--config", invalid}, localEnvironment, configTestNow); err == nil {
			t.Fatal("non-regular/missing configuration accepted")
		}
	}
	for _, key := range []string{"SSL_CERT_FILE", "SSL_CERT_DIR"} {
		_, err := configurationEnvironment([]string{"--config", path}, func(k string) string {
			if k == key {
				return "ambient-trust-canary"
			}
			return localEnvironment(k)
		}, configTestNow)
		if err == nil || strings.Contains(err.Error(), "ambient-trust-canary") {
			t.Fatal("ambient trust override accepted or exposed")
		}
	}
	env := environment()
	getenv, err := configurationEnvironment(nil, func(key string) string { return env[key] }, configTestNow)
	if err != nil || getenv("CATCHPLATE_PROXY_TOKEN") != env["CATCHPLATE_PROXY_TOKEN"] {
		t.Fatal("environment mode changed")
	}
	if _, err := readConfig(getenv); err != nil {
		t.Fatal(err)
	}
}

func TestDownloadedConfigurationNeverSuppliesPostingIntent(t *testing.T) {
	path := writeConfiguration(t, downloadForTest())
	for _, missing := range []string{"CATCHPLATE_X_POST_TEXT", "CATCHPLATE_X_POST_CONFIRM"} {
		_, err := configurationEnvironment([]string{"--config", path}, func(key string) string {
			if key == missing {
				return ""
			}
			return localEnvironment(key)
		}, configTestNow)
		if err == nil || exitCode(err) != 1 {
			t.Fatal("JSON supplied posting intent or classified preflight as sent")
		}
	}
}
