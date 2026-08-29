package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	path := writeConfig(t, fmt.Sprintf(`
api_endpoint = "https://stns.example.com/v1"
auth_token = "secret"
ssl_verify = false
request_timeout = 3
request_retry = 3
request_locktime = 5
request_concurrency = 4

[tls]
ca = "ca.pem"

[cached]
enable = true
cache_dir = %q
cache_ttl = 300
stale_if_error = 86400

[users.admin]
link_users = ["user-name", "user-name"]
link_groups = ["group-name"]
`, dir))
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RequestTimeout != 3*time.Second || cfg.RequestRetry != 3 ||
		cfg.RequestLocktime != 5*time.Second || cfg.SSLVerify ||
		cfg.RequestConcurrency != 4 ||
		cfg.Cached.CacheTTL != 5*time.Minute || cfg.Cached.StaleIfError != 24*time.Hour ||
		!cfg.Cached.Enable || cfg.LogLevel != "info" || cfg.TLS.CA != "ca.pem" {
		t.Fatalf("unexpected config: %+v", cfg)
	}
	links := cfg.LinksFor("admin")
	if len(links.LinkUsers) != 1 || links.LinkUsers[0] != "user-name" ||
		len(links.LinkGroups) != 1 || links.LinkGroups[0] != "group-name" {
		t.Fatalf("LinksFor(admin) = %+v", links)
	}
	fallback := cfg.LinksFor("unconfigured")
	if len(fallback.LinkUsers) != 1 || fallback.LinkUsers[0] != "unconfigured" ||
		len(fallback.LinkGroups) != 0 {
		t.Fatalf("LinksFor(unconfigured) = %+v", fallback)
	}
	if cfg.CacheNamespace("admin") == cfg.CacheNamespace("unconfigured") {
		t.Fatal("source configuration did not affect cache namespace")
	}
}

func TestLoadDefaultsVerificationAndCaching(t *testing.T) {
	dir := t.TempDir()
	cfg, err := Load(writeConfig(t, validConfig(dir)))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.SSLVerify || !cfg.Cached.Enable || cfg.RequestConcurrency != 10 {
		t.Fatalf("secure defaults not applied: %+v", cfg)
	}
}

func TestLoadAllowsDisabledCacheWithoutCacheSettings(t *testing.T) {
	cfg, err := Load(writeConfig(t, `
api_endpoint = "https://stns.example.com/v1"
request_timeout = 3
request_locktime = 5

[cached]
enable = false
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Cached.Enable {
		t.Fatal("cache unexpectedly enabled")
	}
}

func TestLoadRejectsInvalidConfiguration(t *testing.T) {
	dir := t.TempDir()
	base := validConfig(dir)
	tests := map[string]string{
		"unknown key": base + "\nunknown = 1\n",
		"legacy key": strings.Replace(
			base,
			"api_endpoint =",
			"endpoint =",
			1,
		),
		"relative cache": strings.Replace(base, fmt.Sprintf("%q", dir), `"relative"`, 1),
		"endpoint query": strings.Replace(
			base,
			`https://stns.example.com/v1`,
			`https://stns.example.com/v1?x=1`,
			1,
		),
		"certificate unpaired": base + "\n[tls]\ncert = \"client.pem\"\n",
		"bad log level": strings.Replace(
			base,
			"request_timeout = 3",
			"request_timeout = 3\nlog_level = \"verbose\"",
			1,
		),
		"negative retry": strings.Replace(base, "request_retry = 3", "request_retry = -1", 1),
		"zero concurrency": strings.Replace(
			base,
			"request_retry = 3",
			"request_retry = 3\nrequest_concurrency = 0",
			1,
		),
		"negative concurrency": strings.Replace(
			base,
			"request_retry = 3",
			"request_retry = 3\nrequest_concurrency = -1",
			1,
		),
		"invalid linked user": base + "\n[users.admin]\nlink_users = [\"bad\\nname\"]\n",
		"empty linked group":  base + "\n[users.admin]\nlink_groups = [\"\"]\n",
		"zero duration":       strings.Replace(base, "cache_ttl = 300", "cache_ttl = 0", 1),
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(writeConfig(t, input)); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
}

func validConfig(dir string) string {
	return fmt.Sprintf(`
api_endpoint = "https://stns.example.com/v1"
request_timeout = 3
request_retry = 3
request_locktime = 5

[cached]
cache_dir = %q
cache_ttl = 300
stale_if_error = 86400
`, dir)
}

func writeConfig(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
