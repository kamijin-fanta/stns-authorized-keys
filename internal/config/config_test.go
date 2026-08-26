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
endpoint = "https://stns.example.com/v1"
auth_token = "secret"
cache_ttl = "5m"
stale_if_error = "24h"
request_timeout = "3s"
cache_dir = %q

[tls]
skip_ssl_verify = true

[users.admin]
link_users = ["user-name", "user-name"]
link_groups = ["group-name"]
`, dir))
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CacheTTL != 5*time.Minute || cfg.LockWaitTimeout != time.Second ||
		cfg.LogLevel != "info" || !cfg.TLS.SkipSSLVerify {
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

func TestLoadRejectsInvalidConfiguration(t *testing.T) {
	dir := t.TempDir()
	base := fmt.Sprintf(`
endpoint = "https://stns.example.com/v1"
cache_ttl = "5m"
stale_if_error = "24h"
request_timeout = "3s"
cache_dir = %q
`, dir)
	tests := map[string]string{
		"unknown key":    base + "cache_ttll = \"1m\"\n",
		"relative cache": strings.Replace(base, fmt.Sprintf("%q", dir), `"relative"`, 1),
		"endpoint query": strings.Replace(
			base,
			`https://stns.example.com/v1`,
			`https://stns.example.com/v1?x=1`,
			1,
		),
		"certificate unpaired": base + "\n[tls]\ncert_file = \"client.pem\"\n",
		"bad log level":        base + "log_level = \"verbose\"\n",
		"invalid linked user":  base + "\n[users.admin]\nlink_users = [\"bad\\nname\"]\n",
		"empty linked group":   base + "\n[users.admin]\nlink_groups = [\"\"]\n",
		"zero duration": fmt.Sprintf(
			"endpoint = \"https://stns.example.com/v1\"\ncache_ttl = \"0s\"\nstale_if_error = \"1h\"\nrequest_timeout = \"1s\"\ncache_dir = %q\n",
			dir,
		),
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(writeConfig(t, input)); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
}

func writeConfig(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
