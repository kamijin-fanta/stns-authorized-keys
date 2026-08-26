package config

import (
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

type TLS struct {
	CAFile        string `toml:"ca_file"`
	CertFile      string `toml:"cert_file"`
	KeyFile       string `toml:"key_file"`
	SkipSSLVerify bool   `toml:"skip_ssl_verify"`
}

type UserLinks struct {
	LinkUsers  []string `toml:"link_users"`
	LinkGroups []string `toml:"link_groups"`
}

type Config struct {
	Endpoint        string               `toml:"endpoint"`
	AuthToken       string               `toml:"auth_token"`
	CacheTTL        time.Duration        `toml:"cache_ttl"`
	StaleIfError    time.Duration        `toml:"stale_if_error"`
	RequestTimeout  time.Duration        `toml:"request_timeout"`
	CacheDir        string               `toml:"cache_dir"`
	LogLevel        string               `toml:"log_level"`
	LockWaitTimeout time.Duration        `toml:"lock_wait_timeout"`
	TLS             TLS                  `toml:"tls"`
	Users           map[string]UserLinks `toml:"users"`
}

type rawConfig struct {
	Endpoint        string               `toml:"endpoint"`
	AuthToken       string               `toml:"auth_token"`
	CacheDir        string               `toml:"cache_dir"`
	LogLevel        string               `toml:"log_level"`
	CacheTTL        string               `toml:"cache_ttl"`
	StaleIfError    string               `toml:"stale_if_error"`
	RequestTimeout  string               `toml:"request_timeout"`
	LockWaitTimeout string               `toml:"lock_wait_timeout"`
	TLS             TLS                  `toml:"tls"`
	Users           map[string]UserLinks `toml:"users"`
}

func Load(path string) (Config, error) {
	var r rawConfig
	md, err := toml.DecodeFile(path, &r)
	if err != nil {
		return Config{}, err
	}
	if undecoded := md.Undecoded(); len(undecoded) != 0 {
		return Config{}, fmt.Errorf("unknown configuration key %q", undecoded[0].String())
	}
	c := Config{
		Endpoint:  r.Endpoint,
		AuthToken: r.AuthToken,
		CacheDir:  r.CacheDir,
		LogLevel:  r.LogLevel,
		TLS:       r.TLS,
		Users:     r.Users,
	}
	parse := func(s string, d *time.Duration) error {
		if s == "" {
			return nil
		}
		var err error
		*d, err = time.ParseDuration(s)
		return err
	}
	for _, x := range []struct {
		s string
		d *time.Duration
		n string
	}{{r.CacheTTL, &c.CacheTTL, "cache_ttl"}, {r.StaleIfError, &c.StaleIfError, "stale_if_error"}, {r.RequestTimeout, &c.RequestTimeout, "request_timeout"}, {r.LockWaitTimeout, &c.LockWaitTimeout, "lock_wait_timeout"}} {
		if err := parse(x.s, x.d); err != nil {
			return c, fmt.Errorf("%s: %w", x.n, err)
		}
	}
	if c.LockWaitTimeout == 0 {
		c.LockWaitTimeout = time.Second
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	if c.CacheTTL <= 0 || c.StaleIfError <= 0 || c.RequestTimeout <= 0 || c.LockWaitTimeout <= 0 {
		return c, fmt.Errorf("durations must be positive")
	}
	if c.Endpoint == "" || c.CacheDir == "" {
		return c, fmt.Errorf("endpoint and cache_dir are required")
	}
	if !filepath.IsAbs(c.CacheDir) {
		return c, fmt.Errorf("cache_dir must be absolute")
	}
	u, err := url.Parse(c.Endpoint)
	if err != nil || u.Scheme != "http" && u.Scheme != "https" || u.Host == "" {
		return c, fmt.Errorf("endpoint must be an http or https URL")
	}
	if u.User != nil || u.Fragment != "" || u.RawQuery != "" {
		return c, fmt.Errorf("endpoint must not contain userinfo, query, or fragment")
	}
	if c.TLS.CertFile != "" != (c.TLS.KeyFile != "") {
		return c, fmt.Errorf("cert_file and key_file must be paired")
	}
	switch strings.ToLower(c.LogLevel) {
	case "debug", "info", "warning", "error":
		c.LogLevel = strings.ToLower(c.LogLevel)
	default:
		return c, fmt.Errorf("log_level must be debug, info, warning, or error")
	}
	for loginUser, links := range c.Users {
		if !validName(loginUser) {
			return c, fmt.Errorf("users contains invalid login user %q", loginUser)
		}
		for _, target := range links.LinkUsers {
			if !validName(target) {
				return c, fmt.Errorf("users.%s.link_users contains an invalid name", loginUser)
			}
		}
		for _, target := range links.LinkGroups {
			if !validName(target) {
				return c, fmt.Errorf("users.%s.link_groups contains an invalid name", loginUser)
			}
		}
	}
	return c, nil
}

// LinksFor returns configured STNS links. A missing section preserves the
// default behavior of looking up the Linux login user by the same STNS name.
// An explicitly empty section intentionally resolves to no keys.
func (c Config) LinksFor(loginUser string) UserLinks {
	links, ok := c.Users[loginUser]
	if !ok {
		return UserLinks{LinkUsers: []string{loginUser}}
	}
	return UserLinks{
		LinkUsers:  unique(links.LinkUsers),
		LinkGroups: unique(links.LinkGroups),
	}
}

// CacheNamespace isolates cache entries when endpoint or link configuration
// changes. Names cannot contain NUL, so the representation is unambiguous.
func (c Config) CacheNamespace(loginUser string) string {
	links := c.LinksFor(loginUser)
	var b strings.Builder
	b.WriteString(c.Endpoint)
	b.WriteString("\x00users")
	for _, name := range links.LinkUsers {
		b.WriteByte(0)
		b.WriteString(name)
	}
	b.WriteString("\x00groups")
	for _, name := range links.LinkGroups {
		b.WriteByte(0)
		b.WriteString(name)
	}
	return b.String()
}

func validName(name string) bool {
	return name != "" &&
		strings.IndexFunc(name, func(r rune) bool { return r == 0 || r < 0x20 || r == 0x7f }) < 0
}

func unique(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}
