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
	CA   string `toml:"ca"`
	Cert string `toml:"cert"`
	Key  string `toml:"key"`
}

type Cached struct {
	Enable       bool          `toml:"enable"`
	CacheDir     string        `toml:"cache_dir"`
	CacheTTL     time.Duration `toml:"cache_ttl"`
	StaleIfError time.Duration `toml:"stale_if_error"`
}

type UserLinks struct {
	LinkUsers  []string `toml:"link_users"`
	LinkGroups []string `toml:"link_groups"`
}

type Config struct {
	APIEndpoint     string               `toml:"api_endpoint"`
	AuthToken       string               `toml:"auth_token"`
	SSLVerify       bool                 `toml:"ssl_verify"`
	RequestTimeout  time.Duration        `toml:"request_timeout"`
	RequestRetry    int                  `toml:"request_retry"`
	RequestLocktime time.Duration        `toml:"request_locktime"`
	LogLevel        string               `toml:"log_level"`
	TLS             TLS                  `toml:"tls"`
	Cached          Cached               `toml:"cached"`
	Users           map[string]UserLinks `toml:"users"`
}

type rawCached struct {
	Enable       *bool  `toml:"enable"`
	CacheDir     string `toml:"cache_dir"`
	CacheTTL     int64  `toml:"cache_ttl"`
	StaleIfError int64  `toml:"stale_if_error"`
}

type rawConfig struct {
	APIEndpoint     string               `toml:"api_endpoint"`
	AuthToken       string               `toml:"auth_token"`
	SSLVerify       *bool                `toml:"ssl_verify"`
	RequestTimeout  int64                `toml:"request_timeout"`
	RequestRetry    int                  `toml:"request_retry"`
	RequestLocktime int64                `toml:"request_locktime"`
	LogLevel        string               `toml:"log_level"`
	TLS             TLS                  `toml:"tls"`
	Cached          rawCached            `toml:"cached"`
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

	sslVerify := true
	if r.SSLVerify != nil {
		sslVerify = *r.SSLVerify
	}
	cacheEnabled := true
	if r.Cached.Enable != nil {
		cacheEnabled = *r.Cached.Enable
	}
	c := Config{
		APIEndpoint:     r.APIEndpoint,
		AuthToken:       r.AuthToken,
		SSLVerify:       sslVerify,
		RequestTimeout:  seconds(r.RequestTimeout),
		RequestRetry:    r.RequestRetry,
		RequestLocktime: seconds(r.RequestLocktime),
		LogLevel:        r.LogLevel,
		TLS:             r.TLS,
		Cached: Cached{
			Enable:       cacheEnabled,
			CacheDir:     r.Cached.CacheDir,
			CacheTTL:     seconds(r.Cached.CacheTTL),
			StaleIfError: seconds(r.Cached.StaleIfError),
		},
		Users: r.Users,
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	if c.RequestTimeout <= 0 || c.RequestLocktime <= 0 {
		return c, fmt.Errorf("request_timeout and request_locktime must be positive")
	}
	if c.RequestRetry < 0 {
		return c, fmt.Errorf("request_retry must not be negative")
	}
	if c.APIEndpoint == "" {
		return c, fmt.Errorf("api_endpoint is required")
	}
	if c.Cached.Enable {
		if c.Cached.CacheDir == "" {
			return c, fmt.Errorf("cached.cache_dir is required when caching is enabled")
		}
		if !filepath.IsAbs(c.Cached.CacheDir) {
			return c, fmt.Errorf("cached.cache_dir must be absolute")
		}
		if c.Cached.CacheTTL <= 0 || c.Cached.StaleIfError <= 0 {
			return c, fmt.Errorf("cached.cache_ttl and cached.stale_if_error must be positive")
		}
	}
	u, err := url.Parse(c.APIEndpoint)
	if err != nil || u.Scheme != "http" && u.Scheme != "https" || u.Host == "" {
		return c, fmt.Errorf("api_endpoint must be an http or https URL")
	}
	if u.User != nil || u.Fragment != "" || u.RawQuery != "" {
		return c, fmt.Errorf("api_endpoint must not contain userinfo, query, or fragment")
	}
	if c.TLS.Cert != "" != (c.TLS.Key != "") {
		return c, fmt.Errorf("tls.cert and tls.key must be paired")
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

func seconds(value int64) time.Duration {
	return time.Duration(value) * time.Second
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
	b.WriteString(c.APIEndpoint)
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
