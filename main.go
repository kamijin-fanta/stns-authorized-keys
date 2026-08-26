package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/STNS/libstns-go/libstns"
	"github.com/kamijin-fanta/stns-authorized-keys/internal/config"
	"github.com/kamijin-fanta/stns-authorized-keys/internal/logging"
	"github.com/kamijin-fanta/stns-authorized-keys/internal/lookup"
)

var version = "dev"

func main() {
	// libstns-go and its retry transport can write diagnostics to stderr.
	// AuthorizedKeysCommand diagnostics belong in syslog, so discard that
	// dependency output before constructing the client.
	if devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0); err == nil {
		os.Stderr = devNull
		defer devNull.Close()
	}
	logger := logging.New("info")
	cfgPath := flag.String("config", "/etc/stns-authorized-keys.conf", "config path")
	ver := flag.Bool("version", false, "show version")
	flag.Parse()
	if *ver {
		fmt.Println(version)
		return
	}
	if flag.NArg() != 1 {
		logger.Errorf("lookup failed reason=invalid_arguments")
		os.Exit(2)
	}
	c, e := config.Load(*cfgPath)
	if e != nil {
		logger.Errorf("lookup user=%q failed reason=config_invalid", flag.Arg(0))
		os.Exit(1)
	}
	logger = logging.New(c.LogLevel)
	caFile := c.TLS.CAFile
	if c.TLS.SkipSSLVerify && caFile == "" {
		// libstns-go discards a TLS config containing only
		// SkipSSLVerify. Supplying an existing CA bundle keeps that config
		// attached; certificate verification is still disabled by the option.
		caFile = systemCABundle()
		if caFile == "" {
			logger.Errorf("lookup user=%q failed reason=system_ca_not_found", flag.Arg(0))
			os.Exit(1)
		}
	}
	requestTimeoutSeconds := int((c.RequestTimeout + time.Second - 1) / time.Second)
	libClient, e := libstns.NewSTNS(
		c.Endpoint,
		&libstns.Options{
			AuthToken:      c.AuthToken,
			SkipSSLVerify:  c.TLS.SkipSSLVerify,
			RequestTimeout: requestTimeoutSeconds,
			RequestRetry:   -1,
			UserAgent:      "stns-authorized-keys",
			TLS: libstns.TLS{
				CA:   caFile,
				Cert: c.TLS.CertFile,
				Key:  c.TLS.KeyFile,
			},
		},
	)
	if e != nil {
		logger.Errorf("lookup user=%q failed reason=client_initialization", flag.Arg(0))
		os.Exit(1)
	}
	resolver, e := lookup.NewResolver(libClient, c.RequestTimeout)
	if e != nil {
		logger.Errorf("lookup user=%q failed reason=client_initialization", flag.Arg(0))
		os.Exit(1)
	}
	loginUser := flag.Arg(0)
	links := c.LinksFor(loginUser)
	sources := lookup.Sources{Users: links.LinkUsers, Groups: links.LinkGroups}
	started := time.Now()
	r, e := lookup.CachedAuthorizedKeys(
		context.Background(),
		loginUser,
		lookup.Config{
			CacheNamespace:  c.CacheNamespace(loginUser),
			CacheDir:        c.CacheDir,
			CacheTTL:        c.CacheTTL,
			StaleIfError:    c.StaleIfError,
			LockWaitTimeout: c.LockWaitTimeout,
		},
		func(ctx context.Context) ([]string, lookup.Status, error) {
			return resolver.ResolveAuthorizedKeys(ctx, sources)
		},
	)
	if e != nil {
		logger.Errorf(
			"lookup user=%q failed reason=lookup_failed duration_ms=%d",
			flag.Arg(0),
			time.Since(started).Milliseconds(),
		)
		os.Exit(1)
	}
	if r.Outcome == lookup.OutcomeStale {
		logger.Warningf(
			"lookup user=%q cache=%s duration_ms=%d",
			flag.Arg(0),
			r.Outcome,
			time.Since(started).Milliseconds(),
		)
	} else {
		logger.Infof(
			"lookup user=%q cache=%s duration_ms=%d",
			flag.Arg(0),
			r.Outcome,
			time.Since(started).Milliseconds(),
		)
	}
	if _, e = os.Stdout.Write(r.Data); e != nil {
		os.Exit(1)
	}
}

func systemCABundle() string {
	for _, path := range []string{
		"/etc/ssl/certs/ca-certificates.crt",
		"/etc/pki/tls/certs/ca-bundle.crt",
		"/etc/ssl/ca-bundle.pem",
		"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
	} {
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
			return path
		}
	}
	return ""
}
