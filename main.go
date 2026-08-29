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
	"golang.org/x/term"
)

var version = "dev"

func main() {
	stderr := os.Stderr
	verbose := term.IsTerminal(int(stderr.Fd()))
	cfgPath := flag.String("config", "/etc/stns-authorized-keys.conf", "config path")
	ver := flag.Bool("version", false, "show version")
	flag.BoolVar(&verbose, "v", verbose, "also log to standard error")
	flag.BoolVar(&verbose, "verbose", verbose, "also log to standard error")
	flag.Parse()
	var stderrLog *os.File
	if verbose {
		stderrLog = stderr
	}
	logger := logging.New("info", stderrLog)
	if *ver {
		if _, e := fmt.Println(version); e != nil {
			logger.Errorf("version output failed error=%v", e)
			os.Exit(1)
		}
		return
	}
	if flag.NArg() != 1 {
		logger.Errorf(
			"lookup failed reason=invalid_arguments error=%v",
			fmt.Errorf("exactly one login user is required"),
		)
		os.Exit(2)
	}
	c, e := config.Load(*cfgPath)
	if e != nil {
		logger.Errorf("lookup user=%q failed reason=config_invalid error=%v", flag.Arg(0), e)
		os.Exit(1)
	}
	logger = logging.New(c.LogLevel, stderrLog)
	// libstns-go and its retry transport can write diagnostics to stderr.
	// Discard that dependency output while retaining the original descriptor
	// in the application logger when verbose logging is enabled.
	if devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0); err == nil {
		os.Stderr = devNull
		defer devNull.Close()
	}
	caFile := c.TLS.CA
	if !c.SSLVerify && caFile == "" {
		// libstns-go discards a TLS config containing only
		// SkipSSLVerify. Supplying an existing CA bundle keeps that config
		// attached; certificate verification is still disabled by the option.
		caFile = systemCABundle()
		if caFile == "" {
			logger.Errorf(
				"lookup user=%q failed reason=system_ca_not_found error=%v",
				flag.Arg(0),
				fmt.Errorf("no supported system CA bundle exists"),
			)
			os.Exit(1)
		}
	}
	requestTimeoutSeconds := int((c.RequestTimeout + time.Second - 1) / time.Second)
	libClient, e := libstns.NewSTNS(
		c.APIEndpoint,
		&libstns.Options{
			AuthToken:      c.AuthToken,
			SkipSSLVerify:  !c.SSLVerify,
			RequestTimeout: requestTimeoutSeconds,
			RequestRetry:   c.RequestRetry,
			UserAgent:      "stns-authorized-keys",
			TLS: libstns.TLS{
				CA:   caFile,
				Cert: c.TLS.Cert,
				Key:  c.TLS.Key,
			},
		},
	)
	if e != nil {
		logger.Errorf(
			"lookup user=%q failed reason=client_initialization error=%v",
			flag.Arg(0),
			e,
		)
		os.Exit(1)
	}
	resolver, e := lookup.NewResolver(libClient, c.RequestTimeout)
	if e != nil {
		logger.Errorf(
			"lookup user=%q failed reason=client_initialization error=%v",
			flag.Arg(0),
			e,
		)
		os.Exit(1)
	}
	loginUser := flag.Arg(0)
	links := c.LinksFor(loginUser)
	sources := lookup.Sources{Users: links.LinkUsers, Groups: links.LinkGroups}
	started := time.Now()
	fetch := func(ctx context.Context) ([]string, lookup.Status, error) {
		return resolver.ResolveAuthorizedKeys(ctx, sources)
	}
	var r lookup.Result
	if c.Cached.Enable {
		r, e = lookup.CachedAuthorizedKeys(
			context.Background(),
			loginUser,
			lookup.Config{
				CacheNamespace:  c.CacheNamespace(loginUser),
				CacheDir:        c.Cached.CacheDir,
				CacheTTL:        c.Cached.CacheTTL,
				StaleIfError:    c.Cached.StaleIfError,
				LockWaitTimeout: c.RequestLocktime,
			},
			fetch,
		)
	} else {
		r, e = lookup.AuthorizedKeys(context.Background(), loginUser, fetch)
	}
	if e != nil {
		logger.Errorf(
			"lookup user=%q failed reason=lookup_failed duration_ms=%d error=%v",
			flag.Arg(0),
			time.Since(started).Milliseconds(),
			e,
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
		logger.Errorf(
			"lookup user=%q failed reason=output_failed error=%v",
			flag.Arg(0),
			e,
		)
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
