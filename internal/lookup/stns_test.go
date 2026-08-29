package lookup

import (
	"context"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/STNS/libstns-go/libstns"
)

func TestFetchUserKeysRequestAndResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/users" || r.URL.Query().Get("name") != "bob & alice" {
			t.Errorf("request URL = %s", r.URL.String())
		}
		if got := r.Header.Get("Authorization"); got != "token secret" {
			t.Errorf("Authorization = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `[{"name":%q,"keys":[%q]}]`, "bob & alice", testPublicKey)
	}))
	defer server.Close()

	resolver := newTestResolver(t, server.URL+"/v1", "secret", time.Second, nil)
	keys, status, err := resolver.fetchUserKeys(context.Background(), "bob & alice")
	if err != nil || status != OK || len(keys) != 1 || keys[0] != testPublicKey {
		t.Fatalf("fetchUserKeys() = %q, %v, %v", keys, status, err)
	}
}

func TestResolveAuthorizedKeysResolvesUsersAndGroups(t *testing.T) {
	requests := map[string]int{}
	var requestsMu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		requestsMu.Lock()
		requests[r.URL.Path+"?"+name]++
		requestsMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/groups" && name == "operators":
			_, _ = w.Write([]byte(`[{
				"name":"operators",
				"users":["bob","carol","bob"]
			}]`))
		case r.URL.Path == "/groups" && name == "missing":
			w.WriteHeader(http.StatusNotFound)
		case r.URL.Path == "/users" && name == "alice":
			_, _ = w.Write([]byte(`[{"name":"alice","keys":["alice-key","shared-key"]}]`))
		case r.URL.Path == "/users" && name == "bob":
			_, _ = w.Write([]byte(`[{"name":"bob","keys":["bob-key","shared-key"]}]`))
		case r.URL.Path == "/users" && name == "carol":
			_, _ = w.Write([]byte(`[{"name":"carol","keys":["carol-key"]}]`))
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer server.Close()

	resolver := newTestResolver(t, server.URL, "", time.Second, nil)
	keys, status, err := resolver.ResolveAuthorizedKeys(context.Background(), Sources{
		Users:  []string{"alice", "bob", "alice"},
		Groups: []string{"operators", "missing", "operators"},
	})
	wantKeys := []string{"alice-key", "shared-key", "bob-key", "carol-key"}
	if err != nil || status != OK || !reflect.DeepEqual(keys, wantKeys) {
		t.Fatalf("ResolveAuthorizedKeys() = %q, %v, %v; want %q", keys, status, err, wantKeys)
	}
	wantRequests := map[string]int{
		"/groups?operators": 1,
		"/groups?missing":   1,
		"/users?alice":      1,
		"/users?bob":        1,
		"/users?carol":      1,
	}
	requestsMu.Lock()
	defer requestsMu.Unlock()
	if !reflect.DeepEqual(requests, wantRequests) {
		t.Fatalf("requests = %#v; want %#v", requests, wantRequests)
	}
}

func TestResolveAuthorizedKeysLimitsConcurrentGroupRequests(t *testing.T) {
	var active atomic.Int32
	var maximum atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if r.URL.Path == "/groups" {
			current := active.Add(1)
			defer active.Add(-1)
			updateMaximum(&maximum, current)
			time.Sleep(30 * time.Millisecond)
			_, _ = fmt.Fprintf(w, `[{"name":%q,"users":[%q]}]`, name, name+"-user")
			return
		}
		_, _ = fmt.Fprintf(w, `[{"name":%q,"keys":[%q]}]`, name, name+"-key")
	}))
	defer server.Close()

	const concurrency = 3
	resolver := newTestResolverWithConcurrency(
		t,
		server.URL,
		"",
		time.Second,
		concurrency,
		nil,
	)
	groups := make([]string, 9)
	for index := range groups {
		groups[index] = "group-" + strconv.Itoa(index)
	}
	keys, status, err := resolver.ResolveAuthorizedKeys(
		context.Background(),
		Sources{Groups: groups},
	)
	if err != nil || status != OK || len(keys) != len(groups) {
		t.Fatalf("ResolveAuthorizedKeys() returned %d keys, %v, %v", len(keys), status, err)
	}
	if got := maximum.Load(); got != concurrency {
		t.Fatalf("maximum concurrent group requests = %d, want %d", got, concurrency)
	}
}

func TestResolveAuthorizedKeysLimitsConcurrentUserRequests(t *testing.T) {
	var active atomic.Int32
	var maximum atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current := active.Add(1)
		defer active.Add(-1)
		updateMaximum(&maximum, current)
		time.Sleep(30 * time.Millisecond)
		name := r.URL.Query().Get("name")
		_, _ = fmt.Fprintf(w, `[{"name":%q,"keys":[%q]}]`, name, name+"-key")
	}))
	defer server.Close()

	const concurrency = 3
	resolver := newTestResolverWithConcurrency(
		t,
		server.URL,
		"",
		time.Second,
		concurrency,
		nil,
	)
	users := make([]string, 12)
	for index := range users {
		users[index] = "user-" + strconv.Itoa(index)
	}
	keys, status, err := resolver.ResolveAuthorizedKeys(
		context.Background(),
		Sources{Users: users},
	)
	if err != nil || status != OK || len(keys) != len(users) {
		t.Fatalf("ResolveAuthorizedKeys() returned %d keys, %v, %v", len(keys), status, err)
	}
	if got := maximum.Load(); got != concurrency {
		t.Fatalf("maximum concurrent requests = %d, want %d", got, concurrency)
	}
}

func updateMaximum(maximum *atomic.Int32, current int32) {
	for {
		previous := maximum.Load()
		if current <= previous || maximum.CompareAndSwap(previous, current) {
			return
		}
	}
}

func TestResolveAuthorizedKeysIsAllOrNothing(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("name") == "broken" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(`[{"name":"alice","keys":["partial-key"]}]`))
	}))
	defer server.Close()
	resolver := newTestResolver(t, server.URL, "", time.Second, nil)
	keys, status, err := resolver.ResolveAuthorizedKeys(
		context.Background(),
		Sources{Users: []string{"alice", "broken"}},
	)
	if err == nil || status != Retryable || keys != nil {
		t.Fatalf("ResolveAuthorizedKeys() = %q, %v, %v", keys, status, err)
	}
}

func TestResolveAuthorizedKeysRejectsInvalidGroupMember(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[{"name":"operators","users":[""]}]`))
	}))
	defer server.Close()
	resolver := newTestResolver(t, server.URL, "", time.Second, nil)
	keys, status, err := resolver.ResolveAuthorizedKeys(
		context.Background(),
		Sources{Groups: []string{"operators"}},
	)
	if err == nil || status != Retryable || keys != nil {
		t.Fatalf("ResolveAuthorizedKeys() = %q, %v, %v", keys, status, err)
	}
}

func TestResolveAuthorizedKeysWithNoSourcesIsEmpty(t *testing.T) {
	resolver := &Resolver{timeout: time.Second}
	keys, status, err := resolver.ResolveAuthorizedKeys(context.Background(), Sources{})
	if err != nil || status != OK || len(keys) != 0 {
		t.Fatalf("ResolveAuthorizedKeys() = %q, %v, %v", keys, status, err)
	}
}

func TestFetchUserKeysStatusClassification(t *testing.T) {
	tests := []struct {
		status int
		want   Status
	}{
		{http.StatusNotFound, NotFound},
		{http.StatusBadRequest, Permanent},
		{http.StatusUnauthorized, Permanent},
		{http.StatusForbidden, Permanent},
		{http.StatusTooManyRequests, Retryable},
		{http.StatusInternalServerError, Retryable},
		{http.StatusTeapot, Retryable},
	}
	for _, tt := range tests {
		t.Run(http.StatusText(tt.status), func(t *testing.T) {
			server := httptest.NewServer(
				http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(tt.status)
				}),
			)
			defer server.Close()
			resolver := newTestResolver(t, server.URL, "", time.Second, nil)
			_, got, err := resolver.fetchUserKeys(context.Background(), "alice")
			if got != tt.want {
				t.Fatalf("status classification = %v, %v; want %v", got, err, tt.want)
			}
			if tt.want == NotFound && err != nil {
				t.Fatalf("404 returned error: %v", err)
			}
		})
	}
}

func TestFetchUserKeysRejectsMalformedResponses(t *testing.T) {
	for name, body := range map[string]string{
		"malformed": `{`,
		"object":    `{}`,
		"null":      `null`,
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(
				http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					_, _ = w.Write([]byte(body))
				}),
			)
			defer server.Close()
			resolver := newTestResolver(t, server.URL, "", time.Second, nil)
			if _, status, err := resolver.fetchUserKeys(
				context.Background(),
				"alice",
			); err == nil ||
				status != Retryable {
				t.Fatalf("fetchUserKeys() status=%v err=%v", status, err)
			}
		})
	}
}

func TestFetchUserKeysOverallTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(150 * time.Millisecond)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer server.Close()
	resolver := newTestResolver(t, server.URL, "", 20*time.Millisecond, nil)
	started := time.Now()
	if _, status, err := resolver.ResolveAuthorizedKeys(
		context.Background(),
		Sources{Users: []string{"alice"}},
	); err == nil ||
		status != Retryable {
		t.Fatalf("ResolveAuthorizedKeys() status=%v err=%v", status, err)
	}
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("overall timeout took %v", elapsed)
	}
}

func TestTLSVerificationFailureIsPermanent(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[]`))
	}))
	defer server.Close()
	t.Setenv("STNS_SKIP_VERIFY", "false")
	resolver := newTestResolver(t, server.URL, "", time.Second, nil)
	if _, status, err := resolver.fetchUserKeys(
		context.Background(),
		"alice",
	); err == nil ||
		status != Permanent {
		t.Fatalf("fetchUserKeys() status=%v err=%v", status, err)
	}
}

func TestSkipSSLVerifyAllowsUntrustedCertificate(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[]`))
	}))
	defer server.Close()
	t.Setenv("STNS_SKIP_VERIFY", "true")
	unrelated := httptest.NewTLSServer(http.NotFoundHandler())
	defer unrelated.Close()
	caFile := t.TempDir() + "/ca.pem"
	certificate := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: unrelated.Certificate().Raw,
	})
	if err := os.WriteFile(caFile, certificate, 0600); err != nil {
		t.Fatal(err)
	}
	resolver := newTestResolver(t, server.URL, "", time.Second, func(options *libstns.Options) {
		options.SkipSSLVerify = true
		options.TLS.CA = caFile
	})
	if _, status, err := resolver.fetchUserKeys(
		context.Background(),
		"alice",
	); err != nil || status != OK {
		t.Fatalf("fetchUserKeys() status=%v err=%v", status, err)
	}
}

func TestLibstnsSkipSSLVerifyAloneIsDiscarded(t *testing.T) {
	t.Setenv("STNS_SKIP_VERIFY", "")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[]`))
	}))
	defer server.Close()

	resolver := newTestResolver(t, server.URL, "", time.Second, func(options *libstns.Options) {
		options.SkipSSLVerify = true
	})
	if _, status, err := resolver.fetchUserKeys(
		context.Background(),
		"alice",
	); err == nil || status != Permanent {
		t.Fatalf("fetchUserKeys() status=%v err=%v", status, err)
	}
}

func TestLibstnsRejectsMissingCA(t *testing.T) {
	_, err := libstns.NewSTNS("https://stns.example.com/v1", &libstns.Options{
		RequestRetry: -1,
		TLS:          libstns.TLS{CA: t.TempDir() + "/missing.pem"},
	})
	if err == nil {
		t.Fatal("missing CA file accepted")
	}
}

func newTestResolver(
	t *testing.T,
	endpoint string,
	token string,
	timeout time.Duration,
	configure func(*libstns.Options),
) *Resolver {
	t.Helper()
	return newTestResolverWithConcurrency(t, endpoint, token, timeout, 10, configure)
}

func newTestResolverWithConcurrency(
	t *testing.T,
	endpoint string,
	token string,
	timeout time.Duration,
	concurrency int,
	configure func(*libstns.Options),
) *Resolver {
	t.Helper()
	options := &libstns.Options{
		AuthToken:      token,
		RequestTimeout: int((timeout + time.Second - 1) / time.Second),
		RequestRetry:   -1,
	}
	if configure != nil {
		configure(options)
	}
	api, err := libstns.NewSTNS(endpoint, options)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := NewResolver(api, timeout, concurrency)
	if err != nil {
		t.Fatal(err)
	}
	return resolver
}
