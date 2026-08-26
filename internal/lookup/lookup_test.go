package lookup

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kamijin-fanta/stns-authorized-keys/internal/cache"
)

const (
	testNamespace = "https://stns.example.com/v1\x00users\x00alice\x00groups"
	testUser      = "alice"
	testPublicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFpaOUI9V5kHYAYPXYb1sZtilWevnfxnrgNIfNNqVWdv"
)

func testConfig(dir string) Config {
	return Config{
		CacheNamespace:  testNamespace,
		CacheDir:        dir,
		CacheTTL:        time.Minute,
		StaleIfError:    time.Hour,
		LockWaitTimeout: 200 * time.Millisecond,
	}
}

func TestFreshCacheHit(t *testing.T) {
	dir := secureTempDir(t)
	want := []byte(testPublicKey + " cached\n")
	writeEntry(t, dir, want, 10*time.Second)
	result, err := CachedAuthorizedKeys(
		context.Background(),
		testUser,
		testConfig(dir),
		func(context.Context) ([]string, Status, error) {
			t.Fatal("fresh cache queried upstream")
			return nil, Retryable, errors.New("unexpected")
		},
	)
	if err != nil || result.Outcome != OutcomeHit || !bytes.Equal(result.Data, want) {
		t.Fatalf("CachedAuthorizedKeys() = %+v, %v", result, err)
	}
}

func TestCacheMissAndExpiredRefresh(t *testing.T) {
	for _, withExpired := range []bool{false, true} {
		t.Run(map[bool]string{false: "miss", true: "expired"}[withExpired], func(t *testing.T) {
			dir := secureTempDir(t)
			if withExpired {
				writeEntry(t, dir, []byte(testPublicKey+" old\n"), 2*time.Minute)
			}
			result, err := CachedAuthorizedKeys(
				context.Background(),
				testUser,
				testConfig(dir),
				func(context.Context) ([]string, Status, error) {
					return []string{testPublicKey + " new"}, OK, nil
				},
			)
			want := []byte(testPublicKey + " new\n")
			if err != nil || result.Outcome != OutcomeRefresh || !bytes.Equal(result.Data, want) {
				t.Fatalf("CachedAuthorizedKeys() = %+v, %v", result, err)
			}
			entry, err := cache.Read(dir, cache.Key(testNamespace, testUser))
			if err != nil || !bytes.Equal(entry.Data, want) {
				t.Fatalf("cache = %+v, %v", entry, err)
			}
		})
	}
}

func TestAuthoritativeEmptyReplacesPositiveCache(t *testing.T) {
	dir := secureTempDir(t)
	writeEntry(t, dir, []byte(testPublicKey+" old\n"), 2*time.Minute)
	result, err := CachedAuthorizedKeys(
		context.Background(),
		testUser,
		testConfig(dir),
		func(context.Context) ([]string, Status, error) {
			return nil, OK, nil
		},
	)
	if err != nil || len(result.Data) != 0 || result.Outcome != OutcomeRefresh {
		t.Fatalf("CachedAuthorizedKeys() = %+v, %v", result, err)
	}
	entry, err := cache.Read(dir, cache.Key(testNamespace, testUser))
	if err != nil || !entry.Exists || len(entry.Data) != 0 {
		t.Fatalf("empty cache = %+v, %v", entry, err)
	}
}

func TestSuccessfulResponseNeverFallsBackWhenCacheWriteFails(t *testing.T) {
	dir := secureTempDir(t)
	old := []byte(testPublicKey + " old\n")
	writeEntry(t, dir, old, 2*time.Minute)
	result, err := CachedAuthorizedKeys(
		context.Background(),
		testUser,
		testConfig(dir),
		func(context.Context) ([]string, Status, error) {
			// Make ValidateDir reject the cache update independent of whether tests
			// happen to run as root.
			if err := os.Chmod(dir, 0720); err != nil {
				t.Fatal(err)
			}
			return []string{testPublicKey + " current"}, OK, nil
		},
	)
	if chmodErr := os.Chmod(dir, 0700); chmodErr != nil {
		t.Fatal(chmodErr)
	}
	want := []byte(testPublicKey + " current\n")
	if err != nil || !bytes.Equal(result.Data, want) || result.Outcome != OutcomeRefresh {
		t.Fatalf("CachedAuthorizedKeys() = %+v, %v; want authoritative current data", result, err)
	}
	entry, readErr := cache.Read(dir, cache.Key(testNamespace, testUser))
	if readErr != nil || !bytes.Equal(entry.Data, old) {
		t.Fatalf("old on-disk cache changed: %+v, %v", entry, readErr)
	}
}

func TestRetryableFailureUsesOnlyUsableStale(t *testing.T) {
	tests := map[string]struct {
		age    time.Duration
		status Status
		keys   []string
		err    error
		stale  bool
	}{
		"429": {
			age:    2 * time.Minute,
			status: Retryable,
			err:    errors.New("429"),
			stale:  true,
		},
		"5xx": {
			age:    2 * time.Minute,
			status: Retryable,
			err:    errors.New("500"),
			stale:  true,
		},
		"timeout": {
			age:    2 * time.Minute,
			status: Retryable,
			err:    context.DeadlineExceeded,
			stale:  true,
		},
		"malformed key": {
			age:    2 * time.Minute,
			status: OK,
			keys:   []string{"not-a-key"},
			stale:  true,
		},
		"stale expired": {
			age:    2 * time.Hour,
			status: Retryable,
			err:    errors.New("500"),
			stale:  false,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			dir := secureTempDir(t)
			old := []byte(testPublicKey + " old\n")
			writeEntry(t, dir, old, tt.age)
			result, err := CachedAuthorizedKeys(
				context.Background(),
				testUser,
				testConfig(dir),
				func(context.Context) ([]string, Status, error) {
					return tt.keys, tt.status, tt.err
				},
			)
			if tt.stale {
				if err != nil || result.Outcome != OutcomeStale ||
					!bytes.Equal(result.Data, old) {
					t.Fatalf("CachedAuthorizedKeys() = %+v, %v", result, err)
				}
			} else if err == nil {
				t.Fatalf("expired stale cache accepted: %+v, %v", result, err)
			}
		})
	}
}

func TestPermanentFailureNeverUsesStale(t *testing.T) {
	dir := secureTempDir(t)
	writeEntry(t, dir, []byte(testPublicKey+" old\n"), 2*time.Minute)
	result, err := CachedAuthorizedKeys(
		context.Background(),
		testUser,
		testConfig(dir),
		func(context.Context) ([]string, Status, error) {
			return nil, Permanent, errors.New("authentication or certificate failure")
		},
	)
	if err == nil {
		t.Fatalf("permanent failure used stale cache: %+v, %v", result, err)
	}
}

func TestConcurrentRefreshMakesOneRequest(t *testing.T) {
	dir := secureTempDir(t)
	var calls atomic.Int32
	fetch := func(context.Context) ([]string, Status, error) {
		calls.Add(1)
		time.Sleep(30 * time.Millisecond)
		return []string{testPublicKey}, OK, nil
	}
	var wg sync.WaitGroup
	errCh := make(chan error, 12)
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := CachedAuthorizedKeys(
				context.Background(),
				testUser,
				testConfig(dir),
				fetch,
			)
			if err != nil || result.Outcome == "" {
				errCh <- errors.New("lookup failed")
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("upstream called %d times; want 1", got)
	}
}

func TestSmallFutureMtimeIsAccepted(t *testing.T) {
	dir := secureTempDir(t)
	want := []byte(testPublicKey + " future\n")
	writeEntry(t, dir, want, -futureMtimeTolerance/2)
	result, err := CachedAuthorizedKeys(
		context.Background(),
		testUser,
		testConfig(dir),
		func(context.Context) ([]string, Status, error) {
			t.Fatal("cache within future mtime tolerance queried upstream")
			return nil, Retryable, errors.New("unexpected")
		},
	)
	if err != nil || result.Outcome != OutcomeHit || !bytes.Equal(result.Data, want) {
		t.Fatalf("CachedAuthorizedKeys() = %+v, %v", result, err)
	}
}

func TestFutureMtimeBeyondToleranceRefreshes(t *testing.T) {
	dir := secureTempDir(t)
	writeEntry(t, dir, []byte(testPublicKey+" future\n"), -2*futureMtimeTolerance)
	var called bool
	result, err := CachedAuthorizedKeys(
		context.Background(),
		testUser,
		testConfig(dir),
		func(context.Context) ([]string, Status, error) {
			called = true
			return []string{testPublicKey + " current"}, OK, nil
		},
	)
	if err != nil || !called || result.Outcome != OutcomeRefresh {
		t.Fatalf("CachedAuthorizedKeys() = %+v, %v, called=%v", result, err, called)
	}
}

func TestLockContentionUsesStaleWithoutFetching(t *testing.T) {
	dir := secureTempDir(t)
	old := []byte(testPublicKey + " old\n")
	writeEntry(t, dir, old, 2*time.Minute)
	key := cache.Key(testNamespace, testUser)
	lock, err := cache.Lock(dir, key, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	cfg := testConfig(dir)
	cfg.LockWaitTimeout = 20 * time.Millisecond
	result, err := CachedAuthorizedKeys(
		context.Background(),
		testUser,
		cfg,
		func(context.Context) ([]string, Status, error) {
			t.Fatal("lock loser queried upstream")
			return nil, Retryable, nil
		},
	)
	if err != nil || result.Outcome != OutcomeStale || !bytes.Equal(result.Data, old) {
		t.Fatalf("CachedAuthorizedKeys() = %+v, %v", result, err)
	}
}

func TestInvalidUsername(t *testing.T) {
	for _, user := range []string{"", "alice\nforged"} {
		if _, err := CachedAuthorizedKeys(
			context.Background(),
			user,
			testConfig(secureTempDir(t)),
			nil,
		); err == nil {
			t.Fatalf("username %q accepted", user)
		}
	}
}

func writeEntry(t *testing.T, dir string, data []byte, age time.Duration) {
	t.Helper()
	key := cache.Key(testNamespace, testUser)
	if err := cache.Write(dir, key, data); err != nil {
		t.Fatal(err)
	}
	mtime := time.Now().Add(-age)
	if err := os.Chtimes(filepath.Join(dir, key+".keys"), mtime, mtime); err != nil {
		t.Fatal(err)
	}
}

func secureTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}
