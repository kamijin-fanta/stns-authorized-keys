package lookup

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/kamijin-fanta/stns-authorized-keys/internal/cache"
)

type Result struct {
	Data    []byte
	Outcome string
}

const (
	OutcomeHit     = "hit"
	OutcomeRefresh = "refresh"
	OutcomeStale   = "stale"

	// futureMtimeTolerance allows minor skew between a cache file's modification
	// time and the wall clock. One minute covers small clock corrections, while
	// rejecting timestamps that could otherwise keep a cache fresh indefinitely.
	futureMtimeTolerance = time.Minute
)

type Config struct {
	CacheNamespace                          string
	CacheDir                                string
	CacheTTL, StaleIfError, LockWaitTimeout time.Duration
}

func CachedAuthorizedKeys(
	ctx context.Context,
	user string,
	c Config,
	fetch func(context.Context) ([]string, Status, error),
) (Result, error) {
	if user == "" ||
		strings.IndexFunc(user, func(r rune) bool { return r == 0 || r < 0x20 || r == 0x7f }) >= 0 {
		return Result{}, errors.New("invalid username")
	}
	if err := cache.ValidateDir(c.CacheDir); err != nil {
		return Result{}, err
	}
	key := cache.Key(c.CacheNamespace, user)
	ent, err := cache.Read(c.CacheDir, key)
	if err != nil {
		return Result{}, err
	}
	now := time.Now()
	if usable(ent, now, c.CacheTTL) {
		return Result{Data: ent.Data, Outcome: OutcomeHit}, nil
	}
	lock, err := cache.Lock(c.CacheDir, key, c.LockWaitTimeout)
	if err != nil {
		if usable(ent, now, c.StaleIfError) {
			return Result{Data: ent.Data, Outcome: OutcomeStale}, nil
		}
		return Result{}, err
	}
	defer lock.Close()
	ent, err = cache.Read(c.CacheDir, key)
	if err != nil {
		return Result{}, err
	}
	now = time.Now()
	if usable(ent, now, c.CacheTTL) {
		return Result{Data: ent.Data, Outcome: OutcomeHit}, nil
	}
	keys, status, e := fetch(ctx)
	if status == OK && e == nil {
		data, normalizeErr := cache.Normalize(keys)
		if normalizeErr == nil {
			// A successful upstream response is authoritative even if the cache
			// cannot be refreshed; never substitute an older positive entry.
			_ = cache.Write(c.CacheDir, key, data)
			return Result{Data: data, Outcome: OutcomeRefresh}, nil
		}
		e = normalizeErr
	}
	if status == Permanent {
		if e == nil {
			e = errors.New("permanent upstream failure")
		}
		return Result{}, e
	}
	if usable(ent, now, c.StaleIfError) {
		return Result{Data: ent.Data, Outcome: OutcomeStale}, nil
	}
	if e == nil {
		e = errors.New("upstream failure")
	}
	return Result{}, e
}

func usable(e cache.Entry, now time.Time, ttl time.Duration) bool {
	return e.Exists &&
		!e.ModTime.After(now.Add(futureMtimeTolerance)) &&
		now.Sub(e.ModTime) <= ttl
}
