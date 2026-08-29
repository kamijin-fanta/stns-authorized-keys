package lookup

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/STNS/STNS/v2/model"
	"github.com/STNS/libstns-go/libstns"
)

type Sources struct {
	Users  []string
	Groups []string
}

type Status int

const (
	OK Status = iota
	NotFound
	Permanent
	Retryable
)

type Resolver struct {
	api         *libstns.STNS
	timeout     time.Duration
	concurrency int
}

// NewResolver adds response classification and an exact overall timeout to an
// initialized official libstns client.
func NewResolver(
	api *libstns.STNS,
	timeout time.Duration,
	concurrency int,
) (*Resolver, error) {
	if api == nil {
		return nil, fmt.Errorf("libstns client is required")
	}
	if timeout <= 0 {
		return nil, fmt.Errorf("request timeout must be positive")
	}
	if concurrency <= 0 {
		return nil, fmt.Errorf("request concurrency must be positive")
	}
	return &Resolver{api: api, timeout: timeout, concurrency: concurrency}, nil
}

func (r *Resolver) fetchUserKeys(ctx context.Context, user string) ([]string, Status, error) {
	response, status, err := r.request(ctx, "/users", url.Values{"name": []string{user}})
	if status != OK {
		return nil, status, err
	}
	var users []model.User
	if err := json.Unmarshal(response.Body, &users); err != nil {
		return nil, Retryable, fmt.Errorf("invalid upstream response: %w", err)
	}
	if users == nil {
		return nil, Retryable, fmt.Errorf("upstream response must be a user array")
	}
	if len(users) == 0 {
		return nil, OK, nil
	}
	if len(users) != 1 || users[0].Name != user {
		return nil, Retryable, fmt.Errorf("upstream returned an unexpected user result")
	}
	return users[0].Keys, OK, nil
}

func (r *Resolver) fetchGroupMembers(
	ctx context.Context,
	group string,
) ([]string, Status, error) {
	response, status, err := r.request(ctx, "/groups", url.Values{"name": []string{group}})
	if status != OK {
		return nil, status, err
	}
	var groups []model.Group
	if err := json.Unmarshal(response.Body, &groups); err != nil {
		return nil, Retryable, fmt.Errorf("invalid upstream response: %w", err)
	}
	if groups == nil {
		return nil, Retryable, fmt.Errorf("upstream response must be a group array")
	}
	if len(groups) == 0 {
		return nil, OK, nil
	}
	if len(groups) != 1 || groups[0].Name != group {
		return nil, Retryable, fmt.Errorf("upstream returned an unexpected group result")
	}
	for _, member := range groups[0].Users {
		if member == "" ||
			strings.IndexFunc(
				member,
				func(r rune) bool { return r == 0 || r < 0x20 || r == 0x7f },
			) >= 0 {
			return nil, Retryable, fmt.Errorf("upstream group contains an invalid user name")
		}
	}
	return groups[0].Users, OK, nil
}

// ResolveAuthorizedKeys expands configured groups, fetches every user, and
// returns an all-or-nothing aggregate. Missing sources are authoritative empty
// results; retryable or permanent failures abort the aggregate.
func (r *Resolver) ResolveAuthorizedKeys(
	ctx context.Context,
	sources Sources,
) ([]string, Status, error) {
	requestCtx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	users := append([]string(nil), sources.Users...)
	memberSets, status, err := fetchConcurrently(
		requestCtx,
		unique(sources.Groups),
		r.concurrency,
		r.fetchGroupMembers,
	)
	if status != OK {
		return nil, status, err
	}
	for _, members := range memberSets {
		users = append(users, members...)
	}

	keySets, status, err := fetchConcurrently(
		requestCtx,
		unique(users),
		r.concurrency,
		r.fetchUserKeys,
	)
	if status != OK {
		return nil, status, err
	}
	var keys []string
	for _, userKeys := range keySets {
		keys = append(keys, userKeys...)
	}
	return unique(keys), OK, nil
}

type fetchResult struct {
	value     []string
	status    Status
	err       error
	completed bool
}

func fetchConcurrently(
	ctx context.Context,
	values []string,
	concurrency int,
	fetch func(context.Context, string) ([]string, Status, error),
) ([][]string, Status, error) {
	if len(values) == 0 {
		return nil, OK, nil
	}

	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make([]fetchResult, len(values))
	jobs := make(chan int)
	workerCount := min(concurrency, len(values))
	var workers sync.WaitGroup
	var failureOnce sync.Once
	var failure fetchResult
	workers.Add(workerCount)
	for range workerCount {
		go func() {
			defer workers.Done()
			for {
				select {
				case <-workerCtx.Done():
					return
				case index, ok := <-jobs:
					if !ok {
						return
					}
					value, status, err := fetch(workerCtx, values[index])
					results[index] = fetchResult{
						value:     value,
						status:    status,
						err:       err,
						completed: true,
					}
					if status != OK && status != NotFound {
						failureOnce.Do(func() {
							failure = results[index]
							cancel()
						})
						return
					}
				}
			}
		}()
	}

enqueue:
	for index := range values {
		select {
		case jobs <- index:
		case <-workerCtx.Done():
			break enqueue
		}
	}
	close(jobs)
	workers.Wait()

	if failure.completed {
		return nil, failure.status, failure.err
	}
	if err := ctx.Err(); err != nil {
		return nil, Retryable, err
	}
	valuesByIndex := make([][]string, 0, len(results))
	for _, result := range results {
		if !result.completed || result.status == NotFound {
			continue
		}
		valuesByIndex = append(valuesByIndex, result.value)
	}
	return valuesByIndex, OK, nil
}

func (r *Resolver) request(
	ctx context.Context,
	path string,
	query url.Values,
) (*libstns.Response, Status, error) {
	type response struct {
		value *libstns.Response
		err   error
	}
	result := make(chan response, 1)
	go func() {
		value, err := r.api.Request(path, query.Encode())
		result <- response{value: value, err: err}
	}()

	var upstream response
	select {
	case <-ctx.Done():
		return nil, Retryable, ctx.Err()
	case upstream = <-result:
	}

	if upstream.value == nil {
		if certificateVerificationError(upstream.err) {
			return nil, Permanent, upstream.err
		}
		return nil, Retryable, upstream.err
	}
	switch upstream.value.StatusCode {
	case http.StatusOK:
		if upstream.err != nil {
			return nil, Retryable, upstream.err
		}
	case http.StatusNotFound:
		return nil, NotFound, nil
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden:
		return nil, Permanent, fmt.Errorf(
			"upstream rejected request with status %d",
			upstream.value.StatusCode,
		)
	case http.StatusTooManyRequests:
		return nil, Retryable, fmt.Errorf(
			"upstream unavailable with status %d",
			upstream.value.StatusCode,
		)
	default:
		return nil, Retryable, fmt.Errorf(
			"unexpected upstream status %d",
			upstream.value.StatusCode,
		)
	}

	return upstream.value, OK, nil
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

func certificateVerificationError(err error) bool {
	if err == nil {
		return false
	}
	var verificationErr *tls.CertificateVerificationError
	var unknownAuthority x509.UnknownAuthorityError
	var hostnameErr x509.HostnameError
	var invalidErr x509.CertificateInvalidError
	var rootsErr x509.SystemRootsError
	return errors.As(err, &verificationErr) ||
		errors.As(err, &unknownAuthority) ||
		errors.As(err, &hostnameErr) ||
		errors.As(err, &invalidErr) ||
		errors.As(err, &rootsErr)
}
