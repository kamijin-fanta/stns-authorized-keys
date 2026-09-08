# stns-authorized-keys

OpenSSH `AuthorizedKeysCommand` helper backed by STNS and a local atomic cache.

This tool is intended to provide a simple, auditable mapping of who may log in
to a single Linux user. It talks directly to [STNS/STNS](https://github.com/STNS/STNS),
the parent identity and key-management project, without depending on
`cache-stnsd`, `libnss-stns`, or another resident STNS client component.

```text
AuthorizedKeysFile none
AuthorizedKeysCommand /usr/bin/stns-authorized-keys %u
AuthorizedKeysCommandUser stns-keys
```

Logs are sent to journald. Pass `-v` or `--verbose` to also write them to
standard error. Standard-error logging is enabled by default when standard
error is attached to a terminal, and disabled by default otherwise.

Example `/etc/stns-authorized-keys.conf`:

```toml
api_endpoint = "https://stns.example.com/v1"
auth_token = "..."
ssl_verify = true
request_timeout = 3
request_retry = 3
request_locktime = 5
request_concurrency = 10
log_level = "info"

[tls]
# ca = "/etc/stns-authorized-keys/ca.pem"
# cert = "/etc/stns-authorized-keys/client.pem"
# key = "/etc/stns-authorized-keys/client-key.pem"

[cached]
enable = true
cache_dir = "/run/stns-authorized-keys"
cache_ttl = 300
stale_if_error = 86400

[users.admin]
link_users = ["user-name"]
link_groups = ["group-name"]
```

Durations are specified in seconds. `ssl_verify = false` disables server
certificate verification. It is intended only for controlled testing;
production configurations should leave it `true` (the default).

`request_retry` controls the number of upstream HTTP retries, and
`request_locktime` controls how long this command waits to acquire the cache
refresh lock. `request_concurrency` limits concurrent upstream requests for
groups and user keys, and defaults to `10` when omitted. Set
`cached.enable = false` to bypass the local cache entirely.

`[users.<login-user>]` maps the Linux user passed by sshd to STNS sources.
`link_users` fetches those STNS users directly. `link_groups` fetches each STNS
group and then fetches the keys of every user in its `users` response. Duplicate
users and keys are removed. If no section exists, the command keeps the default
behavior and looks up the same username in STNS. An explicitly empty section
returns no keys.

The complete aggregate is cached under a namespace containing the endpoint and
link configuration. A failure while resolving any configured source never
writes a partial cache; the normal stale-if-error policy applies to the previous
aggregate instead.

The cache directory must be created before use and owned by the dedicated
command user:

```sh
install -Dm0755 stns-authorized-keys /usr/bin/stns-authorized-keys
install -Dm0644 tmpfiles.d/stns-authorized-keys.conf /usr/lib/tmpfiles.d/stns-authorized-keys.conf
systemd-tmpfiles --create stns-authorized-keys.conf
```

Build and test from the repository root:

```sh
make format
make check
```

Pushing a tag runs the GitHub Actions release workflow. It runs the tests with
the race detector and `go vet`, then publishes standalone Linux amd64 and arm64
ELF binaries and `checksums.txt` to GitHub Releases. Download the binary for
your architecture and make it executable with `chmod +x`. Configuration files
are available in this repository.

Run `stns-authorized-keys --version` to print the release tag embedded at build
time. Local builds without an embedded version print `dev`.

```sh
git tag 0.0.1
git push origin 0.0.1
```
