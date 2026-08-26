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

Example `/etc/stns-authorized-keys.conf`:

```toml
endpoint = "https://stns.example.com/v1"
auth_token = "..."
cache_ttl = "5m"
stale_if_error = "24h"
request_timeout = "3s"
cache_dir = "/run/stns-authorized-keys"
lock_wait_timeout = "1s"
log_level = "info"

[tls]
# ca_file = "/etc/stns-authorized-keys/ca.pem"
# cert_file = "/etc/stns-authorized-keys/client.pem"
# key_file = "/etc/stns-authorized-keys/client-key.pem"
# skip_ssl_verify = false

[users.admin]
link_users = ["user-name"]
link_groups = ["group-name"]
```

`tls.skip_ssl_verify = true` disables server certificate verification. It is
intended only for controlled testing; production configurations should leave it
unset or `false`.

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
