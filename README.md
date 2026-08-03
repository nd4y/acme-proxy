# acme-proxy

🇬🇧 **English** | [🇷🇺 Русский](README.ru.md)

A DNS-01 broker. It holds the DNS provider credentials; its clients do not.

A client — typically an ACME client running somewhere exposed, such as a control
panel — asks acme-proxy to publish a validation record. acme-proxy checks the
request against that client's policy and writes the record with its own provider
token. The client never sees the token, and a compromised client can do exactly
one thing: create ACME validation records for names it was allowed to touch.

acme-proxy issues nothing. It has no ACME account, sees no certificate and no
private key. Ordering, key generation and CSRs stay with the client.

## Why

Giving an internet-facing service a DNS API token with edit rights on a zone
means that service now controls the zone. The usual workarounds — a second
account, a delegated `_acme-challenge` CNAME zone — either don't reduce the blast
radius or need one delegation per name.

acme-proxy narrows the grant to what ACME actually needs:

- only TXT records, ever — the record type is not part of the API;
- only names beginning with `_acme-challenge.` or `_validation-persist.`;
- only domains on the client's allow list.

The first two invariants are in code and cannot be relaxed by configuration.

## API

Authentication is `Authorization: Bearer <client token>`. Errors are
`{"error": "<code>", "message": "..."}` with codes `unauthorized`,
`forbidden_domain`, `invalid_request`, `invalid_fqdn`, `no_zone`, `rate_limited`,
`provider_error`.

| Endpoint | Body | Purpose |
| --- | --- | --- |
| `POST /v1/dns-01/present` | `{"fqdn": "_acme-challenge.a.example.com", "value": "..."}` | publish a challenge record; idempotent |
| `POST /v1/dns-01/cleanup` | `{"fqdn": "...", "value": "..."}` | remove it; removing what is already gone is a success |
| `PUT /v1/persist` | `{"fqdn": "_validation-persist.example.com", "value": "..."}` | upsert the persistent authorization record for `dns-persist-01` |
| `DELETE /v1/persist` | `{"fqdn": "..."}` | withdraw it |
| `GET /v1/policy` | — | what this client may do; clients can show it in their own UI |
| `GET /healthz` | — | liveness, no authentication |
| `GET /metrics` | — | Prometheus |

`present` appends rather than replaces: an order covering both `example.com` and
`*.example.com` produces two TXT records at the same name, and dropping one of
them fails the order. `PUT /v1/persist` replaces, because there must be exactly
one persistent authorization record per name.

Example:

```bash
curl -s -X POST http://acme-proxy:8080/v1/dns-01/present \
  -H "Authorization: Bearer $CLIENT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"fqdn":"_acme-challenge.edge.example.com","value":"K2s...43-chars"}'
```

## Configuration

See [config.example.yaml](config.example.yaml). Secrets use `${VAR}` and are
resolved from the environment; a missing variable stops startup.

The file is watched. A change is picked up within a second, and a configuration
that fails to parse or to build its providers is logged and **discarded** — the
previous one keeps running. `SIGHUP` forces a reload, which is what you want when
the file is mounted read-only.

Allow patterns:

| Pattern | Matches |
| --- | --- |
| `example.com` | exactly that name |
| `*.example.com` | `example.com` and any subdomain at any depth |
| `node?-*.example.com` | glob inside one label; the number of labels must match |

`*.com` and other single-label suffixes are rejected: one typo there would hand
out the right to write into someone else's zone.

Zones are listed per provider and are matched longest-first, so a delegated
sub-zone wins over its parent. A name outside every configured zone is refused
with `no_zone` before the provider is contacted.

## Providers

`cloudflare` and `memory` are compiled in. The provider layer is
[libdns](https://github.com/libdns), so adding one of the ~95 existing libdns
providers is an import, a `case` in `internal/providers/providers.go` and an entry
in `KnownProviderTypes`.

`memory` keeps records in the process and forgets them on restart. It is meant
for tests and for trying the API out, never for real issuance.

## Running

```bash
docker run --rm \
  -v /etc/acme-proxy:/etc/acme-proxy:ro \
  -e CF_API_TOKEN=... \
  -e CLIENT_TOKEN_PANEL=... \
  -p 8080:8080 \
  ghcr.io/nd4y/acme-proxy:latest
```

Do not publish it to the internet. It is a service for internal clients: bind it
to a private network, and put TLS in front of it if the network between client
and proxy is not trusted.

## Development

```bash
go test ./...
go run ./cmd/acme-proxy -config config.example.yaml -listen :8080
```

With `type: memory` and a couple of environment variables, the full request path
— auth, policy, provider — runs locally without touching DNS.

## License

MIT, see [LICENSE](LICENSE).
