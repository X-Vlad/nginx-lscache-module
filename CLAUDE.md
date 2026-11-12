# CLAUDE.md

## Project

Native C nginx module that speaks the LiteSpeed Cache plugin protocol.
Lets nginx serve WordPress / Drupal / Magento sites that ship with an
LSCache plugin as full-page cached, no LiteSpeed Web Server needed.
Linux only. Tested on nginx 1.24.0, 1.28.3, 1.30.1.

## Build

```bash
# Docker (recommended) - also runs all tests on first start
docker build -t nginx-lscache-test .
docker run --rm nginx-lscache-test

# Native: build .so only, or full install + tests
make build NGINX_VERSION=1.30.1
sudo make install NGINX_VERSION=1.30.1 && make test
```

## Test

```bash
docker run --rm nginx-lscache-test                              # all t/*.t.sh
docker run --rm nginx-lscache-test bash /tests/t/stress.sh      # stress harness
make test-versions                                              # 1.24.0, 1.28.2, 1.30.1
```

The test harness runs two nginx server blocks in one process - an
internal backend on `127.0.0.1:8189` using `add_header` to inject the
`X-LiteSpeed-*` protocol headers, and a public `0.0.0.0:8181` with
`lscache on` + `proxy_pass` to that backend. Required because our
header filter installs at postconfigure and therefore runs BEFORE the
built-in `add_header` filter; only `proxy_pass` guarantees the
upstream headers land in `r->headers_out` before our filter walks it.
In production with real PHP-FPM this is automatic.

## Project structure (flat, nginx convention)

- `ngx_http_lscache_module.{h,c}` - types, module def, config, vars
- `ngx_http_lscache_filter.c`     - header + body capture filters
- `ngx_http_lscache_serve.c`      - PRECONTENT cache lookup + sendfile
- `ngx_http_lscache_storage.c`    - key, paths, atomic write, eviction
- `ngx_http_lscache_purge.c`      - PURGE method + IP ACL + executor
- `ngx_http_lscache_vary.c`       - vary_string builder, cookie reader
- `config`                        - nginx build integration
- `t/`                            - shell tests + stress harness
- `demo/`                         - docker-compose WordPress demo
- `install.sh`                    - auto-detect nginx, build + install

## Code style

- nginx conventions: `ngx_` prefixes, `ngx_int_t` / `ngx_str_t`, pool alloc
- Module-internal functions: `lsc_` prefix
- No malloc/free - use `ngx_palloc` / `ngx_pnalloc`
- `ngx_str_t` is (ptr, length), not NUL-terminated by default
- ASCII only in source files; native English in comments

## Security (don't regress these)

- Host for keys, index and purge scope: `lsc_request_host()` (what nginx
  routed by), never `r->headers_in.host` (t/19).
- Private client id = address + all cookies but the stripped ones; no
  cookie, no private cache. `_lscache_vary` is in every key (t/22).
- `.meta` buffer: every variable length is summed, caps on each protocol
  value; add a field, add it to the sum (t/20).
- One owner per descriptor: the pool cleanup reads `ctx`, no copies (t/24).
- Order of a store: meta, index markers, then the data file. Serve only
  with meta and with the size the header states (t/23).
- Only GET answers are stored; no 1xx/204/206/304; no backend
  Content-Encoding; response headers are stored, Set-Cookie never (t/21).

- `PURGE` gated by `lscache_purge_allowed`; v4-mapped IPv6 is matched as v4.
- Public response with `Set-Cookie` is refused unless `LSC-Cookie` is
  also present (session-leak guard).
- `LSC-Cookie` with CR / LF / NUL is treated as injection and refused.
- All `X-LiteSpeed-*` and `LSC-Cookie` upstream headers are stripped
  from the client response (`hash = 0` on header_out).
- Client-supplied `X-LSCache` is stripped before we inject our own.
- Tag / host / `url=` values pass `lsc_safe_name` (rejects `..`, `\0`,
  control chars, `/`, `\\`, leading `.`, length > 1024).
- Inline purges from a backend are scoped to the requesting `Host`.
- Tmp files: `O_CREAT|O_EXCL|O_CLOEXEC`, mode 0640; dirs 0750.
- Bodies past `UINT32_MAX` refused (on-disk header is 32-bit body_len).
- Upstream `X-LiteSpeed-Purge` capped at 64 KB / 64 blocks per request.

## Common pitfalls

- Ubuntu's `/bin/sh` is dash, no brace expansion. In Dockerfile RUN
  use explicit args, not `mkdir -p path/{a,b,c}`.
- Header filter chain runs in reverse install order. Affects test
  layout (see Test section), not production.
- Cache lookup belongs in `NGX_HTTP_PRECONTENT_PHASE` (after rewrite,
  before content).
- Dynamic modules require exact nginx version match (ABI compat).
- Returning `NGX_OK` from a precontent handler does not stop the
  phase engine - it moves to the next phase. To send a response from
  precontent: `ngx_http_finalize_request` explicitly + return `NGX_DONE`.
- Don't add inotify. We own the cache files; we know when they change.
