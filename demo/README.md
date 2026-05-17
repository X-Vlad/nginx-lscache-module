# nginx-lscache-module demo

A self-contained Docker Compose stack that runs:

- **nginx** built from the local module source, with `lscache on` for
  the WordPress front controller and the PHP handler.
- **php-fpm 8.4** with the extensions WordPress needs (mysqli, gd,
  intl, mbstring, opcache, zip, exif).
- **MySQL 8.0** with a fresh `wordpress` database.
- **wordpress-installer** (the official `wordpress:cli` image) that
  runs once on first boot: installs WP into `./www/wordpress/`,
  installs and activates the **LiteSpeed Cache** plugin, and enables
  its page-cache feature.

This lets you verify end-to-end that:

1. WordPress with the LiteSpeed Cache plugin emits the
   `X-LiteSpeed-Cache-Control: public,max-age=...` (etc.) headers
   on its PHP responses.
2. The nginx module sees those headers, stores the response on disk,
   and serves subsequent requests via `sendfile` with
   `X-LiteSpeed-Cache: hit,public`.
3. Plugin actions (publish a post, change a setting) issue inline
   `X-LiteSpeed-Purge` headers that wipe the right cache entries.

## Run

```bash
cd demo
docker compose -f docker-compose.wordpress.yml up -d --build
```

First boot takes 1-2 minutes (image build + WordPress install). Once
the `wordpress-installer` container exits successfully, visit:

  http://localhost:8080

  Admin login: admin / admin (http://localhost:8080/wp-admin)

## What to check

Open a terminal and hit a sample post twice. **Use GET, not HEAD** -
the LSCache plugin's output buffer hook fires only on full GET requests:

```bash
curl -s -D - -o /dev/null http://localhost:8080/?p=1 | grep -i x-litespeed-cache
# first time:  X-LiteSpeed-Cache: miss
curl -s -D - -o /dev/null http://localhost:8080/?p=1 | grep -i x-litespeed-cache
# second time: X-LiteSpeed-Cache: hit,public
```

Or run the bundled smoke test:

```bash
bash demo/smoke-test.sh
```

Verify the cache files are real:

```bash
docker compose -f docker-compose.wordpress.yml exec nginx \
    find /var/cache/nginx/lscache/data -type f | head
```

Log in to wp-admin, publish a post. The LiteSpeed Cache plugin sends
inline `X-LiteSpeed-Purge` on its admin actions, which should wipe
the homepage cache. Confirm with another:

```bash
curl -sI http://localhost:8080/ | grep -i x-litespeed-cache
# X-LiteSpeed-Cache: miss   (purged and re-fetched)
curl -sI http://localhost:8080/ | grep -i x-litespeed-cache
# X-LiteSpeed-Cache: hit,public
```

Log in as admin and check a logged-in pageview lands in a different
cache slot (the plugin emits
`X-LiteSpeed-Vary: cookie=_lscache_vary` for logged-in users):

```bash
docker compose -f docker-compose.wordpress.yml exec nginx \
    find /var/cache/nginx/lscache/vary -type d -depth 1 | wc -l
# 2 or more (one base key has multiple variants)
```

## Stop / clean up

```bash
docker compose -f docker-compose.wordpress.yml down              # stop
docker compose -f docker-compose.wordpress.yml down -v           # stop + drop MySQL volume
rm -rf www/wordpress                                              # remove WP files
```

## Files

- `Dockerfile.wordpress` - nginx + lscache module + WP-friendly config
- `Dockerfile.php-wp`    - PHP 8.4-FPM with WordPress extensions
- `docker-compose.wordpress.yml` - the stack definition
- `smoke-test.sh`        - automated end-to-end check (warm a page, verify HIT, count cache files)
- `www/wordpress/`       - WordPress install lives here (bind-mounted into both nginx and php)

## How the LSCache plugin gets activated

The LiteSpeed Cache plugin's server detection (in `litespeed-cache.php`)
classifies the runtime as `LITESPEED_SERVER_TYPE = NONE` when the request
doesn't carry an `X-LSCache` indicator and `SERVER_SOFTWARE` doesn't read
`LiteSpeed`. In that classification the plugin silently drops all
`X-LiteSpeed-*` headers and the front-end cache sees nothing to act on.

The lscache nginx module solves this automatically: as soon as `lscache on`
fires for a location, the module injects `X-LSCache: on` into the request
headers in the PRECONTENT phase. `fastcgi_pass` / `proxy_pass` then
forwards it as `HTTP_X_LSCACHE`, the plugin classifies the front-end as
`LITESPEED_SERVER_ADC`, and protocol headers start flowing.

No `fastcgi_param` workaround is needed in your nginx config.
