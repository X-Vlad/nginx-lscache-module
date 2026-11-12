#!/bin/bash
# Test runner for nginx-lscache-module.
# Starts nginx with t/nginx.conf, then sources every t/NN-*.t.sh in order.
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NGINX_BIN="${NGINX_BIN:-/usr/local/nginx/sbin/nginx}"
NGINX_PREFIX="${NGINX_PREFIX:-/usr/local/nginx}"
HTDOCS_ROOT="${SCRIPT_DIR}/htdocs"
NGINX_CONF="${SCRIPT_DIR}/nginx.conf"
LSCACHE_ROOT="${LSCACHE_ROOT:-/var/cache/nginx/lscache}"
export LSCACHE_ROOT
export NGINX_ERROR_LOG="${NGINX_PREFIX}/logs/error.log"
NGINX_PID=""

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
TOTAL_PASSED=0; TOTAL_FAILED=0; TOTAL_TESTS=0

cleanup() {
    if [ -n "$NGINX_PID" ] && kill -0 "$NGINX_PID" 2>/dev/null; then
        kill "$NGINX_PID" 2>/dev/null || true
        wait "$NGINX_PID" 2>/dev/null || true
    fi
    rm -f "${NGINX_PREFIX}/conf/test.conf"
    rm -rf "${LSCACHE_ROOT:?}/data" "${LSCACHE_ROOT:?}/tags" \
           "${LSCACHE_ROOT:?}/hosts" "${LSCACHE_ROOT:?}/vary" \
           "${LSCACHE_ROOT:?}/tmp" 2>/dev/null || true
}
trap cleanup EXIT

[ -x "$NGINX_BIN" ] || { echo -e "${RED}nginx not at $NGINX_BIN${NC}"; exit 1; }
# A static build (--add-module) has no .so and takes no load_module line.
STATIC_BUILD=0
if "$NGINX_BIN" -V 2>&1 | grep -q -- "--add-module="; then STATIC_BUILD=1; fi
[ "$STATIC_BUILD" = 1 ] \
    || [ -f "${NGINX_PREFIX}/modules/ngx_http_lscache_module.so" ] || {
    echo -e "${RED}module .so missing${NC}"; exit 1; }

mkdir -p "${NGINX_PREFIX}/logs" \
         "$HTDOCS_ROOT/cached" "$HTDOCS_ROOT/tagged" "$HTDOCS_ROOT/vary" \
         "$HTDOCS_ROOT/private" "$HTDOCS_ROOT/set-cookie" \
         "$HTDOCS_ROOT/lsc-cookie" "$HTDOCS_ROOT/short" \
         "$HTDOCS_ROOT/no-cache" "$HTDOCS_ROOT/uncontrolled" \
         "$HTDOCS_ROOT/inline-purge" "$HTDOCS_ROOT/purge" \
         "$HTDOCS_ROOT/vary-other" "$HTDOCS_ROOT/vary-encoding" \
         "$HTDOCS_ROOT/strip-cookies" "$HTDOCS_ROOT/min-uses" \
         "$HTDOCS_ROOT/stale-target" \
         "$HTDOCS_ROOT/long-vary" "$HTDOCS_ROOT/gzipped" \
         "$HTDOCS_ROOT/headers" "$HTDOCS_ROOT/etag" \
         "$HTDOCS_ROOT/variants" "$HTDOCS_ROOT/sweep" "$HTDOCS_ROOT/mobile" \
         "${HTDOCS_ROOT}-b/cached" "${HTDOCS_ROOT}-b/purge-other"

# Minimal htdocs files so add_header has something to attach to.
for f in cached/page.html tagged/page.html vary/page.html private/page.html \
         set-cookie/page.html lsc-cookie/page.html short/page.html \
         no-cache/page.html uncontrolled/page.html inline-purge/page.html \
         purge/page.html vary-other/page.html vary-encoding/page.html \
         strip-cookies/page.html min-uses/page.html \
         stale-target/page.html long-vary/page.html gzipped/page.html \
         headers/page.html etag/page.html variants/page.html \
         mobile/page.html; do
    [ -f "$HTDOCS_ROOT/$f" ] \
        || echo "<html><body>$(basename "$(dirname "$f")")-$(basename "$f")</body></html>" \
            > "$HTDOCS_ROOT/$f"
done

# The other tenant's pages: same paths, different content.
echo "<html><body>SITE-B page</body></html>" > "${HTDOCS_ROOT}-b/cached/page.html"
echo "<html><body>SITE-B poison target</body></html>" > "${HTDOCS_ROOT}-b/cached/poison.html"
echo "<html><body>SITE-A poison attempt</body></html>" > "$HTDOCS_ROOT/cached/poison.html"
echo "<html><body>SITE-B purge</body></html>" > "${HTDOCS_ROOT}-b/purge-other/page.html"
for i in $(seq 1 200); do
    [ -f "$HTDOCS_ROOT/sweep/p$i.html" ] \
        || head -c 8192 /dev/zero | tr '\0' 's' > "$HTDOCS_ROOT/sweep/p$i.html"
done
[ -f "$HTDOCS_ROOT/cached/huge.html" ] \
    || head -c 6000000 /dev/zero | tr '\0' 'h' > "$HTDOCS_ROOT/cached/huge.html"

# A larger fixed-content file for the Range test (256 bytes of body).
if [ ! -f "$HTDOCS_ROOT/cached/big.html" ]; then
    printf 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' > "$HTDOCS_ROOT/cached/big.html"
    for _ in $(seq 1 7); do
        printf 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' >> "$HTDOCS_ROOT/cached/big.html"
    done
fi

# Cache root may not exist if the entrypoint runs without the Dockerfile
# RUN step (developer mode). Create it idempotently.
mkdir -p "$LSCACHE_ROOT/data" "$LSCACHE_ROOT/tags" "$LSCACHE_ROOT/hosts" \
         "$LSCACHE_ROOT/vary" "$LSCACHE_ROOT/tmp" 2>/dev/null || true

LONG_VARY=$(head -c 3000 /dev/zero | tr '\0' 'A')
sed -e "s|__HTDOCS_ROOT__|${HTDOCS_ROOT}|g" \
    -e "s|__CACHE_ROOT__|${LSCACHE_ROOT}|g" \
    -e "s|__MODULE__|${NGINX_PREFIX}/modules/ngx_http_lscache_module.so|g" \
    -e "s|__LONG_VARY__|${LONG_VARY}|g" "$NGINX_CONF" \
    > "${NGINX_PREFIX}/conf/test.conf"
[ "$STATIC_BUILD" = 1 ] && sed -i '/^load_module /d' "${NGINX_PREFIX}/conf/test.conf"
[ -n "$NGINX_TEST_USER" ] && sed -i "1i user ${NGINX_TEST_USER};" "${NGINX_PREFIX}/conf/test.conf"

echo "Starting nginx for tests..."
"$NGINX_BIN" -c "${NGINX_PREFIX}/conf/test.conf" -p "$NGINX_PREFIX" &
NGINX_PID=$!

for i in $(seq 1 30); do
    if curl -s -o /dev/null http://127.0.0.1:8181/ 2>/dev/null; then break; fi
    sleep 0.1
done
if ! curl -s -o /dev/null http://127.0.0.1:8181/ 2>/dev/null; then
    echo -e "${RED}nginx failed to start${NC}"
    tail -30 "${NGINX_PREFIX}/logs/error.log" 2>/dev/null
    exit 1
fi
echo -e "${GREEN}nginx started (PID: $NGINX_PID)${NC}"
echo ""

shopt -s nullglob
TEST_FILES=("${SCRIPT_DIR}"/*.t.sh)
if [ ${#TEST_FILES[@]} -eq 0 ]; then
    echo -e "${YELLOW}No .t.sh files found in ${SCRIPT_DIR}; skipping.${NC}"
    exit 0
fi

for test_file in "${TEST_FILES[@]}"; do
    test_name=$(basename "$test_file" .t.sh)
    echo -e "${YELLOW}=== $test_name ===${NC}"
    TESTS_PASSED=0; TESTS_FAILED=0; TESTS_TOTAL=0
    source "${SCRIPT_DIR}/helpers.sh"
    source "$test_file"
    TOTAL_PASSED=$((TOTAL_PASSED + TESTS_PASSED))
    TOTAL_FAILED=$((TOTAL_FAILED + TESTS_FAILED))
    TOTAL_TESTS=$((TOTAL_TESTS + TESTS_TOTAL))
    echo ""
done

# Nothing above may have crashed a worker or tripped a sanitizer.
# (nullglob is on: an unmatched pattern gives an empty array)
SAN_FILES=("${NGINX_PREFIX}"/logs/asan.*)
if grep -q -E "exited on signal|exited with code [1-9]|AddressSanitizer" \
        "${NGINX_PREFIX}/logs/error.log" 2>/dev/null \
   || [ ${#SAN_FILES[@]} -gt 0 ]; then
    echo -e "${RED}a worker died or a sanitizer report was written${NC}"
    grep -E "exited on signal|exited with code [1-9]|AddressSanitizer" \
        "${NGINX_PREFIX}/logs/error.log" 2>/dev/null | head -5
    printf '%s\n' "${SAN_FILES[@]}" | head -3
    TOTAL_FAILED=$((TOTAL_FAILED + 1)); TOTAL_TESTS=$((TOTAL_TESTS + 1))
fi

echo "======================================"
if [ "$TOTAL_FAILED" -eq 0 ]; then
    echo -e "${GREEN}All $TOTAL_TESTS tests passed!${NC}"
else
    echo -e "${RED}$TOTAL_FAILED of $TOTAL_TESTS failed${NC}"
fi
echo "======================================"
exit "$TOTAL_FAILED"
