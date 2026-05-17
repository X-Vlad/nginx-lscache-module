#!/bin/bash
# Test runner for nginx-lscache-module.
# Starts nginx with t/nginx.conf, then sources every t/NN-*.t.sh in order.
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NGINX_BIN="${NGINX_BIN:-/usr/local/nginx/sbin/nginx}"
NGINX_PREFIX="${NGINX_PREFIX:-/usr/local/nginx}"
HTDOCS_ROOT="${SCRIPT_DIR}/htdocs"
NGINX_CONF="${SCRIPT_DIR}/nginx.conf"
NGINX_PID=""

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
TOTAL_PASSED=0; TOTAL_FAILED=0; TOTAL_TESTS=0

cleanup() {
    if [ -n "$NGINX_PID" ] && kill -0 "$NGINX_PID" 2>/dev/null; then
        kill "$NGINX_PID" 2>/dev/null || true
        wait "$NGINX_PID" 2>/dev/null || true
    fi
    rm -f "${NGINX_PREFIX}/conf/test.conf"
    rm -rf /var/cache/nginx/lscache/data/* \
           /var/cache/nginx/lscache/tags/* \
           /var/cache/nginx/lscache/hosts/* \
           /var/cache/nginx/lscache/vary/* \
           /var/cache/nginx/lscache/tmp/* 2>/dev/null || true
}
trap cleanup EXIT

[ -x "$NGINX_BIN" ] || { echo -e "${RED}nginx not at $NGINX_BIN${NC}"; exit 1; }
[ -f "${NGINX_PREFIX}/modules/ngx_http_lscache_module.so" ] || {
    echo -e "${RED}module .so missing${NC}"; exit 1; }

mkdir -p "${NGINX_PREFIX}/logs" \
         "$HTDOCS_ROOT/cached" "$HTDOCS_ROOT/tagged" "$HTDOCS_ROOT/vary" \
         "$HTDOCS_ROOT/private" "$HTDOCS_ROOT/set-cookie" \
         "$HTDOCS_ROOT/lsc-cookie" "$HTDOCS_ROOT/short" \
         "$HTDOCS_ROOT/no-cache" "$HTDOCS_ROOT/uncontrolled" \
         "$HTDOCS_ROOT/inline-purge" "$HTDOCS_ROOT/purge" \
         "$HTDOCS_ROOT/vary-other" "$HTDOCS_ROOT/vary-encoding" \
         "$HTDOCS_ROOT/strip-cookies" "$HTDOCS_ROOT/min-uses" \
         "$HTDOCS_ROOT/stale-target"

# Minimal htdocs files so add_header has something to attach to.
for f in cached/page.html tagged/page.html vary/page.html private/page.html \
         set-cookie/page.html lsc-cookie/page.html short/page.html \
         no-cache/page.html uncontrolled/page.html inline-purge/page.html \
         purge/page.html vary-other/page.html vary-encoding/page.html \
         strip-cookies/page.html min-uses/page.html \
         stale-target/page.html; do
    [ -f "$HTDOCS_ROOT/$f" ] \
        || echo "<html><body>$(basename "$(dirname "$f")")-$(basename "$f")</body></html>" \
            > "$HTDOCS_ROOT/$f"
done

# A larger fixed-content file for the Range test (256 bytes of body).
if [ ! -f "$HTDOCS_ROOT/cached/big.html" ]; then
    printf 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' > "$HTDOCS_ROOT/cached/big.html"
    for _ in $(seq 1 7); do
        printf 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' >> "$HTDOCS_ROOT/cached/big.html"
    done
fi

# Cache root may not exist if the entrypoint runs without the Dockerfile
# RUN step (developer mode). Create it idempotently.
mkdir -p /var/cache/nginx/lscache/data \
         /var/cache/nginx/lscache/tags \
         /var/cache/nginx/lscache/hosts \
         /var/cache/nginx/lscache/vary \
         /var/cache/nginx/lscache/tmp 2>/dev/null || true

sed "s|__HTDOCS_ROOT__|${HTDOCS_ROOT}|g" "$NGINX_CONF" \
    > "${NGINX_PREFIX}/conf/test.conf"

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

echo "======================================"
if [ "$TOTAL_FAILED" -eq 0 ]; then
    echo -e "${GREEN}All $TOTAL_TESTS tests passed!${NC}"
else
    echo -e "${RED}$TOTAL_FAILED of $TOTAL_TESTS failed${NC}"
fi
echo "======================================"
exit "$TOTAL_FAILED"
