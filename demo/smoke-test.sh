#!/bin/bash
# Smoke-test the WordPress demo: confirms the LiteSpeed Cache plugin
# is emitting protocol headers and our module is caching them.
#
# Prereq: `docker compose -f docker-compose.wordpress.yml up -d --build`
# has been run and the wordpress-installer container has exited cleanly.
#
# Usage:
#   bash demo/smoke-test.sh
#
# Exits 0 on success, non-zero on the first failure.

set -u

BASE="${BASE_URL:-http://localhost:8080}"
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

FAILED=0

check_alive() {
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/")
    if [ "$code" = "200" ] || [ "$code" = "302" ] || [ "$code" = "301" ]; then
        echo -e "${GREEN}WordPress is up${NC} (HTTP $code)"
    else
        echo -e "${RED}WordPress not responding${NC} (HTTP $code at $BASE/)"
        echo "Run: docker compose -f docker-compose.wordpress.yml logs"
        exit 1
    fi
}

# A GET on the URL to probe X-LiteSpeed-Cache. HEAD won't trigger the
# LSCache plugin's output-buffer hook that emits the protocol headers,
# so we always use GET.
xls_cache() {
    local path="${1:-/}"
    curl -s -D - -o /dev/null "$BASE$path" \
        | awk -F': ' 'tolower($1)=="x-litespeed-cache"{sub(/\r/,"",$2); print $2; exit}'
}

assert_xls() {
    local expected="$1" path="${2:-/}"
    local actual
    actual=$(xls_cache "$path")
    case "$actual" in
        *"$expected"*)
            echo -e "  ${GREEN}OK${NC} X-LiteSpeed-Cache: $actual"
            ;;
        *)
            echo -e "  ${RED}FAIL${NC} expected '$expected', got '${actual:-<no header>}'"
            FAILED=$((FAILED+1))
            ;;
    esac
}

echo -e "${YELLOW}=== WordPress lscache smoke test ===${NC}"
check_alive

PROBE="/?p=1"
echo ""
echo -e "${YELLOW}-- Cold sample-post GET --${NC}"
curl -s -o /dev/null -X PURGE -H "X-LiteSpeed-Purge: *" "$BASE/"
echo -n "First hit: "
assert_xls "miss" "$PROBE"

echo ""
echo -e "${YELLOW}-- Warm sample-post GET --${NC}"
echo -n "Second hit: "
assert_xls "hit,public" "$PROBE"

echo ""
echo -e "${YELLOW}-- Cache files on disk --${NC}"
count=$(docker compose -f docker-compose.wordpress.yml exec -T nginx \
    sh -c 'find /var/cache/nginx/lscache/data -type f ! -name "*.meta" 2>/dev/null | wc -l' \
    | tr -d '\r')
if [ "${count:-0}" -gt 0 ]; then
    echo -e "  ${GREEN}OK${NC} $count cached entries on disk"
else
    echo -e "  ${RED}FAIL${NC} no cache files found on disk"
    FAILED=$((FAILED+1))
fi

echo ""
if [ "$FAILED" -eq 0 ]; then
    echo -e "${GREEN}All smoke checks passed.${NC}"
    exit 0
else
    echo -e "${RED}$FAILED smoke checks failed.${NC}"
    exit 1
fi
