#!/bin/bash
# Stress test: hammer nginx with concurrent traffic and verify
#   (a) it does not crash
#   (b) it does not leak memory
#   (c) request error rate stays at zero
#   (d) PURGE and tag-based purge under load do not corrupt the cache
#
# Run inside the test container:
#   docker run --rm nginx-lscache-test bash /tests/t/stress.sh
#
# Uses Apache Bench (ab) which comes with apache2-utils (already in the image).

set -u
HTDOCS_ROOT=/tests/t/htdocs
NGINX_PREFIX=/usr/local/nginx
NGINX_BIN=$NGINX_PREFIX/sbin/nginx
CACHE_ROOT=/var/cache/nginx/lscache

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Prepare htdocs same as run_tests.sh
mkdir -p "$HTDOCS_ROOT"/{cached,tagged,vary,private,set-cookie,lsc-cookie,short,no-cache,uncontrolled,inline-purge,purge,vary-other,vary-encoding,strip-cookies,min-uses,stale-target}
for f in cached/page.html tagged/page.html vary/page.html private/page.html \
         set-cookie/page.html lsc-cookie/page.html short/page.html \
         no-cache/page.html uncontrolled/page.html inline-purge/page.html \
         purge/page.html vary-other/page.html vary-encoding/page.html \
         strip-cookies/page.html min-uses/page.html stale-target/page.html; do
    [ -f "$HTDOCS_ROOT/$f" ] \
        || echo "<html><body>$(basename "$(dirname "$f")")</body></html>" \
            > "$HTDOCS_ROOT/$f"
done
if [ ! -f "$HTDOCS_ROOT/cached/big.html" ]; then
    printf 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' > "$HTDOCS_ROOT/cached/big.html"
    for _ in $(seq 1 7); do
        printf 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' >> "$HTDOCS_ROOT/cached/big.html"
    done
fi

# Reset cache root
mkdir -p "$CACHE_ROOT"/{data,tags,hosts,vary,tmp}
rm -rf "$CACHE_ROOT"/data/* "$CACHE_ROOT"/tags/* \
       "$CACHE_ROOT"/hosts/* "$CACHE_ROOT"/vary/* "$CACHE_ROOT"/tmp/* 2>/dev/null || true
chown -R nobody:nogroup "$CACHE_ROOT"

sed "s|__HTDOCS_ROOT__|$HTDOCS_ROOT|g" /tests/t/nginx.conf \
    > $NGINX_PREFIX/conf/test.conf

mkdir -p $NGINX_PREFIX/logs
> $NGINX_PREFIX/logs/error.log

$NGINX_BIN -c $NGINX_PREFIX/conf/test.conf -p $NGINX_PREFIX &
NPID=$!
sleep 1

if ! kill -0 $NPID 2>/dev/null; then
    echo -e "${RED}nginx failed to start${NC}"
    tail -20 $NGINX_PREFIX/logs/error.log
    exit 1
fi

worker_rss() {
    local wpid
    wpid=$(pgrep -P $NPID | head -1)
    [ -n "$wpid" ] && awk '/^VmRSS:/{print $2}' /proc/$wpid/status 2>/dev/null || echo 0
}
START_RSS=$(worker_rss)
echo -e "${YELLOW}nginx PID=$NPID  worker RSS=${START_RSS} KB${NC}"
echo ""

# ----------------------------------------------------------------------
# Scenario runner
# ----------------------------------------------------------------------
total_pass=0; total_fail=0

run_scenario() {
    local label="$1" url="$2" n="$3" c="$4"
    shift 4
    local extra_args=("$@")

    echo -e "${YELLOW}>>> $label${NC}"
    echo "    url=$url  requests=$n  concurrency=$c"
    local out fails non2xx rps mean
    out=$(ab -q -n "$n" -c "$c" "${extra_args[@]}" \
            "http://127.0.0.1:8181$url" 2>&1)

    fails=$(echo "$out"  | awk '/^Failed requests:/{print $3}')
    non2xx=$(echo "$out" | awk '/^Non-2xx responses:/{print $3}')
    rps=$(echo "$out"    | awk '/^Requests per second:/{print $4}')
    mean=$(echo "$out"   | awk '/^Time per request:.*mean\)/{print $4; exit}')

    fails=${fails:-0}; non2xx=${non2xx:-0}; rps=${rps:-?}; mean=${mean:-?}

    if [ "$fails" = "0" ] && \
       { [ "$non2xx" = "0" ] || [ "${NON2XX_OK:-0}" = "1" ]; }; then
        echo -e "    ${GREEN}OK${NC}  rps=$rps  mean=${mean}ms  fails=$fails  non2xx=$non2xx"
        total_pass=$((total_pass+1))
    else
        echo -e "    ${RED}FAIL${NC}  rps=$rps  mean=${mean}ms  fails=$fails  non2xx=$non2xx"
        total_fail=$((total_fail+1))
    fi
    NON2XX_OK=0
}

# 1. Pure pass-through (lscache on but upstream emits no protocol headers).
run_scenario "Pass-through (no upstream directive)" /uncontrolled/page.html 5000 50

# 2. Hot HIT path - the dominant production case (sendfile from disk).
curl -s http://127.0.0.1:8181/cached/page.html -o /dev/null    # warm
run_scenario "Cache HIT (sendfile from disk)" /cached/page.html 20000 100

# 3. Vary HIT under cookie variation - mixed clients pulling distinct slots.
for who in alice bob carol dave eve frank; do
    curl -s -H "Cookie: wp_logged_in=$who" \
         http://127.0.0.1:8181/vary/page.html -o /dev/null
done
run_scenario "Vary HIT, mixed cookie clients" /vary/page.html 5000 50 \
    -H "Cookie: wp_logged_in=alice"

# 4. Private cache - per-client slot serving.
for who in alice bob carol; do
    curl -s -H "Cookie: _lscache_vary=$who" \
         http://127.0.0.1:8181/private/page.html -o /dev/null
    curl -s -H "Cookie: _lscache_vary=$who" \
         http://127.0.0.1:8181/private/page.html -o /dev/null
done
run_scenario "Private HIT" /private/page.html 5000 50 \
    -H "Cookie: _lscache_vary=alice"

# 5. Tagged MISS - upstream-fetch + capture+rename writes a fresh entry every time.
run_scenario "Tagged MISS storm (capture + atomic rename)" /tagged/page.html 1000 25

# 6. Range request on cache HIT.
curl -s http://127.0.0.1:8181/cached/big.html -o /dev/null    # warm
run_scenario "Range HIT (slice cached body)" /cached/big.html 5000 50 \
    -H "Range: bytes=10-99"

# 7. If-Modified-Since 304 from cache.
LM=$(curl -s -D - -o /dev/null http://127.0.0.1:8181/cached/page.html \
        | awk -F': ' 'tolower($1)=="last-modified"{sub(/\r/,"",$2); print $2}' \
        | head -1)
NON2XX_OK=1 run_scenario "IMS 304 from cache" /cached/page.html 5000 50 \
    -H "If-Modified-Since: $LM"

# 8. Out-of-band tag PURGE storm while traffic hits the same tag.
#    Use ab itself as the PURGE driver so we can wait on a single PID
#    instead of 200 backgrounded curls (which can race with `wait`).
ab -q -n 200 -c 20 -m PURGE \
   -H "X-LiteSpeed-Purge: tag=home" \
   http://127.0.0.1:8181/purge/ >/dev/null 2>&1 &
PURGE_PID=$!
run_scenario "Tagged MISS while PURGE storm runs" /tagged/page.html 5000 50
wait "$PURGE_PID" 2>/dev/null

# 9. Stale-marker PURGE (lazy invalidation) - tests the read+modify+write path.
ab -q -n 200 -c 20 -m PURGE \
   -H "X-LiteSpeed-Purge: stale, tag=stale-test" \
   http://127.0.0.1:8181/purge/ >/dev/null 2>&1 &
PURGE_PID=$!
run_scenario "Stale PURGE storm in parallel" /stale-target/page.html 3000 30
wait "$PURGE_PID" 2>/dev/null

# ----------------------------------------------------------------------
# Post-stress checks
# ----------------------------------------------------------------------
echo ""
echo -e "${YELLOW}=== Post-stress checks ===${NC}"

if kill -0 $NPID 2>/dev/null; then
    echo -e "${GREEN}nginx master process still running${NC}"
else
    echo -e "${RED}nginx master process DIED during stress${NC}"
    total_fail=$((total_fail+1))
fi

WPID=$(pgrep -P $NPID | head -1)
if [ -n "$WPID" ] && kill -0 $WPID 2>/dev/null; then
    END_RSS=$(awk '/^VmRSS:/{print $2}' /proc/$WPID/status 2>/dev/null)
    GROWTH=$((END_RSS - START_RSS))
    echo "Worker RSS: ${START_RSS} KB -> ${END_RSS} KB  (delta=${GROWTH} KB)"
    if [ "$GROWTH" -gt 8192 ]; then
        echo -e "${RED}Suspicious memory growth (>8 MB)${NC}"
        total_fail=$((total_fail+1))
    else
        echo -e "${GREEN}Memory growth within bounds${NC}"
    fi
else
    echo -e "${RED}worker process gone${NC}"
    total_fail=$((total_fail+1))
fi

CRIT=$(grep -E "\[(alert|crit|emerg)\]" $NGINX_PREFIX/logs/error.log | wc -l)
if [ "$CRIT" -eq 0 ]; then
    echo -e "${GREEN}No alert/crit/emerg entries in error log${NC}"
else
    echo -e "${RED}$CRIT alert/crit/emerg entries:${NC}"
    grep -E "\[(alert|crit|emerg)\]" $NGINX_PREFIX/logs/error.log | head -5
    total_fail=$((total_fail+1))
fi

# Final liveness probe + a sanity HIT to confirm we still serve from cache.
status=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8181/cached/page.html)
xlsc=$(curl -s -D - -o /dev/null http://127.0.0.1:8181/cached/page.html \
        | awk -F': ' 'tolower($1)=="x-litespeed-cache"{sub(/\r/,"",$2); print $2}' \
        | head -1)
if [ "$status" = "200" ] && [ "$xlsc" = "hit,public" ]; then
    echo -e "${GREEN}Final liveness probe OK (status=200, X-LiteSpeed-Cache=$xlsc)${NC}"
else
    echo -e "${RED}Final liveness probe FAILED (status=$status, X-LiteSpeed-Cache='$xlsc')${NC}"
    total_fail=$((total_fail+1))
fi

# Cache integrity: count data files and confirm every one has a non-empty,
# magic-prefixed header.
BAD=0
while IFS= read -r f; do
    [ -f "$f" ] || continue
    [ -s "$f" ] || { BAD=$((BAD+1)); continue; }
    magic=$(head -c 4 "$f")
    [ "$magic" = "LSC1" ] || BAD=$((BAD+1))
done < <(find $CACHE_ROOT/data -type f ! -name "*.meta")
if [ "$BAD" -eq 0 ]; then
    echo -e "${GREEN}Cache file integrity OK (every data file starts with LSC1)${NC}"
else
    echo -e "${RED}$BAD corrupt cache files${NC}"
    total_fail=$((total_fail+1))
fi

kill $NPID 2>/dev/null
wait $NPID 2>/dev/null

echo ""
echo "======================================"
if [ "$total_fail" -eq 0 ]; then
    echo -e "${GREEN}Stress test: all $total_pass scenarios passed${NC}"
else
    echo -e "${RED}Stress test: $total_fail of $((total_pass+total_fail)) scenarios failed${NC}"
fi
echo "======================================"
exit $total_fail
