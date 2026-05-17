# 12 - If-Modified-Since -> 304 from cache.
#
# After serving a hit, the cache file's mtime becomes the Last-Modified
# value. A subsequent request with If-Modified-Since at or past that
# timestamp returns 304 Not Modified with no body.

lsc_purge /cached/page.html "*" > /dev/null 2>&1

# warm: miss then hit
begin_test "ims: warm cache"
assert_lsc GET /cached/page.html miss
assert_lsc GET /cached/page.html "hit,public"

# extract Last-Modified value
lm=$(curl -s -D - -o /dev/null "${BASE_URL}/cached/page.html" \
        | grep -i "^Last-Modified:" | head -1 \
        | sed 's/^[^:]*: *//' | tr -d '\r')

begin_test "ims: hit advertises Last-Modified"
if [ -n "$lm" ]; then pass; else fail "no Last-Modified header"; fi

begin_test "ims: matching If-Modified-Since returns 304"
status=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "If-Modified-Since: $lm" "${BASE_URL}/cached/page.html")
[ "$status" = "304" ] && pass || fail "expected 304, got $status"

begin_test "ims: stale If-Modified-Since still serves 200"
status=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "If-Modified-Since: Thu, 01 Jan 1970 00:00:00 GMT" \
    "${BASE_URL}/cached/page.html")
[ "$status" = "200" ] && pass || fail "expected 200, got $status"

# extract ETag value (nginx generates it from Last-Modified + Content-Length)
etag=$(curl -s -D - -o /dev/null "${BASE_URL}/cached/page.html" \
        | grep -i "^ETag:" | head -1 \
        | sed 's/^[^:]*: *//' | tr -d '\r')

begin_test "inm: hit advertises ETag"
if [ -n "$etag" ]; then pass; else fail "no ETag header"; fi

begin_test "inm: matching If-None-Match returns 304"
status=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "If-None-Match: $etag" "${BASE_URL}/cached/page.html")
[ "$status" = "304" ] && pass || fail "expected 304, got $status"

begin_test "inm: bogus If-None-Match still serves 200"
status=$(curl -s -o /dev/null -w "%{http_code}" \
    -H 'If-None-Match: "deadbeef-0"' "${BASE_URL}/cached/page.html")
[ "$status" = "200" ] && pass || fail "expected 200, got $status"
