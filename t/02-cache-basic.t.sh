# 02 - Cache control basics: miss, hit, no-cache, expiry, no-directive

# First GET on /cached/page.html: miss.
begin_test "first GET is miss"
# warm up: ensure cache is empty
lsc_purge /cached/page.html "*" > /dev/null 2>&1
assert_lsc GET /cached/page.html miss

# Second GET within max-age: hit,public.
begin_test "second GET is hit,public"
assert_lsc GET /cached/page.html "hit,public"

# Body served from cache matches the upstream body.
begin_test "cached body matches upstream"
body=$(curl -s "${BASE_URL}/cached/page.html")
case "$body" in
    *cached*page.html*) pass ;;
    *) fail "unexpected cached body: $body" ;;
esac

# no-cache directive: every GET is a pass-through miss.
begin_test "no-cache: every GET is miss"
lsc_purge /no-cache/page.html "*" > /dev/null 2>&1
assert_lsc GET /no-cache/page.html miss
assert_lsc GET /no-cache/page.html miss

# No X-LiteSpeed-Cache-Control at all -> X-LiteSpeed-Cache header omitted.
begin_test "no upstream directive: no X-LiteSpeed-Cache header"
actual=$(lsc_cache_status GET /uncontrolled/page.html)
if [ -z "$actual" ]; then
    pass
else
    fail "unexpected X-LiteSpeed-Cache: '$actual'"
fi

# Short max-age expires properly.
begin_test "short max-age: hit then expired"
lsc_purge /short/page.html "*" > /dev/null 2>&1
assert_lsc GET /short/page.html miss
assert_lsc GET /short/page.html "hit,public"
sleep 3
assert_lsc GET /short/page.html miss
