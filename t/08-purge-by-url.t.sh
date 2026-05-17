# 08 - Out-of-band PURGE by URL

lsc_purge /cached/page.html "*" > /dev/null 2>&1

# warm the cache
begin_test "warm cache: first GET is miss"
assert_lsc GET /cached/page.html miss
begin_test "warm cache: second GET is hit"
assert_lsc GET /cached/page.html "hit,public"

begin_test "PURGE url=/cached/page.html returns 200"
status=$(lsc_purge /cached/page.html "url=/cached/page.html")
[ "$status" = "200" ] && pass || fail "expected 200, got $status"

begin_test "GET after PURGE is miss again"
assert_lsc GET /cached/page.html miss
