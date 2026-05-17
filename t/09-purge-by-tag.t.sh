# 09 - PURGE by tag

lsc_purge /tagged/page.html "*" > /dev/null 2>&1
lsc_purge /cached/page.html "*" > /dev/null 2>&1

# /tagged/ carries tags "home" and "sidebar".
begin_test "tagged: warm cache (miss then hit)"
assert_lsc GET /tagged/page.html miss
assert_lsc GET /tagged/page.html "hit,public"

# untagged /cached/ should NOT be purged by tag.
begin_test "untagged peer: warm cache"
assert_lsc GET /cached/page.html miss
assert_lsc GET /cached/page.html "hit,public"

begin_test "PURGE tag=home returns 200"
status=$(lsc_purge /purge/ "tag=home")
[ "$status" = "200" ] && pass || fail "expected 200, got $status"

begin_test "PURGE tag=home wipes tagged entry"
assert_lsc GET /tagged/page.html miss

begin_test "PURGE tag=home does NOT affect untagged entry"
assert_lsc GET /cached/page.html "hit,public"
