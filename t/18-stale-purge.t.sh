# 18 - PURGE stale,... marks entries stale instead of deleting.
#
# After a stale PURGE: the next request observes "miss" (entry was
# treated as not-fresh and the upstream response captures + overwrites).
# Without the stale flag, "stale," is the lazy form: data file stays
# on disk (with LSC_FF_STALE set) until the next request replaces it.

lsc_purge /stale-target/page.html "*" > /dev/null 2>&1

begin_test "stale: warm cache"
assert_lsc GET /stale-target/page.html miss
assert_lsc GET /stale-target/page.html "hit,public"

begin_test "stale: PURGE stale, tag=stale-test returns 200"
status=$(lsc_purge /purge/ "stale, tag=stale-test")
[ "$status" = "200" ] && pass || fail "expected 200, got $status"

begin_test "stale: next GET re-fetches (miss)"
assert_lsc GET /stale-target/page.html miss

begin_test "stale: subsequent GET is hit again (fresh overwrite)"
assert_lsc GET /stale-target/page.html "hit,public"

begin_test "stale: per-tag ~s suffix also marks stale"
status=$(lsc_purge /purge/ "stale-test~s")
[ "$status" = "200" ] && pass || fail "expected 200, got $status"
assert_lsc GET /stale-target/page.html miss
