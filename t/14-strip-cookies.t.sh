# 14 - lscache_strip_cookies removes named cookies from the cache key.
#
# The /strip-cookies/ location declares X-LiteSpeed-Vary: cookie=_ga,
# but also has `lscache_strip_cookies _ga _gid`. Two requests with
# different _ga values therefore land in the SAME cache slot.

lsc_purge /strip-cookies/page.html "*" > /dev/null 2>&1

begin_test "strip-cookies: first GET with _ga=alice is miss"
assert_lsc GET /strip-cookies/page.html miss -H "Cookie: _ga=alice"

begin_test "strip-cookies: second GET with _ga=bob still hits (cookie stripped)"
assert_lsc GET /strip-cookies/page.html "hit,public" -H "Cookie: _ga=bob"

begin_test "strip-cookies: third GET with no cookie also hits"
assert_lsc GET /strip-cookies/page.html "hit,public"
