# 16 - lscache_min_uses gates storing until the Nth request.
#
# /min-uses/ has lscache_min_uses 3. First two GETs must NOT cache.
# Third must store; fourth must hit.

lsc_purge /min-uses/page.html "*" > /dev/null 2>&1

begin_test "min-uses: GET 1 is no-cache"
assert_lsc GET /min-uses/page.html no-cache

begin_test "min-uses: GET 2 is no-cache"
assert_lsc GET /min-uses/page.html no-cache

begin_test "min-uses: GET 3 stores -> miss"
assert_lsc GET /min-uses/page.html miss

begin_test "min-uses: GET 4 is hit"
assert_lsc GET /min-uses/page.html "hit,public"
