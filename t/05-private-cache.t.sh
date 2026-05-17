# 05 - Private cache (per-client_id slots)
#
# All test requests originate from 127.0.0.1, so the remote_addr fallback
# would collapse two "users" into one entry. We exercise the private path
# by giving each user a distinct _lscache_vary cookie (the canonical WP
# plugin client id).

lsc_purge /private/page.html "private,*" > /dev/null 2>&1

begin_test "private: alice first request is miss"
assert_lsc GET /private/page.html miss -H "Cookie: _lscache_vary=alice"

begin_test "private: alice second request is hit,private"
assert_lsc GET /private/page.html "hit,private" -H "Cookie: _lscache_vary=alice"

begin_test "private: bob first request is miss (separate slot)"
assert_lsc GET /private/page.html miss -H "Cookie: _lscache_vary=bob"

begin_test "private: bob second request is hit,private"
assert_lsc GET /private/page.html "hit,private" -H "Cookie: _lscache_vary=bob"

begin_test "private: alice still hits her own slot"
assert_lsc GET /private/page.html "hit,private" -H "Cookie: _lscache_vary=alice"
