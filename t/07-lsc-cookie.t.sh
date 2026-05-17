# 07 - LSC-Cookie side channel
#
# Backend emits LSC-Cookie instead of Set-Cookie. The response IS
# cacheable, and on every served response (miss or hit) we materialize
# the LSC-Cookie value as a Set-Cookie header.

lsc_purge /lsc-cookie/page.html "*" > /dev/null 2>&1

begin_test "lsc-cookie: first request is miss"
assert_lsc GET /lsc-cookie/page.html miss

begin_test "lsc-cookie: client sees Set-Cookie on miss"
assert_header GET /lsc-cookie/page.html "Set-Cookie" "lsc_flag=1"

begin_test "lsc-cookie: second request is hit,public"
assert_lsc GET /lsc-cookie/page.html "hit,public"

begin_test "lsc-cookie: client sees Set-Cookie on hit"
assert_header GET /lsc-cookie/page.html "Set-Cookie" "lsc_flag=1"
