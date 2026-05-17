# 03 - Header sanitization
#
# Backend emits X-LiteSpeed-*, LSC-Cookie. The client must NOT see any of
# those. The client SHOULD see X-LiteSpeed-Cache and (for LSC-Cookie pages)
# a Set-Cookie materialized from the side channel.

lsc_purge /tagged/page.html  "*" > /dev/null 2>&1
lsc_purge /vary/page.html    "*" > /dev/null 2>&1
lsc_purge /lsc-cookie/page.html "*" > /dev/null 2>&1

begin_test "X-LiteSpeed-Cache-Control stripped from response"
assert_no_header GET /tagged/page.html "X-LiteSpeed-Cache-Control"

begin_test "X-LiteSpeed-Tag stripped from response"
assert_no_header GET /tagged/page.html "X-LiteSpeed-Tag"

begin_test "X-LiteSpeed-Vary stripped from response"
assert_no_header GET /vary/page.html "X-LiteSpeed-Vary"

begin_test "LSC-Cookie stripped from response"
assert_no_header GET /lsc-cookie/page.html "LSC-Cookie"

begin_test "X-LiteSpeed-Cache present on caching scope"
assert_header GET /tagged/page.html "X-LiteSpeed-Cache" ""
