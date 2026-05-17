# 04 - X-LiteSpeed-Vary handling

# Two different cookie values must produce two distinct cache slots.

lsc_purge /vary/page.html "*" > /dev/null 2>&1

begin_test "vary: first request as anonymous"
assert_lsc GET /vary/page.html miss

begin_test "vary: second anonymous hits public"
assert_lsc GET /vary/page.html "hit,public"

begin_test "vary: logged-in cookie creates a new entry"
assert_lsc GET /vary/page.html miss -H "Cookie: wp_logged_in=alice"

begin_test "vary: logged-in second call hits"
assert_lsc GET /vary/page.html "hit,public" -H "Cookie: wp_logged_in=alice"

begin_test "vary: anonymous still hits original entry"
assert_lsc GET /vary/page.html "hit,public"

begin_test "vary: different cookie value creates yet another entry"
assert_lsc GET /vary/page.html miss -H "Cookie: wp_logged_in=bob"
