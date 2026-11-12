# 22 - The private cache is one visitor's, and the default vary splits
# the public cache the way LiteSpeed does.

lsc_purge /private/page.html "private,*" > /dev/null 2>&1
lsc_purge /cached/page.html "*" > /dev/null 2>&1

begin_test "private: alice stores and hits her copy"
assert_lsc GET /private/page.html miss -H "Cookie: wordpress_logged_in_x=alice; _lscache_vary=role1"
assert_lsc GET /private/page.html "hit,private" -H "Cookie: wordpress_logged_in_x=alice; _lscache_vary=role1"

begin_test "private: bob with the same role cookie does NOT get alice's copy"
assert_lsc GET /private/page.html miss -H "Cookie: wordpress_logged_in_x=bob; _lscache_vary=role1"

begin_test "private: a visitor without cookies never reads or writes it"
assert_lsc GET /private/page.html miss
assert_lsc GET /private/page.html miss

begin_test "private: a private entry is never served on the public fast path"
assert_lsc GET /private/page.html "hit,private" -H "Cookie: wordpress_logged_in_x=alice; _lscache_vary=role1"
actual=$(lsc_cache_status GET /private/page.html -H "Cookie: other=1")
case "$actual" in hit*) fail "a stranger got '$actual'" ;; *) pass ;; esac

begin_test "default vary: a guest's public page is not served to a role cookie"
assert_lsc GET /cached/page.html miss
assert_lsc GET /cached/page.html "hit,public"
assert_lsc GET /cached/page.html miss -H "Cookie: _lscache_vary=role1"

begin_test "default vary: the role has a copy of its own, the guest keeps theirs"
assert_lsc GET /cached/page.html "hit,public" -H "Cookie: _lscache_vary=role1"
assert_lsc GET /cached/page.html "hit,public"

begin_test "default vary: purging the URL removes both copies"
n=$(lsc_purge_ok /cached/page.html)
if [ "$n" = "2" ]; then pass; else fail "purged '$n' entries, expected 2"; fi

begin_test "lscache_vary_extra: mobile and desktop do not share a page"
lsc_purge /mobile/page.html "*" > /dev/null 2>&1
assert_lsc GET /mobile/page.html miss -A "Desktop"
assert_lsc GET /mobile/page.html "hit,public" -A "Desktop"
assert_lsc GET /mobile/page.html miss -A "Phone Mobile"
assert_lsc GET /mobile/page.html "hit,public" -A "Phone Mobile"
