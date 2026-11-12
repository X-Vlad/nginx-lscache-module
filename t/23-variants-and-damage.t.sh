# 23 - Bounded variants, and entries with a missing or damaged file.

lsc_purge /variants/page.html "*" > /dev/null 2>&1

begin_test "variants: the first three vary values are stored"
for v in 1 2 3; do curl -s -o /dev/null -H "Cookie: v=$v" "${BASE_URL}/variants/page.html"; done
ok=1
for v in 1 2 3; do
    [ "$(lsc_cache_status GET /variants/page.html -H "Cookie: v=$v")" = "hit,public" ] || ok=0
done
if [ $ok = 1 ]; then pass; else fail "a stored variant did not hit"; fi

begin_test "variants: the fourth is passed on, not stored (lscache_max_variants 3)"
curl -s -o /dev/null -H "Cookie: v=4" "${BASE_URL}/variants/page.html"
actual=$(lsc_cache_status GET /variants/page.html -H "Cookie: v=4")
if [ "$actual" = "miss" ]; then pass; else fail "got '$actual'"; fi

begin_test "damage: an entry without its .meta is a miss, not a broken hit"
lsc_purge /cached/page.html "*" > /dev/null 2>&1
curl -s -o /dev/null "${BASE_URL}/cached/page.html"
# find the meta of /cached/page.html: the newest one
meta=$(ls -t "$LSCACHE_ROOT"/data/*/*/*.meta | head -1)
unlink "$meta"
h=$(curl -s -D - -o /dev/null "${BASE_URL}/cached/page.html" | tr -d '\r')
if echo "$h" | grep -q "X-LiteSpeed-Cache: miss" && echo "$h" | grep -qi "^Content-Type: text/html"; then pass; else fail "$h"; fi

begin_test "damage: a data file cut short is a miss"
curl -s -o /dev/null "${BASE_URL}/cached/page.html"
data=$(ls -t "$LSCACHE_ROOT"/data/*/*/*.meta | head -1); data="${data%.meta}"
truncate -s 30 "$data"
assert_lsc GET /cached/page.html miss

begin_test "cleanup: purging a tag removes its emptied index folder"
lsc_purge /tagged/page.html "*" > /dev/null 2>&1
curl -s -o /dev/null "${BASE_URL}/tagged/page.html"
if [ -d "$LSCACHE_ROOT/tags/sidebar" ]; then
    lsc_purge /tagged/page.html "tag=sidebar" > /dev/null
    if [ -d "$LSCACHE_ROOT/tags/sidebar" ]; then
        fail "tags/sidebar is still there"
    else pass; fi
else fail "tags/sidebar was not made"; fi
