# 25 - lscache_max_size holds (300k in the test config), with the
# bounded sweep and the shared size counter. Runs last: it evicts.

begin_test "size limit: 200 pages of 8k end up within the limit"
for i in $(seq 1 200); do curl -s -o /dev/null "${BASE_URL}/sweep/p$i.html"; done
for i in $(seq 1 70); do curl -s -o /dev/null "${BASE_URL}/sweep/p$i.html?again=$i"; done
bytes=$(find "$LSCACHE_ROOT/data" -type f ! -name '*.meta' -printf '%s\n' | awk '{s+=$1} END {print s+0}')
if [ "$bytes" -le 900000 ] && [ "$bytes" -gt 0 ]; then pass; else fail "data files take $bytes bytes"; fi

begin_test "size limit: every data file left has its meta, and every meta its data"
bad=0
for f in $(find "$LSCACHE_ROOT/data" -type f ! -name '*.meta'); do [ -f "$f.meta" ] || bad=$((bad+1)); done
for f in $(find "$LSCACHE_ROOT/data" -type f -name '*.meta'); do [ -f "${f%.meta}" ] || bad=$((bad+1)); done
if [ "$bad" = "0" ]; then pass; else fail "$bad files without their pair"; fi

begin_test "size limit: no index marker points at an evicted entry"
bad=0
for f in $(find "$LSCACHE_ROOT/hosts" "$LSCACHE_ROOT/tags" "$LSCACHE_ROOT/vary" -type f); do
    k=$(basename "$f"); [ -f "$LSCACHE_ROOT/data/${k:0:2}/${k:2:2}/$k" ] || bad=$((bad+1))
done
if [ "$bad" = "0" ]; then pass; else fail "$bad markers without an entry"; fi

begin_test "size limit: the cache still works after eviction"
lsc_purge /cached/page.html "*" > /dev/null 2>&1
assert_lsc GET /cached/page.html miss
assert_lsc GET /cached/page.html "hit,public"
