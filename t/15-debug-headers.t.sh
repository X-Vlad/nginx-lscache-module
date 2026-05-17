# 15 - lscache_debug emits X-LSCache-Debug-Key on miss and hit.

lsc_purge /debug/page.html "*" > /dev/null 2>&1

begin_test "debug: miss carries X-LSCache-Debug-Key"
key=$(curl -s -D - -o /dev/null "${BASE_URL}/debug/page.html" \
        | grep -i "^X-LSCache-Debug-Key:" | head -1 \
        | sed 's/^[^:]*: *//' | tr -d '\r')
if [[ "$key" =~ ^[0-9a-f]{40}$ ]]; then
    pass
else
    fail "no/invalid debug key on miss: '$key'"
fi

begin_test "debug: hit also carries X-LSCache-Debug-Key (same hex)"
key2=$(curl -s -D - -o /dev/null "${BASE_URL}/debug/page.html" \
         | grep -i "^X-LSCache-Debug-Key:" | head -1 \
         | sed 's/^[^:]*: *//' | tr -d '\r')
if [ "$key" = "$key2" ]; then
    pass
else
    fail "hit debug key differs from miss key ('$key2' vs '$key')"
fi
