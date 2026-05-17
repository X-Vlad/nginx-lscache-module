# 13 - Range request from a cache hit.
#
# The PRECONTENT serve path sets r->allow_ranges, so nginx's built-in
# range filter slices the file buf accordingly.

lsc_purge /cached/big.html "*" > /dev/null 2>&1

begin_test "range: warm cache"
assert_lsc GET /cached/big.html miss
assert_lsc GET /cached/big.html "hit,public"

begin_test "range: bytes=0-9 returns 206 + first 10 bytes"
body=$(curl -s -H "Range: bytes=0-9" "${BASE_URL}/cached/big.html")
status=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Range: bytes=0-9" "${BASE_URL}/cached/big.html")
if [ "$status" = "206" ] && [ ${#body} -eq 10 ]; then
    pass
else
    fail "expected 206 + 10 bytes, got status=$status body-len=${#body}"
fi

begin_test "range: bytes=10-19 returns 206 + correct slice"
status=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Range: bytes=10-19" "${BASE_URL}/cached/big.html")
[ "$status" = "206" ] && pass || fail "expected 206, got $status"
