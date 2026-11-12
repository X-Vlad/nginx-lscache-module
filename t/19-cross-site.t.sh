# 19 - One site can never write into, or purge, another site's cache.
#
# nginx picks the server by the host in an absolute request line and
# ignores the Host header then. A key built from the raw Host header
# would file site A's answer under site B's name.

hdrs() { curl -s -D - -o /dev/null "$@"; }

lsc_purge /cached/page.html "*" > /dev/null 2>&1
curl -s -o /dev/null -X PURGE -H "Host: b.test" -H "X-LiteSpeed-Purge: *" "${BASE_URL}/"

begin_test "cross-site: request line names site A, Host header names site B: served by A"
body=$(curl -s --request-target "http://localhost/cached/poison.html" -H "Host: b.test" "${BASE_URL}/")
case "$body" in *SITE-A*) pass ;; *) fail "unexpected body: $body" ;; esac

begin_test "cross-site: site B's visitor gets site B's page, not A's"
body=$(curl -s -H "Host: b.test" "${BASE_URL}/cached/poison.html")
case "$body" in *SITE-B*) pass ;; *) fail "site B got: $body" ;; esac

begin_test "cross-site: and it was a miss for site B (nothing was planted)"
curl -s -o /dev/null -X PURGE -H "Host: b.test" -H "X-LiteSpeed-Purge: *" "${BASE_URL}/"
curl -s -o /dev/null --request-target "http://localhost/cached/poison.html" -H "Host: b.test" "${BASE_URL}/"
actual=$(hdrs -H "Host: b.test" "${BASE_URL}/cached/poison.html" | grep -i "^X-LiteSpeed-Cache:" | tr -d '\r')
case "$actual" in *miss*) pass ;; *) fail "got '$actual'" ;; esac

begin_test "cross-site: site A's inline purge (tag=home) with Host: b.test leaves B's entry"
curl -s -o /dev/null -H "Host: b.test" "${BASE_URL}/cached/page.html"
curl -s -o /dev/null --request-target "http://localhost/inline-purge/page.html" -H "Host: b.test" "${BASE_URL}/"
actual=$(hdrs -H "Host: b.test" "${BASE_URL}/cached/page.html" | grep -i "^X-LiteSpeed-Cache:" | tr -d '\r')
case "$actual" in *hit,public*) pass ;; *) fail "B's entry is gone: '$actual'" ;; esac

begin_test "cross-site: site B's inline purge of '*' leaves site A's entries"
curl -s -o /dev/null "${BASE_URL}/cached/page.html"
curl -s -o /dev/null -H "Host: b.test" "${BASE_URL}/purge-other/page.html"
assert_lsc GET /cached/page.html "hit,public"

begin_test "cross-site: ...and did purge site B's own"
actual=$(hdrs -H "Host: b.test" "${BASE_URL}/cached/page.html" | grep -i "^X-LiteSpeed-Cache:" | tr -d '\r')
case "$actual" in *miss*) pass ;; *) fail "got '$actual'" ;; esac
