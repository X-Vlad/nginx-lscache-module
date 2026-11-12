# 21 - A hit carries the headers the backend sent, not only the body.

hdrs() { curl -s -D - -o /dev/null "$@" | tr -d '\r'; }

lsc_purge /redirect/x "*" > /dev/null 2>&1

begin_test "redirect: miss has Location"
h=$(hdrs "${BASE_URL}/redirect/x")
if echo "$h" | grep -qi "^Location: .*/cached/page.html" && echo "$h" | grep -q "X-LiteSpeed-Cache: miss"; then pass; else fail "$h"; fi

begin_test "redirect: hit has status 301 and Location"
h=$(hdrs "${BASE_URL}/redirect/x")
if echo "$h" | grep -q "^HTTP/1.1 301" && echo "$h" | grep -qi "^Location: .*/cached/page.html" && echo "$h" | grep -q "X-LiteSpeed-Cache: hit,public"; then pass; else fail "$h"; fi

begin_test "headers: hit keeps Content-Security-Policy, X-Frame-Options, Cache-Control"
curl -s -o /dev/null "${BASE_URL}/headers/page.html"
h=$(hdrs "${BASE_URL}/headers/page.html")
if echo "$h" | grep -q "X-LiteSpeed-Cache: hit,public" \
   && echo "$h" | grep -qi "^Content-Security-Policy: default-src 'none'" \
   && echo "$h" | grep -qi "^X-Frame-Options: DENY" \
   && echo "$h" | grep -qi "^Cache-Control: max-age=5"; then pass; else fail "$h"; fi

begin_test "headers: hit never replays the backend's Set-Cookie, only LSC-Cookie"
if echo "$h" | grep -qi "private_session"; then fail "a visitor's cookie came out of the cache"
elif echo "$h" | grep -qi "^Set-Cookie: lsc_shared=1"; then pass
else fail "LSC-Cookie missing: $h"; fi

begin_test "headers: no protocol header reaches the client"
if echo "$h" | grep -qi "^X-LiteSpeed-Cache-Control\|^X-LiteSpeed-Tag\|^LSC-Cookie"; then fail "$h"; else pass; fi

begin_test "gzip from the backend: not stored (it fits only some clients)"
curl -s -o /dev/null "${BASE_URL}/gzipped/page.html"
h=$(hdrs "${BASE_URL}/gzipped/page.html")
if echo "$h" | grep -qi "^Content-Encoding: gzip" && echo "$h" | grep -q "X-LiteSpeed-Cache: no-cache"; then pass; else fail "$h"; fi

begin_test "gzip from the backend: the body still decodes"
body=$(curl -s --compressed "${BASE_URL}/gzipped/page.html")
case "$body" in *gzipped*) pass ;; *) fail "body: $body" ;; esac

# The backend answers the validator itself with 304 (and still sends its
# cache headers). That answer is one client's and has no body.
begin_test "conditional miss: a 304 from the backend is not stored as the page"
lsc_purge /etag/page.html "*" > /dev/null 2>&1
etag=$(curl -s -D - -o /dev/null "http://127.0.0.1:8189/etag/page.html" | grep -i "^ETag:" | sed 's/^[^:]*: *//' | tr -d '\r')
st=$(curl -s -o /dev/null -w "%{http_code}" -H "If-None-Match: $etag" "${BASE_URL}/etag/page.html")
st2=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/etag/page.html")
body=$(curl -s "${BASE_URL}/etag/page.html")
if [ "$st" = "304" ] && [ "$st2" = "200" ] && echo "$body" | grep -q "etag"; then pass; else fail "first=$st then=$st2 body=$body"; fi

begin_test "HEAD on a cold URL stores nothing; the GET after it has a body"
lsc_purge /cached/page.html "*" > /dev/null 2>&1
curl -s -I -o /dev/null "${BASE_URL}/cached/page.html"
body=$(curl -s "${BASE_URL}/cached/page.html")
case "$body" in *cached*) pass ;; *) fail "body: $body" ;; esac
