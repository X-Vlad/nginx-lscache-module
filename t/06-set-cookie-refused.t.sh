# 06 - Set-Cookie + public = refuse to cache (session-leak guard)

lsc_purge /set-cookie/page.html "*" > /dev/null 2>&1

begin_test "set-cookie + public: refused (no-cache)"
assert_lsc GET /set-cookie/page.html no-cache

begin_test "set-cookie + public: still no-cache on second call"
assert_lsc GET /set-cookie/page.html no-cache

# The upstream Set-Cookie itself should pass through to the client
# (we only refused to STORE, we did not strip the cookie).
begin_test "set-cookie passes through to client"
assert_header GET /set-cookie/page.html "Set-Cookie" "session=abc"
