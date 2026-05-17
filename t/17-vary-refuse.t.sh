# 17 - RFC 7234 Vary safety.
#
# Vary: Accept-Encoding is the one allowed value (gzip variation is
# transparent to our cache). Anything else (User-Agent, Cookie, *)
# means responses cannot be safely shared across clients - we refuse.

lsc_purge /vary-other/page.html    "*" > /dev/null 2>&1
lsc_purge /vary-encoding/page.html "*" > /dev/null 2>&1

begin_test "vary-refuse: Vary: User-Agent yields no-cache"
assert_lsc GET /vary-other/page.html no-cache
assert_lsc GET /vary-other/page.html no-cache

begin_test "vary-refuse: Vary: Accept-Encoding still caches"
assert_lsc GET /vary-encoding/page.html miss
assert_lsc GET /vary-encoding/page.html "hit,public"
