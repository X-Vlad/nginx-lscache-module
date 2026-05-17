# 10 - Inline purge from backend response
#
# Backend response on /inline-purge/ carries X-LiteSpeed-Purge: tag=home.
# When that response is processed, all tag=home entries should be purged.

lsc_purge /tagged/page.html "*" > /dev/null 2>&1

# Warm /tagged/ (carries tag=home).
begin_test "inline-purge: warm tagged cache"
assert_lsc GET /tagged/page.html miss
assert_lsc GET /tagged/page.html "hit,public"

# Hit /inline-purge/. Side effect: purges tag=home.
begin_test "inline-purge: response triggers purge"
assert_status GET /inline-purge/page.html 200

# Now /tagged/ should be miss again.
begin_test "inline-purge: tagged entry was purged"
assert_lsc GET /tagged/page.html miss
