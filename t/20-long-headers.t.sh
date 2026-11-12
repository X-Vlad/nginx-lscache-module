# 20 - Protocol headers longer than a meta record takes.
#
# A 12000-byte X-LiteSpeed-Vary used to run past the end of the meta
# buffer (heap overflow in the worker). Now such a response is passed
# on and not stored. The runner fails the whole run if a worker died.

begin_test "long vary: the page is served"
assert_status GET /long-vary/page.html 200

begin_test "long vary: it is not stored"
assert_lsc GET /long-vary/page.html "no-cache"
assert_lsc GET /long-vary/page.html "no-cache"

begin_test "long vary: the worker is still the same one"
p1=$(pgrep -f "nginx: worker" | sort | tr '\n' ' ')
curl -s -o /dev/null "${BASE_URL}/long-vary/page.html"; sleep 0.3
p2=$(pgrep -f "nginx: worker" | sort | tr '\n' ' ')
if [ "$p1" = "$p2" ]; then pass; else fail "workers changed: $p1 -> $p2"; fi
