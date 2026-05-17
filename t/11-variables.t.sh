# 11 - Module variables $lscache_status and $lscache_key
#
# These are exposed for log_format. We don't capture access logs in this
# test runner, so we just sanity-check via $lscache_status fronting a
# debug response header. The test config doesn't expose those variables
# in headers by default, so this test is a smoke check that the variables
# are accepted by the config parser. A failure means nginx -t fails on
# config load, and the suite never reaches us.

begin_test "variables parse: server is up"
status=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/cached/page.html")
if [ "$status" = "200" ]; then
    pass
else
    fail "server returned $status (expected 200)"
fi
