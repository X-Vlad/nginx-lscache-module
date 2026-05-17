# 01 - PURGE method handler + IP ACL

# PURGE from 127.0.0.1 (in default ACL) returns 200 + the count header.
begin_test "PURGE from localhost returns 200"
assert_status PURGE /purge/ 200

# Response carries X-LiteSpeed-Purge-OK with a numeric count.
begin_test "PURGE response carries X-LiteSpeed-Purge-OK"
ok=$(lsc_purge_ok /purge/)
if [[ "$ok" =~ ^[0-9]+$ ]]; then
    pass
else
    fail "X-LiteSpeed-Purge-OK absent or non-numeric: '$ok'"
fi

# PURGE on an off scope falls through to nginx default (no PURGE allowed).
begin_test "PURGE on lscache-off scope is not 200"
status=$(curl -s -o /dev/null -w "%{http_code}" -X PURGE "${BASE_URL}/uncontrolled-but-off/")
if [ "$status" != "200" ]; then
    pass
else
    fail "PURGE on lscache off scope returned 200"
fi
