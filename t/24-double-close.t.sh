# 24 - Storing a page must not close a descriptor twice.
#
# The second close used to hit whatever got the number in between:
# here, another visitor's keep-alive connection.

begin_test "double close: a visitor's connection survives another one's store"
if command -v python3 >/dev/null 2>&1; then
    lsc_purge /cached/huge.html "*" > /dev/null 2>&1
    out=$(python3 "${SCRIPT_DIR}/double_close.py" 8181 /cached/huge.html 2>&1)
    case "$out" in *"SECOND OK"*) pass ;; *) fail "$out" ;; esac
else
    echo "  (python3 not found, skipped)"; pass
fi
