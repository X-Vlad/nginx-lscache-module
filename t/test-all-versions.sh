#!/bin/bash
# Build the test image against each supported nginx release and run
# the full t/*.t.sh suite inside it. Useful as a release gate.
#
# Run from the project root:
#   bash t/test-all-versions.sh
#
# Override the matrix via VERSIONS env var:
#   VERSIONS="1.24.0 1.30.1" bash t/test-all-versions.sh

set -u

VERSIONS="${VERSIONS:-1.24.0 1.28.2 1.30.1}"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

PASSED=()
FAILED=()

for v in $VERSIONS; do
    echo ""
    echo -e "${BOLD}========================================"
    echo -e "  nginx ${v}"
    echo -e "========================================${NC}"
    tag="nginx-lscache-test:${v}"

    if ! docker build --build-arg "NGINX_VERSION=${v}" -t "$tag" . >/tmp/build-${v}.log 2>&1; then
        echo -e "${RED}build failed${NC}"
        tail -20 /tmp/build-${v}.log
        FAILED+=("$v (build)")
        continue
    fi
    echo -e "${GREEN}build ok${NC}"

    if docker run --rm "$tag" >/tmp/test-${v}.log 2>&1; then
        summary=$(grep -E "All [0-9]+ tests passed|of [0-9]+ failed" /tmp/test-${v}.log | tail -1)
        echo -e "${GREEN}tests passed${NC}  -  $summary"
        PASSED+=("$v")
    else
        echo -e "${RED}tests failed${NC}"
        tail -15 /tmp/test-${v}.log
        FAILED+=("$v")
    fi
done

echo ""
echo -e "${BOLD}========================================"
echo -e "  Summary"
echo -e "========================================${NC}"
for v in "${PASSED[@]}"; do
    echo -e "  ${GREEN}PASS${NC}  nginx ${v}"
done
for v in "${FAILED[@]}"; do
    echo -e "  ${RED}FAIL${NC}  nginx ${v}"
done

if [ ${#FAILED[@]} -eq 0 ]; then
    echo ""
    echo -e "${GREEN}${BOLD}All nginx versions passed.${NC}"
    exit 0
else
    echo ""
    echo -e "${RED}${BOLD}${#FAILED[@]} of $(($(echo "$VERSIONS" | wc -w))) failed.${NC}"
    exit 1
fi
