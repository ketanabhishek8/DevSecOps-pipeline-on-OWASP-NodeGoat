#!/usr/bin/env bash
# Smoke and security regression tests for the running NodeGoat app.
#
# 1. Every page renders (HTTP 200), logged out and logged in, so a broken
#    template or dependency upgrade fails the pipeline instead of shipping.
# 2. Each fixed vulnerability stays fixed: the safe behaviour is asserted
#    with harmless inputs.
#
# Usage: scripts/smoke_test.sh [base_url]   (default http://localhost:4000)
# Logs in with the demo account from NodeGoat's seed data (app/README.md).

set -uo pipefail

BASE="${1:-http://localhost:4000}"
JAR="$(mktemp)"
trap 'rm -f "$JAR"' EXIT
failures=0

pass() { echo "  PASS  $1"; }
fail() { echo "  FAIL  $1"; failures=$((failures + 1)); }

status() {  # status <path> [extra curl args...] -> prints HTTP status code
    local path="$1"; shift
    curl -s -o /dev/null -w '%{http_code}' -b "$JAR" -c "$JAR" "$@" "$BASE$path"
}

body() {  # body <path> [extra curl args...] -> prints response body
    local path="$1"; shift
    curl -s -b "$JAR" -c "$JAR" "$@" "$BASE$path"
}

expect_status() {  # expect_status <expected> <label> <path> [curl args...]
    local expected="$1" label="$2" path="$3"; shift 3
    local got
    got="$(status "$path" "$@")"
    if [ "$got" = "$expected" ]; then pass "$label ($path -> $got)"; else fail "$label ($path -> $got, expected $expected)"; fi
}

echo "Public pages"
for path in /login /signup /tutorial /tutorial/a1 /tutorial/a10 /tutorial/ssrf; do
    expect_status 200 "renders" "$path"
done

echo "Log in as demo user"
status /login --data "userName=user1&password=User1_123" > /dev/null
expect_status 200 "session is authenticated" /dashboard

echo "Logged-in pages"
for path in /dashboard /profile /contributions /allocations/2 /memos /benefits /research; do
    expect_status 200 "renders" "$path"
done

echo "Regression: A03 server-side JS injection (contributions)"
page="$(body /contributions --data-urlencode "preTax=1+1" --data "afterTax=0&roth=0")"
if grep -q "Invalid contribution percentages" <<< "$page"; then
    pass "non-numeric input is rejected, not evaluated"
else
    fail "non-numeric input was accepted"
fi

echo "Regression: A03 cross-site scripting (memos, autoescape + marked sanitize)"
marker="smoke$RANDOM"
status /memos --data-urlencode "memo=**$marker** <script>alert('$marker')</script>" > /dev/null
page="$(body /memos)"
if grep -q "<strong>$marker</strong>" <<< "$page"; then pass "Markdown still renders"; else fail "Markdown output missing"; fi
if grep -q "<script>alert('$marker')" <<< "$page"; then fail "raw <script> reached the page"; else pass "raw <script> is escaped"; fi

echo "Regression: A01 open redirect (/learn)"
expect_status 404 "URL parameter no longer redirects" "/learn?url=https://example.com/"
expect_status 404 "unknown resource is refused" "/learn/example.com"
expect_status 302 "known resource still redirects" "/learn/traditional-iras"

echo "Regression: A10 SSRF (/research)"
expect_status 400 "URL in symbol is refused" "/research?symbol=http://169.254.169.254/"

echo
if [ "$failures" -gt 0 ]; then
    echo "$failures check(s) failed"
    exit 1
fi
echo "All checks passed"
