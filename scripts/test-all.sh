#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

echo "===== 1. VSR token (valid HMAC) ====="
bash test-vsr-token.sh
echo ""

echo "===== 2. Google token (wrong issuer) ====="
bash test-google-token.sh
echo ""

echo "===== 3. No token ====="
bash test-no-token.sh
echo ""

echo "===== 4. VSR issuer + bad HMAC ====="
bash test-bad-signature.sh
echo ""

echo "===== 5. John Newbie (OAuth RS256) ====="
bash test-john-newbie.sh