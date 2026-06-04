#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

curl -sw "\nHTTP %{http_code}\n" http://localhost:8000/debug/
