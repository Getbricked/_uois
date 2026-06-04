#!/usr/bin/env bash
KEY=$(curl -s http://localhost:8000/oauth/login3 | python3 -c "import sys,json;print(json.load(sys.stdin)['key'])")
TOKEN=$(curl -s -X POST http://localhost:8000/oauth/login3 -H "Content-Type: application/json" -d "{\"username\":\"john.newbie@world.com\",\"password\":\"john.newbie@world.com\",\"key\":\"$KEY\"}" | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")
curl -sw "\nHTTP %{http_code}\n" -b "authorization=$TOKEN" http://localhost:8000/debug/
