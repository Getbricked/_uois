#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

TOKEN=$(python3 -c "
import json, base64, hmac, hashlib, time
h='{\"alg\":\"HS256\",\"typ\":\"JWT\"}'
p=json.dumps({'iss':'https://accounts.google.com','sub':'bad','exp':int(time.time())+3600}, separators=(',',':'))
b=lambda d:base64.urlsafe_b64encode(d).rstrip(b'=').decode()
m=b(h.encode())+'.'+b(p.encode())
s=b(hmac.new(b'whatever',m.encode(),hashlib.sha256).digest())
print(m+'.'+s)")

curl -sw "\nHTTP %{http_code}\n" -H "Authorization: Bearer $TOKEN" http://localhost:8000/debug/
