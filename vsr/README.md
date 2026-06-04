# VSR Auth — Developer Guide

## Quick Start

### 1. Install dependencies

Make sure you are inside the `_uois` directory!

Create a virtual environment:
```bash
python -m venv .venv
```

Activate it and install dependencies:
```bash
source .venv/bin/activate # for Linux

.venv/Scripts/Activate.ps1 # for Windows

pip install -r requirements-dev.txt
```

### 2. Start the server

```bash
CONNECTION_STRING="sqlite+aiosqlite:///test_vsr.db" \
SALT="test-salt" \
DEMO=True \
python -m uvicorn server.main-vsr:app --port 8000
```

Set `DEMO=False` to also enable the original OAuth auth backend.

### 3. Run all tests (in another terminal)

Since we are using dotenv, it is required to activate the python environment:
Make sure you are inside the `_uois` directory!

```bash
source .venv/bin/activate # for Linux
# or
.venv/Scripts/Activate.ps1 # for Windows  
bash scripts/test-all.sh
```

---

## Getting a Token

### Option A — VSR token (HS256, self-signed)

Generate locally using the shared secret:

```bash
TOKEN=$(python3 -c "
import json, base64, hmac, hashlib, time
from vsr.vsr_auth import VSR_ISSUER, VSR_SECRET
h='{\"alg\":\"HS256\",\"typ\":\"JWT\"}'
p=json.dumps({'iss':VSR_ISSUER,'sub':'vsr-user-001','user_id':'vsr-user-001','exp':int(time.time())+3600}, separators=(',',':'))
b=lambda d:base64.urlsafe_b64encode(d).rstrip(b'=').decode()
m=b(h.encode())+'.'+b(p.encode())
s=b(hmac.new(VSR_SECRET.encode(),m.encode(),hashlib.sha256).digest())
print(m+'.'+s)
")
```

### Option B — OAuth RS256 token (from the OAuth server)

Uses the built-in login flow:

```bash
KEY=$(curl -s http://localhost:8000/oauth/login3 | python3 -c "import sys,json;print(json.load(sys.stdin)['key'])")
TOKEN=$(curl -s -X POST http://localhost:8000/oauth/login3 \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"john.newbie@world.com\",\"password\":\"john.newbie@world.com\",\"key\":\"$KEY\"}" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")
```

Default credentials: `john.newbie@world.com` / `john.newbie@world.com`.

---

## How to Send Requests

The `/debug` endpoint reads the token from the `authorization` **cookie**:

```bash
curl -sw "\nHTTP %{http_code}\n" -b "authorization=$TOKEN" http://localhost:8000/debug/
```

Other endpoints (index, api, generic) read from the **Authorization header**:

```bash
curl -sw "\nHTTP %{http_code}\n" -H "Authorization: Bearer $TOKEN" http://localhost:8000/index/
```

---

## Test Scenarios

| Test | Command | Expected Status | What happens |
|---|---|---|---|
| Valid VSR token | `bash scripts/test-vsr-token.sh` | **200** | VSRPolicyMiddleware passes (issuer matches), HybridAuthBackend verifies HMAC, user authenticated |
| Google-issuer token | `bash scripts/test-google-token.sh` | **403** | VSRPolicyMiddleware sees iss=google.com, returns 403 immediately (no sig check needed) |
| No token (DEMO=True) | `bash scripts/test-no-token.sh` | **200** | VSRPolicyMiddleware passes, HybridAuthBackend returns anonymous (original_backend=None) |
| No token (DEMO=False) | `bash scripts/test-no-token.sh` | **302** | VSRPolicyMiddleware passes, HybridAuthBackend falls through to original auth which redirects to /oauth/login2 |
| VSR issuer + bad HMAC | `bash scripts/test-bad-signature.sh` | **302** | VSRPolicyMiddleware passes (issuer looks correct), HybridAuthBackend HMAC fails, AuthenticationMiddleware catches and redirects to login |
| Real OAuth RS256 token (DEMO=False) | see "Option B" | **200** | OAuth token has no `iss` claim → passes VSRPolicyMiddleware. Falls through to original auth (RS256 verify) |

---

## Expected Results Matrix

| Token | DEMO=True | DEMO=False |
|---|---|---|
| VSR HS256 (valid sig, iss=VSR) | 200 | 200 |
| Google HS256 (iss=google.com) | 403 | 403 |
| OAuth RS256 (no `iss` claim) | 200 (anonymous) | 200 (full auth) |
| No token | 200 (anonymous) | 302 (redirect to login) |
| VSR + bad sig (iss=VSR) | 302 | 302 |

---

## Customizing Configuration

In `vsr/vsr_auth.py`:

```python
VSR_ISSUER = "https://vsr.local-auth.internal"       # accepted issuer
VSR_SECRET = "vsr-local-signing-key-2026"              # HMAC key
```

Both can be overridden via environment variables (`VSR_ISSUER`, `VSR_SECRET`) or a `key.env` file.

---

## File Reference

| File | What it does |
|---|---|
| `vsr/vsr_auth.py` | Core logic: `decode_jwt`, `verify_jwt`, `vsr_authenticate`, `VSRPolicyMiddleware`, `HybridAuthBackend` |
| `vsr/vsr_auth-backup.py` | Snapshot of an earlier stacked-middleware approach (returns 403 for all failures) |
| `vsr/fastapi_demo.py` | Standalone FastAPI app — tests VSR in isolation without _uois |
| `server/main-vsr.py` | Modified — all 5 sub-apps use `HybridAuthBackend` + `VSRPolicyMiddleware` |
| `scripts/test-*.sh` | Ready-to-run test scripts for each scenario |
| `VSR_Auth_Integration_Report.md` | Formal report with problem/reason/solution |

---

## Standalone Demo (no _uois)

```bash
cd _uois/vsr
pip install -r requirements.txt    # starlette, fastapi, uvicorn
python fastapi_demo.py
```

```bash
curl -H "Authorization: Bearer $VSR_TOKEN" http://localhost:8000/vsr-protected
```
