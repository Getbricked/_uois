# VSR Authentication Middleware

Localized authentication enforcement for the VSR (Virtual Secure Realm)
environment. Any token not issued by the VSR authority is rejected with
a 403 Forbidden response.

## VSR Policy Rule

The custom rule in `vsr_auth.py:43` checks the JWT `iss` (issuer) claim.
If the issuer is anything other than `https://vsr.local-auth.internal`,
the request is denied. This prevents citizen credentials from being
issued or validated by foreign servers (Google, Microsoft, etc.).

## Files

| File | Purpose |
|---|---|
| `vsr_auth.py` | Core auth library + optional Starlette middleware |
| `fastapi_demo.py` | Demo FastAPI server for manual / Postman testing |
| `requirements.txt` | Dependencies for the FastAPI demo |
| `README.md` | This file |

## Core API (zero dependencies)

The core functions in `vsr_auth.py` use only the Python standard library.
No packages need to be installed to use them.

```python
from vsr.vsr_auth import decode_jwt, verify_jwt, vsr_authenticate
```

### `decode_jwt(token: str) -> dict`

Decodes a JWT and returns the payload without verifying the signature.

```python
payload = decode_jwt("eyJhbGciOi...")
print(payload["iss"])   # 'https://vsr.local-auth.internal'
```

### `verify_jwt(token: str, secret: str) -> bool`

Verifies the HMAC-SHA256 signature of a JWT.

```python
assert verify_jwt(token) == True
```

### `vsr_authenticate(token: str, secret: str) -> dict`

Full VSR authentication pipeline:
1. Verify the HMAC-SHA256 signature
2. Decode the payload
3. Check that `iss` equals `https://vsr.local-auth.internal`
4. Extract `user_id` or `sub` from the payload

Returns a dict with `id` and `jwt` keys on success.

Raises `VSRAuthError` if:
- The signature is invalid
- The issuer is not the VSR issuer
- No user identifier is found in the token

```python
from vsr.vsr_auth import vsr_authenticate, VSRAuthError

try:
    user = vsr_authenticate(token)
    print(f"Authenticated user: {user['id']}")
except VSRAuthError as e:
    print(f"Rejected: {e}")
```

## Starlette / FastAPI Middleware

When `starlette` is installed, the module also provides drop-in
middleware classes compatible with FastAPI and Starlette applications.

### VSRAuthBackend

Starlette `AuthenticationBackend` that extracts the JWT from
`Authorization: Bearer <token>` or the `authorization` cookie, then
runs it through `vsr_authenticate()`.

### VSRAuthenticationMiddleware

Starlette `AuthenticationMiddleware` that returns plain-text 403 on
VSR policy violations.

### VSRAuthenticationMiddlewareJSON

Same as above but returns JSON responses:

```json
{"error": "VSR Forbidden", "detail": "..."}
```

### Usage with FastAPI

```python
from fastapi import FastAPI, Request
from vsr.vsr_auth import VSRAuthBackend, VSRAuthenticationMiddlewareJSON

app = FastAPI()

app.add_middleware(
    VSRAuthenticationMiddlewareJSON,
    backend=VSRAuthBackend(),
)

@app.get("/protected")
async def protected(request: Request):
    return {"user_id": request.user["id"]}
```

## Integration with _uois

Replace the existing auth backend in `server/main.py`:

```python
# old:
from .BasicAuthBackend4Phase import BasicAuthBackend4Phase as BasicAuthBackend

# new:
from vsr.vsr_auth import VSRAuthBackend as BasicAuthBackend
```

No other changes are needed. `VSRAuthBackend` implements the same
`AuthenticationBackend` interface.

## Running the Demo

### Prerequisites

```bash
pip install -r vsr/requirements.txt
```

### Start the server

```bash
python vsr/fastapi_demo.py
```

The server starts on `http://127.0.0.1:8000`. It provides two endpoints:

- `GET /vsr-protected` -- protected by VSR authentication
- `GET /public` -- open endpoint

### Generate test tokens

The module does not require any third-party libraries to generate
tokens. Use the functions in `demo_test.py` (now removed; see commands
below) or create tokens inline with the Python standard library.

#### VSR token (accepted -- 200 OK)

```bash
TOKEN=$(python -c "
import json, base64, hmac, hashlib, time
from vsr.vsr_auth import VSR_ISSUER, VSR_SECRET

header = '{\"alg\":\"HS256\",\"typ\":\"JWT\"}'
payload = json.dumps({
    'iss': VSR_ISSUER,
    'sub': 'vsr-user-001',
    'user_id': 'vsr-user-001',
    'iat': int(time.time()),
    'exp': int(time.time()) + 3600,
    'jti': 'demo-token'
}, separators=(',', ':'))

def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

msg = b64(header.encode()) + '.' + b64(payload.encode())
sig = b64(hmac.new(VSR_SECRET.encode(), msg.encode(), hashlib.sha256).digest())
print(msg + '.' + sig)
")
```

```bash
curl -H "Authorization: Bearer $TOKEN" \
     http://localhost:8000/vsr-protected
```

Expected response (200):

```json
{"status": "authenticated", "message": "VSR token accepted", "issuer": "https://vsr.local-auth.internal"}
```

#### Foreign token (rejected -- 403 Forbidden)

Generate a token with a non-VSR issuer (e.g., `https://accounts.google.com`)
by changing the `iss` value in the payload above:

```python
payload = json.dumps({
    'iss': 'https://accounts.google.com',
    ...
}, separators=(',', ':'))
```

```bash
curl -H "Authorization: Bearer $TOKEN" \
     http://localhost:8000/vsr-protected
```

Expected response (403):

```json
{"error": "VSR Forbidden", "detail": "Token rejected by VSR policy: issuer 'https://accounts.google.com' is not trusted. Only 'https://vsr.local-auth.internal' is allowed."}
```

## Direct Python test (no server needed)

```python
from vsr.vsr_auth import vsr_authenticate, VSRAuthError

# VSR token -- should pass
vsr_token = "eyJ...<paste VSR-signed token>"
try:
    user = vsr_authenticate(vsr_token)
    print("PASS: token accepted, user:", user["id"])
except VSRAuthError as e:
    print("FAIL:", e)

# Foreign token -- should fail
google_token = "eyJ...<paste Google-signed token>"
try:
    user = vsr_authenticate(google_token)
    print("FAIL: token should have been rejected")
except VSRAuthError as e:
    print("PASS: token rejected:", e)
```

## Customization

Change the allowed issuer and signing secret at the module level:

```python
from vsr.vsr_auth import VSR_ISSUER, VSR_SECRET

# or override per call
vsr_authenticate(token, secret="my-custom-secret")
```
