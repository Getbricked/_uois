import json
import base64
import hmac
import hashlib
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(dotenv_path=Path(__file__).with_name("key.env"))

VSR_ISSUER = os.getenv("VSR_ISSUER", "https://vsr.local-auth.internal")
VSR_SECRET = os.getenv("VSR_SECRET", "vsr-local-signing-key-2026")


# Extract JWT from cookie or Authorization header
def _extract_jwt_source(headers, cookies) -> str | None:
    jwtsource = cookies.get("authorization", None)
    if jwtsource is None:
        jwtsource = headers.get("Authorization", None)
        if jwtsource is not None:
            parts = jwtsource.split("Bearer ")
            if len(parts) == 2:
                jwtsource = parts[1]
    return jwtsource


# Decode method
def _base64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


# Decode JWT payload
def decode_jwt(token: str) -> dict:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT: expected 3 parts")
    payload_b64 = parts[1]
    payload_json = _base64url_decode(payload_b64)
    return json.loads(payload_json)


# Verify JWT signature
def verify_jwt(token: str, secret: str = VSR_SECRET) -> bool:
    parts = token.split(".")
    if len(parts) != 3:
        return False
    message = f"{parts[0]}.{parts[1]}".encode()
    expected_sig = hmac.new(secret.encode(), message, hashlib.sha256).digest()
    actual_sig = _base64url_decode(parts[2])
    return hmac.compare_digest(expected_sig, actual_sig)


# Main authentication function
def vsr_authenticate(token: str, secret: str = VSR_SECRET) -> dict:
    if not verify_jwt(token, secret):
        raise VSRAuthError("Token rejected: invalid signature")

    payload = decode_jwt(token)

    issuer = payload.get("iss")
    if issuer != VSR_ISSUER:
        raise VSRAuthError(
            f"Token rejected by VSR policy: "
            f"issuer '{issuer}' is not trusted. "
            f"Only '{VSR_ISSUER}' is allowed."
        )

    user_id = payload.get("user_id") or payload.get("sub")
    if not user_id:
        raise VSRAuthError("Token does not contain a user identifier")

    return {"id": user_id, "jwt": payload}


class VSRAuthError(Exception):
    pass


try:
    from starlette.authentication import (
        AuthCredentials,
        AuthenticationBackend,
        AuthenticationError,
    )
    from starlette.middleware.authentication import AuthenticationMiddleware
    from starlette.requests import HTTPConnection
    from starlette.responses import PlainTextResponse, JSONResponse

    class VSRAuthBackend(AuthenticationBackend):
        def __init__(self, secret: str = VSR_SECRET):
            self.secret = secret

        async def authenticate(self, conn):
            jwtsource = _extract_jwt_source(conn.headers, conn.cookies)

            if jwtsource is None:
                raise AuthenticationError("Missing authorization token")

            try:
                user = vsr_authenticate(jwtsource, self.secret)
            except VSRAuthError as e:
                raise VSRAuthenticationError(str(e))

            return AuthCredentials(["authenticated", "vsr"]), user

    class VSRAuthenticationMiddleware(AuthenticationMiddleware):
        @staticmethod
        def default_on_error(conn: HTTPConnection, exc: Exception) -> PlainTextResponse:
            return PlainTextResponse(str(exc), status_code=403)

    class VSRAuthenticationMiddlewareJSON(AuthenticationMiddleware):
        @staticmethod
        def default_on_error(conn: HTTPConnection, exc: Exception) -> JSONResponse:
            return JSONResponse(
                {"error": "VSR Forbidden", "detail": str(exc)},
                status_code=403,
            )

    class VSRAuthenticationError(AuthenticationError):
        pass

    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.responses import JSONResponse

    class VSRPolicyMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            jwtsource = _extract_jwt_source(request.headers, request.cookies)

            if jwtsource:
                try:
                    payload = decode_jwt(jwtsource)
                except Exception:
                    payload = {}

                issuer = payload.get("iss")
                if issuer is not None and issuer != VSR_ISSUER:
                    return JSONResponse(
                        {
                            "error": "VSR Forbidden",
                            "detail": f"issuer '{issuer}' is not trusted. "
                            f"Only '{VSR_ISSUER}' is allowed.",
                        },
                        status_code=403,
                    )

            return await call_next(request)

    class HybridAuthBackend(AuthenticationBackend):
        def __init__(self, original_backend=None, vsr_secret: str = VSR_SECRET):
            self.original_backend = original_backend
            self.vsr_secret = vsr_secret

        async def _fallback(self, conn):
            if self.original_backend:
                return await self.original_backend.authenticate(conn)
            return AuthCredentials(["anonymous"]), {}

        async def authenticate(self, conn):
            jwtsource = _extract_jwt_source(conn.headers, conn.cookies)

            if not jwtsource:
                return await self._fallback(conn)

            try:
                payload = decode_jwt(jwtsource)
            except Exception:
                return await self._fallback(conn)

            issuer = payload.get("iss")
            if issuer == VSR_ISSUER:
                try:
                    user = vsr_authenticate(jwtsource, self.vsr_secret)
                    return AuthCredentials(["authenticated", "vsr"]), user
                except VSRAuthError as e:
                    raise AuthenticationError(str(e))

            return await self._fallback(conn)

except ImportError:

    class VSRAuthBackend:
        def __init__(self, *args, **kwargs):
            raise ImportError("starlette is required for VSRAuthBackend")

    class VSRAuthenticationMiddleware:
        def __init__(self, *args, **kwargs):
            raise ImportError("starlette is required for VSRAuthenticationMiddleware")

    class VSRAuthenticationMiddlewareJSON:
        def __init__(self, *args, **kwargs):
            raise ImportError(
                "starlette is required for VSRAuthenticationMiddlewareJSON"
            )

    class VSRIssuerCheckBackend:
        def __init__(self, *args, **kwargs):
            raise ImportError("starlette is required for VSRIssuerCheckBackend")
