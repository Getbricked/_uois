import json
import base64
import hmac
import hashlib

VSR_ISSUER = "https://vsr.local-auth.internal"
VSR_SECRET = "vsr-local-signing-key-2024"


def _base64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def decode_jwt(token: str) -> dict:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT: expected 3 parts")
    payload_b64 = parts[1]
    payload_json = _base64url_decode(payload_b64)
    return json.loads(payload_json)


def verify_jwt(token: str, secret: str = VSR_SECRET) -> bool:
    parts = token.split(".")
    if len(parts) != 3:
        return False
    message = f"{parts[0]}.{parts[1]}".encode()
    expected_sig = hmac.new(secret.encode(), message, hashlib.sha256).digest()
    actual_sig = _base64url_decode(parts[2])
    return hmac.compare_digest(expected_sig, actual_sig)


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
        AuthCredentials, AuthenticationBackend, AuthenticationError
    )
    from starlette.middleware.authentication import AuthenticationMiddleware
    from starlette.requests import HTTPConnection
    from starlette.responses import PlainTextResponse, JSONResponse

    class VSRAuthBackend(AuthenticationBackend):
        def __init__(self, secret: str = VSR_SECRET):
            self.secret = secret

        async def authenticate(self, conn):
            headers = conn.headers
            cookies = conn.cookies

            jwtsource = cookies.get("authorization", None)
            if jwtsource is None:
                jwtsource = headers.get("Authorization", None)
                if jwtsource is not None:
                    parts = jwtsource.split("Bearer ")
                    if len(parts) == 2:
                        jwtsource = parts[1]

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

    class VSRIssuerCheckBackend(AuthenticationBackend):
        async def authenticate(self, conn):
            headers = conn.headers
            cookies = conn.cookies

            jwtsource = cookies.get("authorization", None)
            if jwtsource is None:
                jwtsource = headers.get("Authorization", None)
                if jwtsource is not None:
                    parts = jwtsource.split("Bearer ")
                    if len(parts) == 2:
                        jwtsource = parts[1]

            if not jwtsource:
                raise AuthenticationError("Missing authorization token")

            try:
                payload = decode_jwt(jwtsource)
            except Exception as e:
                raise AuthenticationError(f"Invalid JWT: {e}")

            issuer = payload.get("iss")
            if issuer != VSR_ISSUER:
                raise VSRAuthenticationError(
                    f"Token rejected by VSR policy: "
                    f"issuer '{issuer}' is not trusted. "
                    f"Only '{VSR_ISSUER}' is allowed."
                )

            return AuthCredentials(["vsr-check-passed"]), {"issuer": issuer}

except ImportError:
    class VSRAuthBackend:
        def __init__(self, *args, **kwargs):
            raise ImportError("starlette is required for VSRAuthBackend")

    class VSRAuthenticationMiddleware:
        def __init__(self, *args, **kwargs):
            raise ImportError("starlette is required for VSRAuthenticationMiddleware")

    class VSRAuthenticationMiddlewareJSON:
        def __init__(self, *args, **kwargs):
            raise ImportError("starlette is required for VSRAuthenticationMiddlewareJSON")

    class VSRIssuerCheckBackend:
        def __init__(self, *args, **kwargs):
            raise ImportError("starlette is required for VSRIssuerCheckBackend")
