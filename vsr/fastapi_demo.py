import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from fastapi import FastAPI, Request
from vsr_auth import (
    VSRAuthBackend,
    VSRAuthenticationMiddlewareJSON,
    VSR_ISSUER,
)

app = FastAPI(title="VSR Authentication Demo")

app.add_middleware(
    VSRAuthenticationMiddlewareJSON,
    backend=VSRAuthBackend(),
)


@app.get("/vsr-protected")
async def vsr_protected(request: Request):
    user = request.user
    return {
        "status": "authenticated",
        "message": "VSR token accepted",
        "issuer": VSR_ISSUER,
    }


@app.get("/public")
async def public_endpoint():
    return {"status": "ok", "message": "This endpoint is public"}


if __name__ == "__main__":
    import uvicorn
    print(f"Starting VSR Auth Demo on http://127.0.0.1:8000")
    print(f"Allowed issuer: {VSR_ISSUER}")
    uvicorn.run(app, host="127.0.0.1", port=8000)
