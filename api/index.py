import os
import sys

BACKEND_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "sentinel", "backend")
)

if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from app import app as backend_app  # noqa: E402
from db import init_db  # noqa: E402

init_db()


class ApiPrefixMiddleware:
    def __init__(self, asgi_app):
        self.asgi_app = asgi_app

    async def __call__(self, scope, receive, send):
        if scope.get("type") == "http" and scope.get("path", "").startswith("/api/"):
            scope = dict(scope)
            scope["path"] = scope["path"][4:] or "/"
        await self.asgi_app(scope, receive, send)


app = ApiPrefixMiddleware(backend_app)
