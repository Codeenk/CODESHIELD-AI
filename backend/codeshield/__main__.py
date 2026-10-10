"""Run the CodeShield AI API: ``python -m codeshield``."""
from __future__ import annotations

import os


def main() -> None:
    import uvicorn

    host = os.environ.get("CODESHIELD_HOST", "127.0.0.1")
    port = int(os.environ.get("CODESHIELD_PORT", "8000"))
    reload = os.environ.get("CODESHIELD_RELOAD", "").lower() in {"1", "true", "yes"}
    uvicorn.run("codeshield.api.app:app", host=host, port=port, reload=reload)


if __name__ == "__main__":
    main()
