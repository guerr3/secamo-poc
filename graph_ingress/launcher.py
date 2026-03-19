from __future__ import annotations

import os

import uvicorn


def main() -> None:
    """Launch the Graph ingress FastAPI service."""
    host = os.environ.get("GRAPH_INGRESS_HOST", "0.0.0.0")
    port = int(os.environ.get("GRAPH_INGRESS_PORT", "8081"))
    uvicorn.run("graph_ingress.app:app", host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
