from __future__ import annotations

import uvicorn

from serverware.ca_material import ensure_mitm_ca_material
from serverware.config import WEB_HOST, WEB_PORT, ensure_data_dirs
from serverware.db import init_db


def main() -> None:
    ensure_data_dirs()
    ensure_mitm_ca_material()
    init_db()
    uvicorn.run("serverware.app:app", host=WEB_HOST, port=WEB_PORT, log_level="info")


if __name__ == "__main__":
    main()
