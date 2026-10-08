"""Public presentation assets for the separate operator-development profile.

Rendering never reads configuration, credentials, or runtime state. The admitted
profile owns routing and the authenticated APIs supply all displayed metadata.
"""
from functools import lru_cache
from pathlib import Path


@lru_cache(maxsize=1)
def render() -> str:
    assets = Path(__file__).with_name("operator_demo_web")
    document = (assets / "index.html").read_text(encoding="utf-8")
    for marker, filename in (("__OPERATOR_DEMO_STYLE__", "style.css"),
                             ("__OPERATOR_DEMO_SCRIPT__", "app.js")):
        if document.count(marker) != 1:
            raise RuntimeError("operator demo portal asset marker is missing or duplicated")
        document = document.replace(marker, (assets / filename).read_text(encoding="utf-8"))
    return document
