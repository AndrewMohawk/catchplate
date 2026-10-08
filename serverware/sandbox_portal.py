"""Task-oriented UI for the explicit synthetic sandbox, not production setup.

Only public presentation assets are embedded here. All state comes from the
existing authenticated APIs; no credential or management token enters the HTML.
"""
from functools import lru_cache
from pathlib import Path


@lru_cache(maxsize=1)
def render() -> str:
    assets = Path(__file__).with_name("sandbox_web")
    document = (assets / "index.html").read_text(encoding="utf-8")
    for marker, filename in (("__SANDBOX_STYLE__", "style.css"),
                             ("__SANDBOX_SCRIPT__", "app.js")):
        if document.count(marker) != 1:
            raise RuntimeError("sandbox portal asset marker is missing or duplicated")
        document = document.replace(marker, (assets / filename).read_text(encoding="utf-8"))
    return document
