"""Public presentation assets for the separate operator-development profile.

Rendering never reads configuration, credentials, or runtime state. The admitted
profile owns routing and the authenticated APIs supply all displayed metadata.
"""
from functools import lru_cache
from pathlib import Path
import re

SCRIPT_FILES = ("workspace_core.js", "credential_guide_data.js", "workspace_credential_guides.js", "workspace_common_apps.js", "workspace_github.js", "workspace_npm.js", "workspace_npm_publish.js", "workspace_x.js", "workspace_x_accounts.js", "workspace_x_post.js", "workspace_alchemy.js", "workspace_aws.js", "workspace_ecr.js", "workspace_ecr_publications.js", "workspace_google.js", "workspace_google_reauthorization.js", "workspace_resources.js", "workspace_workload_renewal.js", "workspace_applications.js",
                "workspace_gmail_sdk.js", "workspace_proxy_audit.js", "workspace_connect.js", "workspace_notifications.js", "workspace_pending_actions.js", "workspace_upstreams.js", "workspace_google_configuration.js", "workspace_x_configuration.js", "app.js")


@lru_cache(maxsize=1)
def render() -> str:
    assets = Path(__file__).with_name("operator_demo_web")
    document = (assets / "index.html").read_text(encoding="utf-8")
    styles = (assets / "style.css").read_text(encoding="utf-8")
    scripts = "\n".join((assets / filename).read_text(encoding="utf-8") for filename in SCRIPT_FILES)
    # A fixed asset list, never request/configuration values. Refuse raw-text
    # terminators rather than letting an asset escape its HTML script/style tag.
    if re.search(r"</script", scripts, re.I) or re.search(r"</style", styles, re.I):
        raise RuntimeError("operator portal asset contains an HTML raw-text terminator")
    scripts = "(() => {\n'use strict';\n" + scripts + "\n})();\n"
    for marker, content in (("__OPERATOR_DEMO_STYLE__", styles),
                            ("__OPERATOR_DEMO_SCRIPT__", scripts)):
        if document.count(marker) != 1:
            raise RuntimeError("operator demo portal asset marker is missing or duplicated")
        document = document.replace(marker, content)
    return document
