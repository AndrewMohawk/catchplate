#!/usr/bin/env python3
"""Prepare an unsigned local image artifact; never approve or contact AWS.

Run from the checkout with python3 -B -m scripts.prepare_ecr_image_artifact.
The source contains OCI-style blobs/sha256/<digest> files. Select one exact
manifest digest; no index/tag lookup, decompression, Docker daemon or ambient
AWS credential discovery is performed.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from serverware.ecr_artifact_staging import ArtifactStagingError, stage_artifact


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path,
        help="absolute existing directory containing blobs/sha256")
    parser.add_argument("--manifest-digest", required=True,
        help="exact sha256:<lowercase hex> of the selected original manifest")
    parser.add_argument("--destination", required=True, type=Path,
        help="new absolute directory under an existing private, owned parent")
    args = parser.parse_args(argv)
    try:
        marker = stage_artifact(source_directory=args.source,
            destination_directory=args.destination, manifest_digest=args.manifest_digest)
    except ArtifactStagingError:
        print("ECR artifact preparation failed or its completion is uncertain. "
            "Preserve any created destination for inspection; do not overwrite or retry it.",
            file=sys.stderr)
        return 1
    print(json.dumps(marker, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
