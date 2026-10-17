"""Build-stage writer for the immutable app/normal-binary pairing manifest."""
import hashlib
import json
from pathlib import Path
import re


def main():
    root = Path("/opt/catchplate")
    metadata = json.loads((root / "metadata.json").read_text())
    required = {"sourceRevision", "sourceTreeDigest", "compilerInputsDigest", "expectedBinaryDigest"}
    if set(metadata) != required or not re.fullmatch("[0-9a-f]{40}", metadata["sourceRevision"]):
        raise ValueError("invalid standalone build metadata")
    for key in ("sourceTreeDigest", "compilerInputsDigest"):
        if not re.fullmatch("sha256:[0-9a-f]{64}", metadata[key]):
            raise ValueError("invalid standalone build digest")
    with Path("/usr/local/bin/catchplate-decision-gate").open("rb") as stream:
        binary = "sha256:" + hashlib.file_digest(stream, "sha256").hexdigest()
    expected = metadata.pop("expectedBinaryDigest")
    if expected is not None and expected != binary:
        raise ValueError("cached normal binary digest mismatch")
    value = {"schema": "catchplate.standaloneArtifact/v1", **metadata, "dataPlaneBinaryDigest": binary}
    with (root / "artifact.json").open("x") as stream:
        json.dump(value, stream, sort_keys=True)
        stream.write("\n")
    (root / "artifact.json").chmod(0o444)


if __name__ == "__main__":
    main()
