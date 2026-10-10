#!/usr/bin/env python3
"""Run one isolated Alchemy SDK examples fixture using existing pinned artifacts.

No build, dependency install, image pull, deployment, or provider contact occurs.
The X fixture runner owns containment, bounded phases, and exact-ID cleanup;
this entrypoint selects only fixed Alchemy recipe and checker constants.
"""
from __future__ import annotations

from pathlib import Path
import sys

# Fixed sibling source, never a module name or search path supplied by the CLI.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from scripts.run_operator_x_examples_fixture import Run, main


class AlchemyRun(Run):
    SOURCE_FILE = Path(__file__).resolve()
    SOURCE_SCRIPT = "scripts/run_operator_alchemy_examples_fixture.py"
    RECIPE_MODULE = "scripts.prepare_operator_alchemy_fixture"
    CHECKER_MODULE = "scripts.check_operator_alchemy_examples"
    CHECKER_SCRIPT = "/app/scripts/check_operator_alchemy_examples.py"
    PROVIDER_SERVICE = "alchemy"
    PROVIDER_PKI_SERVICE = "alchemy-pki"
    NODE_EXAMPLE_DIRECTORY = "examples/alchemy-chain-status-node"
    GO_MOUNT_TARGET = "/example-go/alchemy-chain-status"
    CLAIM_SCHEMA = "serverware.privateAlchemyExamplesRunClaim/v1"
    TERMINAL_SCHEMA = "serverware.privateAlchemyExamplesRun/v1"
    REAL_PROVIDER_VERIFIED = "realAlchemyVerified"


if __name__ == "__main__":
    raise SystemExit(main(AlchemyRun, description=__doc__))
