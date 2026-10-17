#!/usr/bin/env python3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from catchplate_agent_trust.attestation import *  # noqa: F403
from catchplate_agent_trust.attestation import console_main


if __name__ == "__main__":
    raise SystemExit(console_main())
