#!/usr/bin/env python3
"""Installed offline operator entrypoint; pinned public manifest on FD3."""
import sys

if not sys.flags.isolated:
    raise SystemExit("Run the installed operator tool with Python isolated mode (-I).")

from serverware.native_shadow_retrieval_store import main

if __name__ == "__main__":
    raise SystemExit(main())
