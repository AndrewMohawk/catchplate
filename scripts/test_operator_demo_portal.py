#!/usr/bin/env python3
"""Compatibility entrypoint for the current separated operator catalog UI.

The former combined-connection UI and its fixtures are retained in Git at
5af81cdd. Current commands exercise the catalog instead of obsolete selectors
and the deliberately retired /api/operator-demo/status response.
"""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_operator_catalog_assets import OperatorCatalogAssets


if __name__ == "__main__":
    unittest.main(verbosity=2)
