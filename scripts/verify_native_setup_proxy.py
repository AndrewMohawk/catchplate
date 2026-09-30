#!/usr/local/bin/python3.11 -I
"""Separate independently provisioned proxy verifier; protected3/sealed4+5."""
import sys

def main():
    if len(sys.argv)!=1 or sys.flags.isolated!=1 or sys.flags.ignore_environment!=1 or sys.flags.dont_write_bytecode!=1:
        raise ValueError("fixed isolated proxy verifier invocation required")
    from serverware.native_setup_independent_verifier import proxy
    proxy()

if __name__=="__main__":
    try: main()
    except Exception: raise SystemExit(1) from None
