#!/usr/local/bin/python3.11 -I
"""Fixed independent origin verifier: configuration3, sealed seed4, TCP5."""
import sys


def main():
    if len(sys.argv) != 1 or sys.flags.isolated != 1 or sys.flags.ignore_environment != 1:
        raise ValueError("generation origin issuer requires isolated fixed invocation")
    from serverware.native_generation_origin_issuer import run
    run()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        sys.stderr.write("native generation origin issuance failed\n")
        raise SystemExit(1) from None
