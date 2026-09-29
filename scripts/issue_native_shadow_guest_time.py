#!/usr/local/bin/python3.11 -I
"""Fixed no-argument external time issuer: config3, sealed seed4, TCP5."""
import sys


def main():
    if len(sys.argv) != 1 or sys.flags.isolated != 1 or sys.flags.ignore_environment != 1:
        raise ValueError("native guest time issuer requires isolated fixed invocation")
    from serverware.native_shadow_time_issuer import run
    run()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        sys.stderr.write("native guest time issuance failed\n")
        raise SystemExit(1) from None
