#!/usr/local/bin/python3.11 -I
"""Fixed one-shot external native shadow verifier: FD3 config, FD4 seed, FD5 evidence.

The independently provisioned launcher must use the pinned interpreter/module
closure with isolated Python imports and the exact final verifier identity.
No argv/env authority selectors, key generation, network or generic signing API.
"""
import sys

def main():
    if len(sys.argv) != 1 or sys.flags.isolated != 1 or sys.flags.ignore_environment != 1:
        raise ValueError("native shadow verifier requires isolated fixed invocation")
    from serverware.native_shadow_nitro_verifier import run
    result = run()
    sys.stdout.buffer.write(result)
    sys.stdout.buffer.flush()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        sys.stderr.write("native shadow custody verification failed\n")
        raise SystemExit(1) from None
