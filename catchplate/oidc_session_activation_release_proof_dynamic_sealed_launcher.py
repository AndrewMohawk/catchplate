"""Fixed sealed-original cold launcher; no alternate path or handler."""
import os
import stat
import sys


def main():
    try:
        if (sys.prefix != '/runtime/python' or sys.executable != '/runtime/python/bin/python3'
                or not sys.flags.isolated or not sys.flags.ignore_environment
                or sys.argv[1:] != ['--root-delivery']):
            raise RuntimeError('sealed activation delivery requires its fixed isolated runtime')
        for path in ('/', '/runtime', '/runtime/authority-bootstrap', '/vendor', '/app'):
            value = os.stat(path, follow_symlinks=False)
            if not stat.S_ISDIR(value.st_mode) or value.st_uid != 0 or value.st_mode & 0o022:
                raise RuntimeError('sealed activation delivery runtime directory differs')
        sys.dont_write_bytecode = True
        sys.path[:0] = ['/vendor', '/app']
        from catchplate.oidc_session_activation_release_proof_dynamic_entrypoint import main as run
        return run(_sealed_sources=True)
    except BaseException:
        try:
            os.write(2, b'activation follow-on sealed delivery failed; retain original outcome\n')
        except OSError:
            pass
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
