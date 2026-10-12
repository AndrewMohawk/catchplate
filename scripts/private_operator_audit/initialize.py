"""Fresh private-fixture ownership setup; fixed mount, no live-root option."""
import json
import os
from pathlib import Path
import secrets
import stat

ROOT = Path('/fixture-runtime')
ROLES = ('admin', 'credential-lease', 'audit', 'grant-consume', 'rate-limit-consume',
         'release-authorization', 'management', 'fixture-control')


def initialize(root=ROOT):
    if os.geteuid() != 0:
        raise RuntimeError('initializer requires its bounded root container')
    info = root.lstat()
    if root.is_symlink() or not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700:
        raise RuntimeError('private fixture root refused')
    if any(root.iterdir()):
        raise RuntimeError('initializer refuses existing or partial runtime')
    os.umask(0o077)
    for name in ('app-data', 'gate-data', 'upstream-data', 'upstream-data/demo-upstream', 'service-secrets'):
        directory = root / name
        directory.mkdir(mode=0o700)
        os.chown(directory, 10001, 10001)
    for role in ROLES:
        fd = os.open(root / 'service-secrets' / (role + '.token'), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
        with os.fdopen(fd, 'w', encoding='ascii') as out:
            out.write(secrets.token_urlsafe(48))
            out.flush()
            os.fsync(out.fileno())
            os.fchown(out.fileno(), 10001, 10001)
    fd = os.open(root / '.private-fixture.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(fd, 'w', encoding='ascii') as out:
        json.dump({'schema': 'serverware.privateOperatorAuditFixture/v1', 'syntheticOnly': True}, out)
        out.flush()
        os.fsync(out.fileno())
        os.fchown(out.fileno(), 10001, 10001)
    print('Fresh isolated runtime initialized; no credential values emitted.')


if __name__ == '__main__':
    initialize()
