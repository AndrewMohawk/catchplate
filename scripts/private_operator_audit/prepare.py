"""Render/review a fresh private fixture. Never starts or recreates a container.

Default: read-only preflight and configuration output. --write writes only the
empty, caller-created job root after all checks pass. Runtime initialization
and launching are separate, explicitly reviewed Compose operations.
"""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess

from config import build, PREFIX

SCRATCH = Path('/srv/catchplate-fast/tmp')


def command(args):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=30).stdout


def sha256(path):
    result = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            result.update(chunk)
    return result.hexdigest()


def fresh_root(path):
    if (path.parent != SCRATCH or path.resolve() != path or path.is_symlink()
            or not re.fullmatch(r'catchplate-audit-private\.[A-Za-z0-9]{6,32}', path.name)):
        raise ValueError('job root must be an exact new private-audit NVMe scratch child')
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700 or any(path.iterdir()):
        raise ValueError('job root must be owned, mode 0700 and empty')


def overlaps(subnet):
    candidate = ipaddress.ip_network(subnet, strict=True)
    ids = command(['docker', 'network', 'ls', '-q']).split()
    networks = json.loads(command(['docker', 'network', 'inspect', *ids])) if ids else []
    existing = [item['Subnet'] for network in networks for item in (network.get('IPAM', {}).get('Config') or []) if item.get('Subnet')]
    existing += [r['dst'] for r in json.loads(command(['ip', '-json', 'route', 'show'])) if r.get('dst') not in (None, 'default')]
    conflicts = sorted({value for value in existing if ipaddress.ip_network(value).version == candidate.version and candidate.overlaps(ipaddress.ip_network(value))})
    if conflicts:
        raise ValueError('candidate subnet overlaps existing Docker or host networks')
    return {'dockerNetworksChecked': len(networks), 'candidate': subnet, 'conflicts': []}


def prepare(args):
    root, source, binary = args.job_root, args.source, args.binary
    fresh_root(root)
    for path in (source, binary):
        if not path.is_absolute() or path.resolve() != path:
            raise ValueError('source and binary require exact non-symlink absolute paths')
    if not (source / 'catchplate/operator_demo_runner.py').is_file() or not (source / 'scripts/private_operator_audit/check.py').is_file():
        raise ValueError('integrated source with fixture harness required')
    info = binary.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not info.st_mode & stat.S_IXUSR:
        raise ValueError('exact regular executable required')
    if sha256(binary) != args.sha256:
        raise ValueError('executable differs from approved SHA-256')
    filesystem = json.loads(command(['findmnt', '--json', '-T', str(root), '-o', 'TARGET,SOURCE,FSTYPE']))
    available = os.statvfs(root)
    if available.f_bavail * available.f_frsize < 2 * 1024**3:
        raise ValueError('at least 2 GiB free required before fixture writes')
    network = overlaps(args.subnet)
    project = PREFIX + hashlib.sha256(root.name.encode()).hexdigest()[:12]
    if command(['docker', 'ps', '-a', '-q', '--filter', 'label=com.docker.compose.project=' + project]).strip():
        raise ValueError('new fixture project already has containers')
    config = build(source, binary, root / 'runtime', args.sha256, project, args.subnet)
    manifest = {'schema': 'catchplate.privateOperatorAuditPreparation/v1', 'project': project,
        'jobRoot': str(root), 'source': str(source), 'sourceHead': command(['git', '-C', str(source), 'rev-parse', 'HEAD']).strip(),
        'sourceStatus': command(['git', '-C', str(source), 'status', '--short']).splitlines(),
        'binary': str(binary), 'binarySha256': args.sha256, 'networkPreflight': network,
        'filesystem': filesystem, 'productionReady': False, 'launched': False,
        'harnessSha256': {p.name: sha256(p) for p in sorted((source / 'scripts/private_operator_audit').glob('*.py'))},
        'composeSha256': hashlib.sha256((json.dumps(config, indent=2, sort_keys=True) + '\n').encode()).hexdigest()}
    if args.write:
        # Recheck the exact new directory immediately before creating any files.
        fresh_root(root)
        (root / 'runtime').mkdir(mode=0o700)
        for name, value in (('compose.json', config), ('preparation.json', manifest)):
            with (root / name).open('x', encoding='utf-8') as target:
                json.dump(value, target, indent=2, sort_keys=True)
                target.write('\n')
            os.chmod(root / name, 0o600)
    return {'preflight': manifest, 'compose': config}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--job-root', type=Path, required=True)
    parser.add_argument('--subnet', default='172.16.249.48/28')
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    try:
        print(json.dumps(prepare(args), indent=2, sort_keys=True))
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        # Inputs are paths/digests only; do not dump subprocess output or env.
        raise SystemExit('Private fixture preparation refused: ' + type(error).__name__)
