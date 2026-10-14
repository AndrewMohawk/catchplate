#!/usr/bin/env python3
"""One hosted engineering attempt: public provisioning, then offline Rust controls.

No native admission, real credentials, deployment, normal proxy binary, cache
restoration, or automatic retry. Source remains the read-only exact checkout.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import posixpath
import re
import resource
import secrets
import shlex
import stat
import subprocess
import time
import tomllib

IMAGE = 'rust:1.88-slim-bookworm@sha256:38bc5a86d998772d4aec2348656ed21438d20fcdce2795b56ca434cf21430d89'
IMAGE_ID = 'sha256:c8211ab4ab64eb72091912fa408ac59daaeb56d0ae1a2bf243c08753777c4382'
CRATE = 'data-plane/decision-gate-rs/'
ROSTER = 'scripts/native_jit_review_rust_tests.json'
FIXTURE = 'scripts/fixtures/native_release_jit_preparation.json'
FIXTURE_SHA = 'b1bdf10c83bee503dbf82be8a0fc2e72f9121db4110f0e7f61186bd09d578b23'
LOG_LIMIT = 8 * 1024**2
RESERVE = 2 * 1024**3
LABEL = 'com.serverware.hosted-native-review'
CONFIG = '[source.crates-io]\nreplace-with = "vendored-sources"\n[source.vendored-sources]\ndirectory = "/vendor"\n'
APIS = (
    ('old-pass', 'native_browser_transport_api_tests/pass.rs', None, None),
    ('old-private', 'native_browser_transport_api_tests/private_transport.rs', 'E0603', 1),
    ('opening-pass', 'native_jit_review_open_api_tests/pass.rs', None, None),
    ('opening-attempts', 'native_jit_review_open_api_tests/private_attempts.rs', 'E0616', 2),
    ('opening-transport', 'native_jit_review_open_api_tests/private_transport.rs', 'E0616', 2),
)


def require(value, message):
    if not value:
        raise ValueError(message)


def read(path, limit=LOG_LIMIT):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_size <= limit, 'file type/size bound')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            data = stream.read(limit + 1)
        after = os.fstat(fd)
        require(len(data) == before.st_size and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'file changed during read')
        require(path.lstat().st_ino == before.st_ino, 'file identity changed')
        return data
    finally:
        os.close(fd)


def sha(path, limit=512 * 1024**2):
    return hashlib.sha256(read(path, limit)).hexdigest()


def save(path, document):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(document, stream, sort_keys=True, separators=(',', ':'))
        stream.write('\n')


def check_tests(listed, output, expected):
    names = [line[:-6] for line in listed.splitlines() if line.endswith(': test')]
    passed = re.findall(r'^test (.+) \.\.\. ok$', output, re.M)
    summary = re.findall(r'^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;', output, re.M)
    require(len(names) == len(expected) and set(names) == set(expected)
            and len(passed) == len(expected) and set(passed) == set(expected)
            and summary == [(str(len(expected)), '0', '0')], 'test roster/result mismatch')


def check_api(stdout, stderr, code, source, line):
    require(not stdout, 'unexpected API probe stdout')
    rows = [json.loads(value) for value in stderr.splitlines()]
    errors = [row for row in rows if row.get('level') == 'error' and row.get('code') is not None]
    if code is None:
        require(not any(row.get('level') == 'error' for row in rows), 'positive API probe error')
    else:
        require(len(errors) == 1 and errors[0]['code']['code'] == code
                and any(span.get('is_primary') is True and span['file_name'] == '/repository/' + CRATE + 'src/' + source
                        and span['line_start'] == line for span in errors[0]['spans']), 'wrong API diagnostic/span')


def cargo_row(raw, phase):
    rows = [json.loads(line) for line in raw.splitlines()]
    require([row['success'] for row in rows if row.get('reason') == 'build-finished'] == [True], 'Cargo completion missing')
    binary = phase == 'bintest'
    selected = [row for row in rows if row.get('reason') == 'compiler-artifact'
                and row.get('target', {}).get('name') == ('serverware-decision-gate' if binary else 'serverware_decision_gate')
                and row['target']['kind'] == (['bin'] if binary else ['lib'])
                and row['profile']['test'] is (phase != 'library') and row['fresh'] is False]
    require(len(selected) == 1, 'unique fresh artifact missing')
    row = selected[0]
    require(row['target']['src_path'] == '/repository/' + CRATE + 'src/' + ('main.rs' if binary else 'custody_protocol.rs'), 'wrong artifact source')
    return row


def compiler_inputs(raw):
    first = raw.decode().splitlines()[0]
    require(first.startswith('/target/release/') and ': ' in first, 'unexpected dep-info rule')
    names = set()
    for item in shlex.split(first.split(': ', 1)[1]):
        name = posixpath.normpath(item if item.startswith('/') else '/repository/' + CRATE + item)
        require(name.startswith('/repository/'), 'compiler input outside checkout')
        names.add(name.removeprefix('/repository/'))
    require(1 <= len(names) <= 4096, 'compiler input count bound')
    return names


class HostedRun:
    def __init__(self, repository, output, revision):
        self.repo, self.root, self.revision = repository, output, revision
        self.results = output / 'results'
        self.results.mkdir(mode=0o700)
        for name in ('target', 'vendor', 'cargo-home'):
            (output / name).mkdir(mode=0o700)
        (output / 'cargo-config.toml').write_text(CONFIG, encoding='utf-8')
        self.receipt = {'sourceRevision': revision, 'image': IMAGE, 'imageId': IMAGE_ID,
            'scope': 'focused engineering controls; includes pure/synthetic and source-order tests',
            'nativeAdmission': False, 'deployed': False, 'normalProxyBinaryBuilt': False,
            'automaticRetry': False, 'cacheRestored': False, 'containers': [], 'artifacts': {},
            'limits': {'cpus': 2, 'memoryBytes': 6 * 1024**3, 'swapAdditionalBytes': 0, 'pids': 256, 'cargoJobs': 1}}

    def command(self, label, argv, seconds, *, check=True, watch_disk=True):
        save(self.results / (label + '.command.json'), {'argv': argv, 'timeoutSeconds': seconds})
        started = time.monotonic(); reason = 'completed'
        def bounds():
            resource.setrlimit(resource.RLIMIT_FSIZE, (LOG_LIMIT, LOG_LIMIT))
        with (self.results / (label + '.stdout.log')).open('xb') as stdout, (self.results / (label + '.stderr.log')).open('xb') as stderr:
            child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}, preexec_fn=bounds)
            identity = {'pid': child.pid, 'startTimeTicks': None}
            try:
                try:
                    identity['startTimeTicks'] = int(Path(f'/proc/{child.pid}/stat').read_text().rsplit(') ', 1)[1].split()[19])
                except (OSError, IndexError, ValueError):
                    identity['identityUnavailable'] = True
                while child.poll() is None:
                    available = os.statvfs(self.root)
                    if time.monotonic() - started >= seconds or (watch_disk and available.f_bavail * available.f_frsize < RESERVE):
                        reason = 'timeout_or_disk_floor'; child.kill(); break
                    time.sleep(0.2)
            finally:
                if child.poll() is None: child.kill()
                try:
                    code = child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    code = None; reason = 'pending_child'
                    pending = {'command': label, **identity, 'reapTimeoutSeconds': 10, 'automaticRetry': False}
                    self.receipt.setdefault('pendingChildren', []).append(pending)
                    save(self.results / (label + '.pending-child.json'), pending)
        save(self.results / (label + '.exit.json'), {'exitCode': code, 'reason': reason, 'seconds': round(time.monotonic() - started, 3)})
        require(code is not None, 'child remains pending after bounded reap: ' + label)
        require(not check or (code == 0 and reason == 'completed'), 'command failed: ' + label)
        return code if reason == 'completed' else 124, read(self.results / (label + '.stdout.log'))

    def container(self, phase, argv, seconds, *, offline=True, readonly_target=False):
        token = secrets.token_hex(12); name = 'native-review-' + phase + '-' + token
        attempt = {'phase': phase, 'attemptedName': name, 'token': token, 'id': None,
            'offline': offline, 'removed': False, 'cleanupUncertain': True}
        self.receipt['containers'].append(attempt)
        args = ['docker', 'create', '--pull', 'never', '--init', '--name', name, '--label', LABEL + '=' + token,
            '--ipc', 'none', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
            '--cpus', '2', '--memory', '6g', '--memory-swap', '6g', '--pids-limit', '256',
            '--user', str(os.getuid()) + ':' + str(os.getgid()), '--ulimit', 'core=0:0', '--log-driver', 'none',
            '--tmpfs', '/tmp:rw,exec,nosuid,nodev,size=1g,mode=1777',
            '--mount', f'type=bind,src={self.repo},dst=/repository,readonly',
            '--mount', f'type=bind,src={self.root}/vendor,dst=/vendor' + (',readonly' if offline else ''),
            '--mount', f'type=bind,src={self.root}/target,dst=/target' + (',readonly' if readonly_target else ''),
            '--mount', f'type=bind,src={self.results},dst=/results', '--workdir', '/repository/' + CRATE,
            '--env', 'CARGO_HOME=/cargo-home', '--env', 'CARGO_TARGET_DIR=/target', '--env', 'CARGO_BUILD_JOBS=1',
            '--env', 'CARGO_NET_RETRY=0', '--env', 'SOURCE_DATE_EPOCH=0', '--env', 'RUSTFLAGS=-C link-arg=-Wl,--build-id=none']
        if offline:
            args += ['--network', 'none', '--env', 'CARGO_NET_OFFLINE=true', '--tmpfs',
                f'/cargo-home:rw,noexec,nosuid,nodev,size=16m,uid={os.getuid()},gid={os.getgid()}',
                '--mount', f'type=bind,src={self.root}/cargo-config.toml,dst=/cargo-home/config.toml,readonly']
        else:
            args += ['--mount', f'type=bind,src={self.root}/cargo-home,dst=/cargo-home']
        if readonly_target:
            args += ['--ulimit', f'fsize={LOG_LIMIT}:{LOG_LIMIT}']
        cid = None
        try:
            _, raw = self.command(phase + '-create', args + [IMAGE, 'timeout', '--signal=TERM', '--kill-after=10s', str(seconds) + 's', *argv], 30)
            candidate = raw.decode().strip(); require(re.fullmatch('[0-9a-f]{64}', candidate), 'bad container id')
            cid = candidate; attempt['id'] = cid
            code, _ = self.command(phase, ['docker', 'start', '--attach', cid], seconds + 30, check=False)
            require(code == 0, 'container command failed: ' + phase)
        finally:
            inspect_code, raw = self.command(phase + '-inspect', ['docker', 'inspect', '--format',
                '{"Id":{{json .Id}},"Image":{{json .Image}},"Labels":{{json .Config.Labels}},"State":{{json .State}}}', cid or name],
                15, check=False, watch_disk=False)
            require(inspect_code == 0 and raw.strip(), 'owned container cleanup uncertain')
            if raw.strip():
                row = json.loads(raw); require(row['Labels'].get(LABEL) == token and row['Image'] == IMAGE_ID, 'cleanup ownership mismatch')
                attempt['id'] = row['Id']
                _, removed = self.command(phase + '-remove', ['docker', 'rm', '--force', row['Id']], 20, watch_disk=False)
                require(removed.decode().strip() == row['Id'], 'container removal mismatch')
                state = row['State']; attempt.update({'exitCode': state['ExitCode'], 'oomKilled': state['OOMKilled'],
                    'runningBeforeCleanup': state['Running'], 'removed': True, 'cleanupUncertain': False})
                require(not state['Running'] and state['ExitCode'] == 0 and not state['OOMKilled'], 'worker failed: ' + phase)

    def artifact(self, phase, git_files):
        row = cargo_row(read(self.results / (phase + '.stdout.log')), phase)
        if phase == 'library':
            emitted = [name for name in row['filenames'] if name.endswith('.rlib')]
            require(len(emitted) == 1, 'one library artifact required'); emitted = emitted[0]
        else:
            emitted = row['executable']
        require(isinstance(emitted, str) and re.fullmatch(r'/target/release/(?:deps/)?[A-Za-z0-9_-]+(?:\.rlib)?', emitted), 'artifact path refused')
        path = self.root / emitted.removeprefix('/')
        if phase == 'library':
            aliases = [item for item in (self.root / 'target/release/deps').glob('libserverware_decision_gate-*.rlib') if item.samefile(path)]
            require(len(aliases) == 1, 'hashed library alias missing')
            dep = aliases[0].with_name(aliases[0].name.removeprefix('lib')).with_suffix('.d')
        else:
            dep = Path(str(path) + '.d')
        raw = read(dep); inputs = compiler_inputs(raw)
        require(raw.decode().splitlines()[0].startswith('/' + dep.relative_to(self.root).as_posix() + ': '), 'dep-info artifact mismatch')
        inputs.update((CRATE + 'Cargo.toml', CRATE + 'Cargo.lock'))
        closure = {}
        for name in sorted(inputs):
            require(name in git_files and git_files[name][0] in ('100644', '100755'), 'compiler source absent from Git')
            body = read(self.repo / name, 32 * 1024**2)
            require(hashlib.sha1(b'blob ' + str(len(body)).encode() + b'\0' + body).hexdigest() == git_files[name][1], 'compiler source differs from Git')
            closure[name] = hashlib.sha256(body).hexdigest()
        required = ('native_jit_review_open.rs', 'native_startup_config/jit_review_open.rs') if phase == 'bintest' else (
            'native_jit_review_open_v1.rs', 'native_jit_review_open_policy.rs', 'native_jit_review_open_wire.rs',
            'native_jit_review_browser_v1.rs', 'native_jit_review_open_custody.rs', 'native_secret_broker_v1/jit_review_open.rs')
        require(all(CRATE + 'src/' + name in closure for name in required), 'new modules absent from emitted closure')
        require(phase == 'library' or closure.get(FIXTURE) == FIXTURE_SHA, 'historical fixture changed/missing')
        item = {'path': emitted, 'sha256': sha(path), 'depInfoSha256': hashlib.sha256(raw).hexdigest(),
            'sourceHashes': closure, 'fresh': False, 'profile': 'release', 'normalBinary': False}
        save(self.results / (phase + '-artifact.json'), item); self.receipt['artifacts'][phase] = item
        return item

    def run(self):
        _, head = self.command('revision', ['git', '-C', str(self.repo), 'rev-parse', 'HEAD'], 15)
        require(head.decode().strip() == self.revision, 'checkout revision differs')
        _, dirty = self.command('source-before', ['git', '-C', str(self.repo), 'status', '--porcelain=v1', '--untracked-files=all'], 30)
        require(not dirty, 'checkout must be clean')
        _, tree = self.command('git-inputs', ['git', '-C', str(self.repo), 'ls-tree', '-rz', '--full-tree', self.revision], 30)
        git_files = {}
        for record in tree.split(b'\0'):
            if record:
                header, name = record.split(b'\t', 1); mode, kind, oid = header.decode().split()
                if kind == 'blob': git_files[name.decode()] = (mode, oid)
        lock = read(self.repo / CRATE / 'Cargo.lock'); packages = tomllib.loads(lock.decode())['package']
        require(all((item.get('source') == 'registry+https://github.com/rust-lang/crates.io-index'
                     and re.fullmatch('[0-9a-f]{64}', item.get('checksum', '')))
                    or ('source' not in item and item['name'] == 'serverware-decision-gate') for item in packages), 'nonpublic/unpinned dependency')
        roster_raw = read(self.repo / ROSTER); roster = json.loads(roster_raw)
        require({kind: sum(len(item['names']) for item in roster.values() if item['kind'] == kind)
                 for kind in ('library', 'binary')} == {'library': 29, 'binary': 24}, 'control roster count changed')
        self.receipt.update({'cargoLockSha256': hashlib.sha256(lock).hexdigest(), 'rosterSha256': hashlib.sha256(roster_raw).hexdigest()})
        self.command('pull', ['docker', 'pull', '--platform', 'linux/amd64', IMAGE], 180)
        _, image = self.command('image', ['docker', 'image', 'inspect', '--format', '{{.Id}}', IMAGE], 15)
        require(image.decode().strip() == IMAGE_ID, 'Rust image identity differs')
        self.container('provision', ['cargo', 'vendor', '--locked', '--versioned-dirs', '/vendor'], 300, offline=False)
        space = os.statvfs(self.root)
        require(space.f_bavail * space.f_frsize >= 8 * 1024**3, 'need 8 GiB free after provisioning; no automatic host cleanup')
        for phase, command in (
            ('library', ['cargo', 'build', '--lib']),
            ('libtest', ['cargo', 'test', '--lib', '--no-run']),
            ('bintest', ['cargo', 'test', '--bin', 'serverware-decision-gate', '--no-run'])):
            self.container(phase, command + ['--release', '--frozen', '--offline', '--message-format=json'], 900)
            self.artifact(phase, git_files)
        artifacts = self.receipt['artifacts']; script = ['set -eu',
            'rustc --version --verbose > /results/rustc.txt', 'cargo --version > /results/cargo.txt']
        for label, item in roster.items():
            require(re.fullmatch('[a-z-]+', label) and item['kind'] in ('library', 'binary'), 'unsafe control label')
            executable = artifacts['libtest' if item['kind'] == 'library' else 'bintest']['path']
            for suffix, option in (('list', '--list'), ('tests', '--test-threads=1')):
                script.append(shlex.join([executable, item['prefix'], option]) + ' > /results/' + label + '-' + suffix + '.txt')
        for label, source, code, _ in APIS:
            command = shlex.join(['rustc', '--edition=2021', '--emit=metadata', '--error-format=json', '--extern',
                'serverware_decision_gate=' + artifacts['library']['path'], '-L', 'dependency=/target/release/deps',
                '/repository/' + CRATE + 'src/' + source, '-o', '/tmp/' + label + '.rmeta'])
            command += ' > /results/' + label + '.stdout 2> /results/' + label + '.stderr'
            script.append('if ' + command + '; then exit 1; fi' if code else command)
        self.container('tests', ['/bin/sh', '-c', '\n'.join(script)], 120, readonly_target=True)
        for label, item in roster.items():
            check_tests(read(self.results / (label + '-list.txt')).decode(), read(self.results / (label + '-tests.txt')).decode(),
                [item['prefix'] + name for name in item['names']])
        for label, source, code, line in APIS:
            check_api(read(self.results / (label + '.stdout')), read(self.results / (label + '.stderr')), code, source, line)
        for item in artifacts.values(): require(sha(self.root / item['path'].removeprefix('/')) == item['sha256'], 'tested artifact changed')
        require(not (self.root / 'target/release/serverware-decision-gate').exists(), 'normal proxy binary unexpectedly exists')
        _, dirty = self.command('source-after', ['git', '-C', str(self.repo), 'status', '--porcelain=v1', '--untracked-files=all'], 30)
        require(not dirty and sha(self.repo / CRATE / 'Cargo.lock') == self.receipt['cargoLockSha256'], 'checkout changed')
        self.receipt.update({'ok': True, 'passed': {'library': 29, 'binary': 24, 'api': 5}, 'skipped': 0})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-revision', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    require(os.environ.get('GITHUB_ACTIONS') == 'true' and re.fullmatch('[0-9a-f]{40}', args.expected_revision), 'hosted exact revision required')
    root = args.output
    require(root.is_absolute() and root.parent.resolve() == Path(os.environ['RUNNER_TEMP']).resolve()
            and root.name == 'native-jit-review-rust' and not root.exists(), 'fresh job-local output required')
    root.mkdir(mode=0o700); run = HostedRun(Path(__file__).resolve().parents[1], root, args.expected_revision)
    try:
        run.run()
    except BaseException as error:
        run.receipt.update({'ok': False, 'errorType': type(error).__name__, 'error': str(error)[:512]})
        raise
    finally:
        save(run.results / 'result.json', run.receipt)


if __name__ == '__main__':
    main()
