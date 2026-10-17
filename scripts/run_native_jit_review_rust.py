#!/usr/bin/env python3
"""One hosted attempt: engineering controls, or an explicit normal ELF build.

The default remains the 58 engineering controls. Normal mode exports only a
normal ELF and public provenance; neither mode establishes native admission,
runtime acceptance or deployment. No cache restoration or automatic retry.
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
LABEL = 'com.catchplate.hosted-native-review'
CONFIG = '[source.crates-io]\nreplace-with = "vendored-sources"\n[source.vendored-sources]\ndirectory = "/vendor"\n'
BUILD_ENV = {'CARGO_HOME': '/cargo-home', 'CARGO_TARGET_DIR': '/target', 'CARGO_BUILD_JOBS': '1',
             'CARGO_NET_RETRY': '0', 'SOURCE_DATE_EPOCH': '0', 'RUSTFLAGS': '-C link-arg=-Wl,--build-id=none'}
NORMAL_COMMAND = ('cargo', 'build', '--release', '--frozen', '--offline', '--bin',
                  'catchplate-decision-gate', '--message-format=json')
NORMAL_FILES = ('scripts/discard_headers_parity.v1.json', 'policies/credential-limits.examples.json')
NORMAL_SCHEMA = 'catchplate.hostedNormalRust/v1'
NORMAL_WORKFLOW = '.github/workflows/native-review-rust.yml'
NORMAL_RUNNER = 'scripts/run_native_jit_review_rust.py'
NORMAL_BUILD_SECONDS = 1800
NORMAL_PHASES = ('prepare', 'source', 'provision', 'normal', 'artifact-validation', 'cleanup', 'source-check', 'export', 'complete')
NORMAL_COMMAND_LABELS = ('revision', 'source-before', 'git-inputs', 'pull', 'image',
    'provision-create', 'provision', 'provision-inspect', 'provision-remove',
    'normal-create', 'normal', 'normal-inspect', 'normal-remove',
    'provision-remaining', 'normal-remaining', 'source-after')
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


def normal_failure_receipt(run):
    """Fresh public projection only; CLI outcomes are not worker exit/OOM state."""
    require(run.receipt.get('ok') is False and run.normal_phase in NORMAL_PHASES
            and re.fullmatch('[0-9a-f]{40}', run.revision), 'not a normal failure')
    commands = []
    require(len(run.command_results) <= len(NORMAL_COMMAND_LABELS), 'failure command bound')
    for row in run.command_results:
        require(row['command'] in NORMAL_COMMAND_LABELS and row['reason'] in
                ('unavailable', 'completed', 'timeout', 'disk_floor', 'pending_child'), 'failure command scope')
        require(row['exitCode'] is None or type(row['exitCode']) is int, 'failure command exit type')
        if row['reason'] != 'completed' or row['exitCode'] != 0:
            commands.append({'command': row['command'], 'exitCode': row['exitCode'], 'reason': row['reason']})
    workers = []
    require(len(run.receipt['containers']) <= 2, 'failure worker bound')
    for row in run.receipt['containers']:
        require(row['phase'] in ('provision', 'normal'), 'failure worker scope')
        require(row.get('exitCode') is None or type(row['exitCode']) is int, 'failure worker exit type')
        require(all(row.get(key) is None or type(row[key]) is bool
                    for key in ('oomKilled', 'runningBeforeCleanup'))
                and all(type(row[key]) is bool for key in ('removed', 'cleanupUncertain')), 'failure worker state type')
        workers.append({'phase': row['phase'], 'limitSeconds': 300 if row['phase'] == 'provision' else NORMAL_BUILD_SECONDS,
            'exitCode': row.get('exitCode'), 'oomKilled': row.get('oomKilled'),
            'runningBeforeCleanup': row.get('runningBeforeCleanup'),
            'removed': row['removed'], 'cleanupUncertain': row['cleanupUncertain']})
    # An inner timeout's 124 is retained as an exit code, not inferred as proof
    # of timeout. Only the outer supervisor directly observes reason=timeout.
    pending = len(run.receipt.get('pendingChildren', []))
    require(pending <= len(NORMAL_COMMAND_LABELS), 'failure pending bound')
    return {'schema': 'catchplate.hostedNormalRustFailure/v1', 'ok': False,
        'sourceRevision': run.revision, 'phase': run.normal_phase, 'normalBuildLimitSeconds': NORMAL_BUILD_SECONDS,
        'failedCommands': commands, 'workers': workers, 'pendingChildren': pending,
        'normalBinaryPublished': False, 'automaticRetry': False, 'cacheRestored': False}


def save_normal_failure(run):
    if run.receipt.get('ok') is False:
        save(run.root / 'normal-failure.json', normal_failure_receipt(run))


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
                and row.get('target', {}).get('name') == ('catchplate-decision-gate' if binary else 'catchplate_decision_gate')
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


def normal_configuration():
    return {'image': IMAGE, 'imageId': IMAGE_ID, 'platform': 'linux/amd64',
            'command': list(NORMAL_COMMAND), 'workdir': '/repository/' + CRATE,
            'environment': {**BUILD_ENV, 'CARGO_NET_OFFLINE': 'true'}, 'cargoConfig': CONFIG}


def identity_digest(identity):
    return hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def normal_git_files(raw):
    result = {}
    for record in raw.split(b'\0'):
        if record:
            header, raw_name = record.split(b'\t', 1)
            mode, kind, oid = header.decode('ascii').split(); name = raw_name.decode('utf-8')
            require(kind in ('blob', 'commit') and name not in result
                    and not name.startswith('/') and posixpath.normpath(name) == name
                    and '..' not in name.split('/'), 'invalid Git input tree')
            result[name] = (mode, oid)  # Retain submodules; selected nonregular modes refuse below.
    return result


def normal_input_identity(repository, git_files):
    """Conservative compiler closure; no app commit, JS or top-level docs key.

    The caller supplies a clean exact Git tree, not a claimed verification flag.
    Every selected byte is independently joined to that tree here. Newly added
    crate/schema inputs alter the roster even before a compiler has seen them.
    """
    for parent in ('', 'data-plane/', CRATE):
        forbidden = ('.cargo', 'rust-toolchain', 'rust-toolchain.toml')
        if parent != CRATE:
            forbidden += ('Cargo.toml',)
        for leaf in forbidden:
            path = repository / (parent + leaf)
            require(not path.exists() and not path.is_symlink(), 'unreviewed compiler configuration')
    require(not (repository / CRATE / 'build.rs').exists()
            and not (repository / CRATE / 'build.rs').is_symlink(), 'first-party build script refused')
    manifest = tomllib.loads(read(repository / CRATE / 'Cargo.toml', 1024**2).decode())
    require(not {'build', 'workspace'} & manifest['package'].keys()
            and not {'workspace', 'build-dependencies'} & manifest.keys()
            and not any('build-dependencies' in item for item in manifest.get('target', {}).values()),
            'unreviewed workspace/build dependencies')
    names = sorted(name for name in git_files if name.startswith((CRATE, 'schemas/')) or name in NORMAL_FILES)
    require(1 <= len(names) <= 4096 and set(NORMAL_FILES) <= set(names)
            and {CRATE + 'Cargo.toml', CRATE + 'Cargo.lock', CRATE + 'src/main.rs',
                 CRATE + 'src/custody_protocol.rs'} <= set(names), 'normal input roster incomplete')
    rows, total = {}, 0
    for name in names:
        mode, oid = git_files[name]
        require(mode in ('100644', '100755') and re.fullmatch('[0-9a-f]{40}', oid), 'nonregular Git input')
        path = repository / name
        require(path.resolve() == path and not path.is_symlink(), 'indirect compiler input')
        body = read(path, 32 * 1024**2); total += len(body)
        require(total <= 256 * 1024**2 and hashlib.sha1(b'blob ' + str(len(body)).encode() + b'\0' + body).hexdigest() == oid,
                'compiler input differs from Git or bound')
        rows[name] = {'mode': mode, 'gitBlob': oid, 'sha256': hashlib.sha256(body).hexdigest()}
    version = manifest['package']['version']
    require(type(version) is str and re.fullmatch(r'[0-9A-Za-z.+-]{1,128}', version), 'package version differs')
    return {'schema': 'catchplate.normalRustBuildInputs/v1', 'configuration': normal_configuration(),
            'packageVersion': version, 'files': rows}


def normal_cargo_rows(raw):
    rows = [json.loads(line) for line in raw.splitlines()]
    require([row['success'] for row in rows if row.get('reason') == 'build-finished'] == [True], 'normal build incomplete')
    selected = {}
    for kind, name, source in (('binary', 'catchplate-decision-gate', 'main.rs'),
                               ('library', 'catchplate_decision_gate', 'custody_protocol.rs')):
        matches = [row for row in rows if row.get('reason') == 'compiler-artifact'
                   and row.get('target', {}).get('name') == name]
        require(len(matches) == 1, 'normal target is missing or ambiguous')
        row = matches[0]
        require(row['target']['kind'] == (['bin'] if kind == 'binary' else ['lib'])
                and row['target']['src_path'] == '/repository/' + CRATE + 'src/' + source
                and row['profile']['test'] is False and row['profile']['opt_level'] == '3'
                and row['fresh'] is False and row['features'] == [], 'normal Cargo profile/target differs')
        selected[kind] = row
    require(selected['binary']['executable'] == '/target/release/catchplate-decision-gate'
            and selected['binary']['filenames'] == ['/target/release/catchplate-decision-gate']
            and selected['library']['executable'] is None, 'normal executable path differs')
    return selected


def normal_dep_info(raw, targets, version):
    """Closed rustc Make-style subset for this fixed ASCII, no-build-script crate."""
    require(raw.endswith(b'\n') and b'\\' not in raw and b'\r' not in raw, 'unsupported dep-info escaping')
    files, phony, environment, seen = None, set(), {}, set()
    def source_path(value):
        require(re.fullmatch(r'[A-Za-z0-9_./+-]+', value), 'unsupported compiler input spelling')
        absolute = posixpath.normpath(value if value.startswith('/') else '/repository/' + CRATE + value)
        require(absolute.startswith('/repository/'), 'compiler input escapes checkout')
        return absolute.removeprefix('/repository/')
    for line in raw.decode('ascii').splitlines():
        if not line:
            continue
        if line.startswith('# env-dep:'):
            key, separator, value = line[len('# env-dep:'):].partition('=')
            require(separator and key == 'CARGO_PKG_VERSION' and value == version and key not in environment,
                    'unsupported compiler environment dependency')
            environment[key] = value
            continue
        target, separator, dependencies = line.partition(':')
        require(separator and target not in seen and not line.startswith('#'), 'unrecognized dep-info record')
        seen.add(target)
        if dependencies.strip():
            require(target in targets, 'dep-info target differs')
            names = {source_path(item) for item in dependencies.split()}
            require(1 <= len(names) <= 4096 and (files is None or files == names), 'dep-info rules disagree')
            files = names
        else:
            phony.add(source_path(target))
    require(files is not None and phony <= files, 'dep-info closure incomplete')
    return files, environment


def verify_normal_receipt(receipt, binary_bytes, current_identity):
    """Pure artifact/current-input joins; GitHub provenance is the consumer's job."""
    require(type(receipt) is dict and set(receipt) == {'schema', 'ok', 'sourceRevision', 'buildInputIdentity', 'buildInputs',
        'cargoLockSha256', 'github', 'runnerSourceSha256', 'toolchain', 'binary', 'compilerInputs', 'cleanup',
        'normalBinary', 'tested', 'deployed', 'nativeAdmission', 'cacheRestored', 'automaticRetry'}, 'normal receipt shape')
    require(receipt['schema'] == NORMAL_SCHEMA and receipt['ok'] is True and receipt['normalBinary'] is True
            and all(receipt[key] is False for key in ('tested', 'deployed', 'nativeAdmission', 'cacheRestored', 'automaticRetry')),
            'normal receipt scope differs')
    require(type(current_identity) is dict and set(current_identity) == {'schema', 'configuration', 'packageVersion', 'files'}
            and re.fullmatch('[0-9a-f]{40}', receipt['sourceRevision'])
            and re.fullmatch('[0-9a-f]{64}', receipt['runnerSourceSha256'])
            and receipt['buildInputs'] == current_identity
            and current_identity['schema'] == 'catchplate.normalRustBuildInputs/v1'
            and current_identity['configuration'] == normal_configuration()
            and receipt['buildInputIdentity'] == identity_digest(current_identity), 'normal build identity differs')
    files = current_identity['files']
    require(receipt['cargoLockSha256'] == files[CRATE + 'Cargo.lock']['sha256'], 'normal lock differs')
    github = receipt['github']
    require(type(github) is dict and set(github) == {'repository', 'runId', 'runAttempt', 'workflowPath', 'job'}
            and re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', github['repository'])
            and all(type(github[key]) is int and 0 < github[key] < 2**63 for key in ('runId', 'runAttempt'))
            and github['workflowPath'] == NORMAL_WORKFLOW and github['job'] == 'normal-proxy', 'normal GitHub provenance shape')
    require(type(binary_bytes) is bytes and 64 <= len(binary_bytes) <= 512 * 1024**2
            and binary_bytes[:7] == b'\x7fELF\x02\x01\x01' and binary_bytes[18:20] == b'\x3e\x00'
            and binary_bytes[16:18] in (b'\x02\x00', b'\x03\x00'), 'normal ELF format differs')
    require(receipt['binary'] == {'name': 'catchplate-decision-gate', 'sha256': hashlib.sha256(binary_bytes).hexdigest(),
                                 'bytes': len(binary_bytes), 'mode': '0555'}, 'normal ELF identity differs')
    toolchain = receipt['toolchain']
    require(type(toolchain) is dict and set(toolchain) == {'rustcVersionVerbose', 'cargoVersion'}
            and all(type(value) is str and len(value) <= 4096 for value in toolchain.values())
            and toolchain['rustcVersionVerbose'].startswith('rustc 1.88.0 ')
            and '\nhost: x86_64-unknown-linux-gnu\n' in toolchain['rustcVersionVerbose']
            and toolchain['cargoVersion'].startswith('cargo 1.88.0 '), 'normal toolchain differs')
    require(type(receipt['compilerInputs']) is dict and set(receipt['compilerInputs']) == {'binary', 'library'},
            'normal compiler closure missing')
    for kind, source in (('binary', 'main.rs'), ('library', 'custody_protocol.rs')):
        item = receipt['compilerInputs'][kind]
        require(type(item) is dict and set(item) == {'artifactPath', 'artifactSha256', 'depInfoPath', 'depInfoSha256', 'files', 'environment'}
                and re.fullmatch('[0-9a-f]{64}', item['artifactSha256'])
                and re.fullmatch('[0-9a-f]{64}', item['depInfoSha256'])
                and re.fullmatch(r'/target/release/deps/catchplate_decision_gate-[0-9a-f]{16}\.d', item['depInfoPath'])
                and type(item['files']) is dict and CRATE + 'src/' + source in item['files']
                and all(name in files and row == files[name] for name, row in item['files'].items())
                and type(item['environment']) is dict and set(item['environment']) <= {'CARGO_PKG_VERSION'}
                and all(value == current_identity['packageVersion'] for value in item['environment'].values()),
                'normal compiler input provenance differs')
        require((item['artifactPath'] == '/target/release/catchplate-decision-gate'
                 and item['artifactSha256'] == receipt['binary']['sha256']) if kind == 'binary' else
                item['artifactPath'] == item['depInfoPath'].removesuffix('.d').replace('/catchplate_', '/libcatchplate_') + '.rlib',
                'normal compiler artifact differs')
    require(type(receipt['cleanup']) is dict and set(receipt['cleanup']) == {'allOwnedContainersRemoved', 'phases'}
            and receipt['cleanup']['allOwnedContainersRemoved'] is True
            and receipt['cleanup']['phases'] == ['provision', 'normal'],
            'normal workers did not reach clean terminal state')


class HostedRun:
    def __init__(self, repository, output, revision):
        self.repo, self.root, self.revision = repository, output, revision
        self.normal_phase, self.command_results = 'prepare', []
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
        outcome = {'command': label, 'exitCode': None, 'reason': 'unavailable'}
        self.command_results.append(outcome)
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
                    if time.monotonic() - started >= seconds:
                        reason = 'timeout'; child.kill(); break
                    if watch_disk and available.f_bavail * available.f_frsize < RESERVE:
                        reason = 'disk_floor'; child.kill(); break
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
        outcome.update({'exitCode': code, 'reason': reason})
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
            '--mount', f'type=bind,src={self.results},dst=/results', '--workdir', '/repository/' + CRATE]
        args += [part for key, value in BUILD_ENV.items() for part in ('--env', key + '=' + value)]
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
                state = row['State']; attempt.update({'exitCode': state['ExitCode'], 'oomKilled': state['OOMKilled'],
                    'runningBeforeCleanup': state['Running']})
                _, removed = self.command(phase + '-remove', ['docker', 'rm', '--force', row['Id']], 20, watch_disk=False)
                require(removed.decode().strip() == row['Id'], 'container removal mismatch')
                attempt.update({'removed': True, 'cleanupUncertain': False})
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
            aliases = [item for item in (self.root / 'target/release/deps').glob('libcatchplate_decision_gate-*.rlib') if item.samefile(path)]
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
                    or ('source' not in item and item['name'] == 'catchplate-decision-gate') for item in packages), 'nonpublic/unpinned dependency')
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
            ('bintest', ['cargo', 'test', '--bin', 'catchplate-decision-gate', '--no-run'])):
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
                'catchplate_decision_gate=' + artifacts['library']['path'], '-L', 'dependency=/target/release/deps',
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
        require(not (self.root / 'target/release/catchplate-decision-gate').exists(), 'normal proxy binary unexpectedly exists')
        _, dirty = self.command('source-after', ['git', '-C', str(self.repo), 'status', '--porcelain=v1', '--untracked-files=all'], 30)
        require(not dirty and sha(self.repo / CRATE / 'Cargo.lock') == self.receipt['cargoLockSha256'], 'checkout changed')
        self.receipt.update({'ok': True, 'passed': {'library': 29, 'binary': 24, 'api': 5}, 'skipped': 0})

    def run_normal(self):
        """One normal build, never an alias for a test artifact or cached target."""
        self.normal_phase = 'source'
        self.receipt['scope'] = 'normal release ELF build; no runtime acceptance'
        _, head = self.command('revision', ['git', '-C', str(self.repo), 'rev-parse', 'HEAD'], 15)
        require(head.decode().strip() == self.revision, 'checkout revision differs')
        _, dirty = self.command('source-before', ['git', '-C', str(self.repo), 'status', '--porcelain=v1', '--untracked-files=all'], 30)
        require(not dirty, 'checkout must be clean')
        _, tree = self.command('git-inputs', ['git', '-C', str(self.repo), 'ls-tree', '-rz', '--full-tree', self.revision], 30)
        git_files = normal_git_files(tree)
        identity = normal_input_identity(self.repo, git_files)
        manifest = tomllib.loads(read(self.repo / CRATE / 'Cargo.toml', 1024**2).decode())
        lock = read(self.repo / CRATE / 'Cargo.lock'); packages = tomllib.loads(lock.decode())['package']
        require(all((item.get('source') == 'registry+https://github.com/rust-lang/crates.io-index'
                     and re.fullmatch('[0-9a-f]{64}', item.get('checksum', '')))
                    or ('source' not in item and item['name'] == 'catchplate-decision-gate') for item in packages),
                'nonpublic/unpinned dependency')
        repository = os.environ.get('GITHUB_REPOSITORY', '')
        require(os.environ.get('GITHUB_SHA') == self.revision and os.environ.get('GITHUB_JOB') == 'normal-proxy'
                and os.environ.get('GITHUB_WORKFLOW_REF', '').startswith(repository + '/' + NORMAL_WORKFLOW + '@refs/')
                and re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository)
                and all(re.fullmatch('[1-9][0-9]{0,18}', os.environ.get(key, ''))
                        for key in ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT')), 'normal hosted provenance unavailable')
        self.command('pull', ['docker', 'pull', '--platform', 'linux/amd64', IMAGE], 180)
        _, image = self.command('image', ['docker', 'image', 'inspect', '--format', '{{.Id}}', IMAGE], 15)
        require(image.decode().strip() == IMAGE_ID, 'Rust image identity differs')
        self.normal_phase = 'provision'
        self.container('provision', ['cargo', 'vendor', '--locked', '--versioned-dirs', '/vendor'], 300, offline=False)
        space = os.statvfs(self.root)
        require(space.f_bavail * space.f_frsize >= 8 * 1024**3, 'need 8 GiB free after provisioning')
        self.normal_phase = 'normal'
        self.container('normal', ['/bin/sh', '-c', 'set -eu\n'
            'rustc --version --verbose > /results/normal-rustc.txt\n'
            'cargo --version > /results/normal-cargo.txt\nexec ' + shlex.join(NORMAL_COMMAND)], NORMAL_BUILD_SECONDS)
        self.normal_phase = 'artifact-validation'
        rows = normal_cargo_rows(read(self.results / 'normal.stdout.log'))
        binary_path = self.root / 'target/release/catchplate-decision-gate'
        binary_bytes = read(binary_path, 512 * 1024**2)
        require(binary_path.stat().st_mode & 0o111, 'normal ELF is not executable')
        # Cargo's root .d can omit rustc env-dep records. Join the actual compiler
        # unit through its ELF hardlink/identical bytes, then parse its complete .d.
        units = [path for path in (self.root / 'target/release/deps').glob('catchplate_decision_gate-*')
                 if re.fullmatch(r'catchplate_decision_gate-[0-9a-f]{16}', path.name)]
        require(1 <= len(units) <= 4, 'normal compiler unit count differs')
        aliases = [path for path in units if not path.is_symlink()
                   and (path.samefile(binary_path) or read(path, 512 * 1024**2) == binary_bytes)]
        require(len(aliases) == 1, 'normal compiler-unit ELF join missing')
        library = [path for path in rows['library']['filenames']
                   if re.fullmatch(r'/target/release/(?:libcatchplate_decision_gate|deps/libcatchplate_decision_gate-[0-9a-f]{16})\.rlib', path)]
        require(len(library) == 1, 'linked library artifact missing')
        library_path = self.root / library[0].removeprefix('/')
        library_bytes = read(library_path, 512 * 1024**2)
        library_units = [path for path in (self.root / 'target/release/deps').glob('libcatchplate_decision_gate-*.rlib')
                         if re.fullmatch(r'libcatchplate_decision_gate-[0-9a-f]{16}\.rlib', path.name)]
        require(1 <= len(library_units) <= 4, 'linked library compiler unit count differs')
        library_aliases = [path for path in library_units if not path.is_symlink()
                           and (path.samefile(library_path) or read(path, 512 * 1024**2) == library_bytes)]
        require(len(library_aliases) == 1, 'linked library compiler-unit join missing')
        units = {'binary': '/' + aliases[0].relative_to(self.root).as_posix(),
                 'library': '/' + library_aliases[0].relative_to(self.root).as_posix()}
        compiler = {}
        for kind, artifact_path in units.items():
            stem = artifact_path if kind == 'binary' else artifact_path.removesuffix('.rlib').replace('/libcatchplate_', '/catchplate_')
            dep_path = stem + '.d'
            targets = {dep_path, artifact_path}
            if kind == 'library':
                targets.add(artifact_path.removesuffix('.rlib') + '.rmeta')
            raw = read(self.root / dep_path.removeprefix('/'))
            names, environment = normal_dep_info(raw, targets, manifest['package']['version'])
            require(names <= identity['files'].keys(), 'compiler consumed an undeclared input')
            artifact_bytes = binary_bytes if kind == 'binary' else read(self.root / artifact_path.removeprefix('/'), 512 * 1024**2)
            require(kind == 'binary' or artifact_bytes.startswith(b'!<arch>\n'), 'linked library is not an rlib archive')
            compiler[kind] = {'artifactPath': rows['binary']['executable'] if kind == 'binary' else artifact_path,
                'artifactSha256': hashlib.sha256(artifact_bytes).hexdigest(),
                'depInfoPath': dep_path, 'depInfoSha256': hashlib.sha256(raw).hexdigest(),
                'files': {name: identity['files'][name] for name in sorted(names)}, 'environment': environment}
        self.normal_phase = 'cleanup'
        require(not self.receipt.get('pendingChildren') and len(self.receipt['containers']) == 2
                and [row['phase'] for row in self.receipt['containers']] == ['provision', 'normal']
                and all(row['removed'] is True and row['cleanupUncertain'] is False and row['exitCode'] == 0
                        and row['oomKilled'] is False and row['runningBeforeCleanup'] is False
                        for row in self.receipt['containers']), 'normal cleanup incomplete')
        for row in self.receipt['containers']:
            _, remaining = self.command(row['phase'] + '-remaining', ['docker', 'ps', '-aq', '--no-trunc', '--filter',
                'label=' + LABEL + '=' + row['token']], 15, watch_disk=False)
            require(not remaining.strip(), 'normal owned container remains')
        self.normal_phase = 'source-check'
        _, dirty = self.command('source-after', ['git', '-C', str(self.repo), 'status', '--porcelain=v1', '--untracked-files=all'], 30)
        require(not dirty and normal_input_identity(self.repo, git_files) == identity
                and read(self.root / 'cargo-config.toml') == CONFIG.encode(), 'normal source/config changed')
        receipt = {'schema': NORMAL_SCHEMA, 'ok': True, 'sourceRevision': self.revision,
            'buildInputIdentity': identity_digest(identity), 'buildInputs': identity,
            'cargoLockSha256': hashlib.sha256(lock).hexdigest(),
            'github': {'repository': repository, 'runId': int(os.environ['GITHUB_RUN_ID']),
                'runAttempt': int(os.environ['GITHUB_RUN_ATTEMPT']), 'workflowPath': NORMAL_WORKFLOW, 'job': 'normal-proxy'},
            'runnerSourceSha256': sha(self.repo / NORMAL_RUNNER),
            'toolchain': {'rustcVersionVerbose': read(self.results / 'normal-rustc.txt', 4096).decode('ascii'),
                          'cargoVersion': read(self.results / 'normal-cargo.txt', 4096).decode('ascii')},
            'binary': {'name': 'catchplate-decision-gate', 'sha256': hashlib.sha256(binary_bytes).hexdigest(),
                       'bytes': len(binary_bytes), 'mode': '0555'}, 'compilerInputs': compiler,
            'cleanup': {'allOwnedContainersRemoved': True, 'phases': ['provision', 'normal']},
            'normalBinary': True, 'tested': False, 'deployed': False, 'nativeAdmission': False,
            'cacheRestored': False, 'automaticRetry': False}
        verify_normal_receipt(receipt, binary_bytes, identity)
        self.normal_phase = 'export'
        export = self.root / 'artifact'; export.mkdir(mode=0o700)
        with (export / 'catchplate-decision-gate').open('xb') as stream:
            stream.write(binary_bytes); stream.flush(); os.fsync(stream.fileno()); os.fchmod(stream.fileno(), 0o555)
        save(export / 'normal.json', receipt)
        self.receipt.update({'ok': True, 'normalProxyBinaryBuilt': True,
                             'buildInputIdentity': receipt['buildInputIdentity'], 'publicArtifact': 'artifact'})
        self.normal_phase = 'complete'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-revision', required=True)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--mode', choices=('engineering', 'normal'), default='engineering')
    args = parser.parse_args()
    require(os.environ.get('GITHUB_ACTIONS') == 'true' and re.fullmatch('[0-9a-f]{40}', args.expected_revision), 'hosted exact revision required')
    root = args.output
    require(root.is_absolute() and root.parent.resolve() == Path(os.environ['RUNNER_TEMP']).resolve()
            and root.name == ('native-jit-review-rust' if args.mode == 'engineering' else 'normal-proxy-rust')
            and not root.exists(), 'fresh job-local output required')
    root.mkdir(mode=0o700); run = HostedRun(Path(__file__).resolve().parents[1], root, args.expected_revision)
    try:
        if args.mode == 'normal':
            run.run_normal()
        else:
            run.run()
    except BaseException as error:
        run.receipt.update({'ok': False, 'errorType': type(error).__name__, 'error': str(error)[:512]})
        raise
    finally:
        if args.mode == 'normal':
            save_normal_failure(run)
        save(run.results / 'result.json', run.receipt)


if __name__ == '__main__':
    main()
