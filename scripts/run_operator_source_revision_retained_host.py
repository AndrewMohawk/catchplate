#!/usr/bin/env python3
"""One explicitly selected role against an isolated retained migration copy.

Run with python3 -I -B under an outer timeout. This owner never advances to the
next role, retries a claim, pulls/builds images, mounts live state, promotes a
database or rolls back. Failure keeps the copied files and private bounded logs.
Only the returned, fully inspected, stopped container ID may be removed.
Running or uncertain containers are retained; cleanup never stops or forces them.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import time

ROOT = Path('/srv/catchplate-archive/homelab_data/catchplate-source350-release.6kZhpc9d')
CAPTURE = Path('/srv/catchplate-archive/homelab_data/catchplate-pending-actions-release.FHXB1YSb/capture')
COMMIT = 'cb326c64de920aa3eeca692b6b9b8e411a8a0cd1'
SOURCE = ROOT / ('source-' + COMMIT)
WORK = ROOT / 'copy'
RECEIPTS = ROOT / 'host-receipts'
RUNNER = ROOT / 'runner'
STARTUP_ENVIRONMENT = ROOT / 'startup-runtime.env'
IMAGE = 'sha256:ec14a558a42e483a834860521e399b461a2df880fcba495e7127b0d8d2a51e01'
BINARY_SHA = 'e30fe08b97815970aaa08c0317d74ccf96e525a0c3a9957a0b351c69e12f6626'
ROLES = ('prepare', 'recover', 'plan', 'apply', 'freeze', 'startup1', 'observe1', 'startup2', 'observe2', 'result')
LABEL_KEY = 'catchplate.source-revision-retained'
LABEL = '6kZhpc9d'
SCHEMA = 'catchplate.sourceRevisionRetainedHost/v1'
ENV = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'GOMAXPROCS': '2'}
DOCKER = ['/usr/bin/docker', '--host', 'unix:///var/run/docker.sock']
MAX_FILE_BYTES = 64 * 1024**2
STREAM_LIMIT = 256 * 1024
TMPFS = 'rw,nosuid,nodev,noexec,size=128m,uid=10001,gid=10001,mode=0700'


def need(value):
    if not value:
        raise ValueError('retained source-revision host refused')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def save_bytes(path, raw, *, mode):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fchmod(stream.fileno(), mode)
        os.fsync(stream.fileno())
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
    return sha(raw)


def save(path, value, *, mode=0o444):
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode() + b'\n'
    return save_bytes(path, raw, mode=mode)


def pinned(path, digest, limit=8 * 1024**2):
    need(type(digest) is str and re.fullmatch('[0-9a-f]{64}', digest))
    path = Path(path)
    before = path.lstat()
    need(path.resolve(strict=True) == path and stat.S_ISREG(before.st_mode)
         and before.st_nlink == 1 and before.st_size <= limit)
    raw = path.read_bytes()
    identity = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
        value.st_uid, value.st_gid, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
    need(len(raw) == before.st_size and sha(raw) == digest and identity(path.lstat()) == identity(before))
    return raw


def load(name, path, digest):
    pinned(path, digest)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def environment(values):
    """Inspect environment values only in memory; receipts never contain them."""
    need(type(values) is list and len(values) <= 512)
    result = {}
    for value in values:
        need(type(value) is str and '\x00' not in value and '=' in value)
        name, content = value.split('=', 1)
        need(re.fullmatch('[A-Za-z_][A-Za-z0-9_]*', name) and name not in result)
        result[name] = content
    return result


def startup_environment_bytes(captured):
    """Keep every captured line except the two explicitly selected replacements."""
    need(type(captured) is bytes and 0 < len(captured) <= 65536
         and captured.endswith(b'\n') and b'\r' not in captured)
    values = environment(captured.decode('utf-8').splitlines())
    replacements = {'PYTHONDONTWRITEBYTECODE': '1',
        'CATCHPLATE_EXPECTED_DATA_PLANE_BINARY_DIGEST': 'sha256:' + BINARY_SHA}
    need(set(replacements) <= set(values))
    derived = ''.join(name + '=' + replacements.get(name, value) + '\n'
        for name, value in values.items()).encode('utf-8')
    need(len(derived) <= 65536)
    return derived


def startup_environment(cfg, *, create=False):
    """Private one-attempt file; never overwrite or expose captured secret values."""
    need(cfg['normalBinarySha256'] == BINARY_SHA)
    original = pinned(CAPTURE / 'app.env', cfg['capturePins']['app.env'], 65536)
    raw = startup_environment_bytes(original)
    if create:
        save_bytes(STARTUP_ENVIRONMENT, raw, mode=0o400)
    before = STARTUP_ENVIRONMENT.lstat()
    need(stat.S_ISREG(before.st_mode) and stat.S_IMODE(before.st_mode) == 0o400
         and before.st_uid == before.st_gid == 1000 and before.st_nlink == 1)
    need(pinned(STARTUP_ENVIRONMENT, sha(raw), 65536) == raw)
    after = STARTUP_ENVIRONMENT.lstat()
    identity = lambda info: (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
        info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    need(identity(before) == identity(after))
    return {'sha256': sha(raw), 'bytes': len(raw), 'uid': before.st_uid, 'gid': before.st_gid,
        'mode': stat.S_IMODE(before.st_mode), 'device': before.st_dev, 'inode': before.st_ino,
        'mtimeNs': before.st_mtime_ns, 'ctimeNs': before.st_ctime_ns,
        'capturedEnvironmentSha256': cfg['capturePins']['app.env']}


def expected_environment(image_environment, role, cfg):
    need(cfg['normalBinarySha256'] == BINARY_SHA)
    result = environment(image_environment)
    if role.startswith('startup'):
        info = startup_environment(cfg)
        raw = pinned(STARTUP_ENVIRONMENT, info['sha256'], 65536)
        result.update(environment(raw.decode('utf-8').splitlines()))
    result['PYTHONDONTWRITEBYTECODE'] = '1'
    return result


def plan(role, inputs_sha256):
    need(role in ROLES and re.fullmatch('[0-9a-f]{64}', inputs_sha256))
    privileged = role in ('prepare', 'result')
    mounts = [(SOURCE, '/app', True), (ROOT / 'inputs.json', '/inputs.json', True),
        (ROOT / 'proofs', '/proofs', True), (RECEIPTS, '/host-receipts', True)]
    for name in ('run_operator_source_revision_retained.py', 'operator_source_revision_retained.py'):
        mounts.append((RUNNER / name, '/runner/' + name, True))
    if privileged:
        mounts += [(CAPTURE, '/captured', True), (WORK, '/job', False)]
    else:
        mounts += [(WORK / 'out', '/out', False),
            (WORK / 'candidate/persistent/app-data', '/data', role not in ('recover', 'apply', 'startup1', 'startup2'))]
        mounts += [(WORK / ('candidate/' + leaf), '/' + leaf + '-custody', not role.startswith('startup'))
            for leaf in ('provider', 'notification', 'x')]
        if role.startswith('startup'):
            mounts += [(WORK / 'candidate/persistent/service-secrets', '/run/secrets/catchplate', True),
                (WORK / 'candidate/persistent/upstream-data/demo-upstream', '/demo-upstream', True),
                (WORK / 'startup.env', '/startup.env', True)]
        if role == 'recover':
            mounts.append((WORK / 'recovery/persistent/app-data', '/recovery-data', False))
    name = 'catchplate-source350-6kzhpc9d-' + role
    command = [*DOCKER, 'create', '--name', name, '--label', LABEL_KEY + '=' + LABEL,
        '--pull', 'never', '--network', 'none', '--read-only', '--no-healthcheck', '--ipc', 'private',
        '--cgroupns', 'private', '--user', '0:0' if privileged else '10001:10001', '--cap-drop', 'ALL',
        '--security-opt', 'no-new-privileges', '--cpus', '1', '--memory', '768m', '--memory-swap', '768m',
        '--pids-limit', '96', '--ulimit', 'fsize=' + str(MAX_FILE_BYTES) + ':' + str(MAX_FILE_BYTES),
        '--log-driver', 'none', '--tmpfs', '/tmp:' + TMPFS, '--workdir', '/app']
    if privileged:
        for cap in ('DAC_OVERRIDE', 'CHOWN', 'FOWNER'):
            command += ['--cap-add', cap]
    for source, target, readonly in mounts:
        command += ['--mount', 'type=bind,src=' + str(source) + ',dst=' + target + (',readonly' if readonly else '')]
    if role.startswith('startup'):
        command += ['--env-file', str(STARTUP_ENVIRONMENT)]
    else:
        command += ['--env', 'PYTHONDONTWRITEBYTECODE=1']
    command += ['--entrypoint', 'python', IMAGE,
        '-B', '/runner/run_operator_source_revision_retained.py', role, inputs_sha256]
    return {'role': role, 'name': name, 'image': IMAGE, 'mounts': [[str(a), b, c] for a, b, c in mounts],
        'createArgv': command, 'inputsSha256': inputs_sha256}


def identity(identifier, actual, selected):
    need(type(identifier) is str and re.fullmatch('[0-9a-f]{64}', identifier)
         and actual['Id'] == identifier and actual['Name'] == '/' + selected['name']
         and actual['Image'] == IMAGE and actual['Config']['Labels'].get(LABEL_KEY) == LABEL)


def isolation(actual, selected, expected_env):
    """Fail before start on extra mounts, changed limits, authority or routing."""
    privileged = selected['role'] in ('prepare', 'result')
    host, config = actual['HostConfig'], actual['Config']
    mounts = actual['Mounts']
    need(all(row['Type'] == 'bind' and row['Propagation'] == 'rprivate' for row in mounts)
         and sorted((row['Source'], row['Destination'], not row['RW']) for row in mounts)
             == sorted(tuple(row) for row in selected['mounts']))
    need(host['NetworkMode'] == 'none' and host['ReadonlyRootfs'] is True
         and config['User'] == ('0:0' if privileged else '10001:10001')
         and config['Healthcheck'].get('Test') == ['NONE'] and host['Privileged'] is False
         and host['Memory'] == host['MemorySwap'] == 768 * 1024**2
         and host['NanoCpus'] == 1_000_000_000 and host['PidsLimit'] == 96
         and host['Ulimits'] == [{'Name': 'fsize', 'Hard': MAX_FILE_BYTES, 'Soft': MAX_FILE_BYTES}]
         and host['CapDrop'] == ['ALL']
         and set(host['CapAdd'] or []) == ({'CAP_DAC_OVERRIDE', 'CAP_CHOWN', 'CAP_FOWNER'} if privileged else set())
         and host['SecurityOpt'] == ['no-new-privileges']
         and host['LogConfig'] == {'Type': 'none', 'Config': {}}
         and host['Tmpfs'] == {'/tmp': TMPFS}
         and not host['PortBindings'] and host['RestartPolicy'] == {'Name': 'no', 'MaximumRetryCount': 0}
         and host['PidMode'] == '' and host['IpcMode'] == 'private' and host['UTSMode'] == ''
         and host['CgroupnsMode'] == 'private' and host['UsernsMode'] == ''
         and all(not host.get(key) for key in ('Devices', 'DeviceRequests', 'DeviceCgroupRules',
             'Binds', 'VolumesFrom', 'Links', 'ExtraHosts', 'Dns', 'DnsOptions', 'DnsSearch'))
         and all(value is None for value in (actual['NetworkSettings']['Ports'] or {}).values())
         and set(actual['NetworkSettings']['Networks']) <= {'none'}
         and config['WorkingDir'] == '/app' and config['Entrypoint'] == ['python']
         and config['Cmd'] == ['-B', '/runner/run_operator_source_revision_retained.py',
             selected['role'], selected['inputsSha256']]
         and config['OpenStdin'] is False and config['Tty'] is False
         and environment(config['Env']) == expected_env)
    return {'networkNone': True, 'readonlyRoot': True, 'user': config['User'],
        'memoryBytes': host['Memory'], 'memorySwapBytes': host['MemorySwap'], 'nanoCpus': host['NanoCpus'],
        'pidsLimit': host['PidsLimit'], 'fileLimitBytes': MAX_FILE_BYTES, 'privateTmpfsBytes': 128 * 1024**2,
        'noNewPrivileges': True, 'mountsExact': True, 'environmentExact': True, 'publishedPorts': False}


def terminal_projection(actual):
    return {key: actual['State'][key] for key in (
        'Status', 'Running', 'Paused', 'Restarting', 'Dead', 'ExitCode', 'OOMKilled', 'StartedAt', 'FinishedAt')}


def terminal_state(actual):
    terminal = terminal_projection(actual)
    need(terminal['Status'] == 'exited' and terminal['ExitCode'] == 0
         and all(terminal[key] is False for key in ('Running', 'Paused', 'Restarting', 'Dead', 'OOMKilled'))
         and actual['RestartCount'] == 0)
    return terminal


def previous_receipt(role, inputs_sha256, helper_sha256, cfg, proof, startup_env=None):
    index = ROLES.index(role)
    if index == 0:
        return None
    previous = ROLES[index - 1]
    path = RECEIPTS / (previous + '.json')
    raw = path.read_bytes()
    need(len(raw) <= 32768 and path.resolve(strict=True) == path and not path.is_symlink())
    receipt = json.loads(raw)
    validate_receipt(receipt, previous, inputs_sha256, helper_sha256, cfg, proof)
    if startup_env is not None:
        need(receipt['startupEnvironment'] == startup_env)
    return {'role': previous, 'sha256': sha(raw)}


def validate_receipt(receipt, role, inputs_sha256, helper_sha256, cfg, proof):
    need(receipt['schema'] == SCHEMA and receipt['role'] == role and receipt['ok'] is True
         and receipt['containerRemoved'] is True and receipt['sourceAndCaptureUnchanged'] is True
         and receipt['exitCode'] == 0 and receipt['inputsSha256'] == inputs_sha256
         and receipt['helperSha256'] == helper_sha256 and receipt['workerSha256'] == cfg['workerSha256']
         and receipt['helpersSha256'] == cfg['helpersSha256'] and receipt['sourceProof'] == proof
         and receipt['oomKilled'] is False and receipt['restartCount'] == 0
         and type(receipt['containerId']) is str and re.fullmatch('[0-9a-f]{64}', receipt['containerId'])
         and receipt['errorType'] is None and receipt['cleanupErrorType'] is None)
    terminal_state({'State': receipt['terminalState'], 'RestartCount': 0})


class Commands:
    """Bounded pipes; lifecycle ownership comes from the frozen maintained helper."""
    def __init__(self, lifecycle):
        self.lifecycle = lifecycle

    def run(self, argv, *, seconds=10, logs=None):
        began, counts, buffers, streams = time.monotonic(), [0, 0], [bytearray(), bytearray()], []
        status, process = 'passed', None
        try:
            if logs is not None:
                for path in logs:
                    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                    streams.append(os.fdopen(fd, 'wb'))
            process = subprocess.Popen(argv, env=ENV, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
            with selectors.DefaultSelector() as poll:
                for index, stream in enumerate((process.stdout, process.stderr)):
                    poll.register(stream, selectors.EVENT_READ, index)
                while poll.get_map():
                    remaining = seconds - (time.monotonic() - began)
                    if remaining <= 0:
                        status = 'timeout'
                        break
                    for key, _ in poll.select(min(remaining, .1)):
                        index = key.data
                        chunk = os.read(key.fd, min(8192, STREAM_LIMIT + 1 - counts[index]))
                        counts[index] += len(chunk)
                        if not chunk:
                            poll.unregister(key.fileobj)
                        elif streams:
                            streams[index].write(chunk)
                        else:
                            buffers[index].extend(chunk)
                    if max(counts) > STREAM_LIMIT:
                        status = 'output_limit'
                        break
                if status == 'passed':
                    while self.lifecycle.child_exit_status(process) is None:
                        if time.monotonic() - began >= seconds:
                            status = 'timeout'
                            break
                        time.sleep(.02)
        finally:
            try:
                if process is not None:
                    self.lifecycle.stop_group(process)
            finally:
                if process is not None:
                    process.stdout.close()
                    process.stderr.close()
                for stream in streams:
                    stream.flush()
                    os.fsync(stream.fileno())
                    stream.close()
        receipt = {'status': status, 'exitCode': process.returncode, 'bytes': counts,
            'seconds': round(time.monotonic() - began, 6)}
        return receipt, bytes(buffers[0])

    def docker(self, *args, seconds=10):
        result, output = self.run([*DOCKER, *args], seconds=seconds)
        need(result['status'] == 'passed' and result['exitCode'] == 0)
        return output.decode().strip()

    def inspect(self, identifier):
        value = json.loads(self.docker('inspect', identifier))
        need(type(value) is list and len(value) == 1 and type(value[0]) is dict)
        return value[0]

    def matching(self, selected):
        result = []
        for criterion in ('name=^/' + selected['name'] + '$', 'label=' + LABEL_KEY + '=' + LABEL):
            values = self.docker('ps', '-aq', '--no-trunc', '--filter', criterion).splitlines()
            need(all(re.fullmatch('[a-f0-9]{64}', value) for value in values))
            result.append(values)
        return result


def run_role(commands, selected, expected_env, preservation, proof, context):
    """No role dispatch loop: caller must separately authorize every next role."""
    role = selected['role']
    need(not any(commands.matching(selected)))
    claim = {**context, 'role': role, 'sourceProof': proof, 'automaticRetry': False}
    save(RECEIPTS / ('host-' + role + '.claim.json'), claim)
    identifier = run = terminal = limits = restarts = None
    ok = removed = unchanged = False
    error_type = cleanup_error = cleanup_state = None
    try:
        created, raw = commands.run(selected['createArgv'], seconds=15)
        # A create timeout is ambiguous. Never recover ownership by name or
        # delete a guessed container: preserve the claim for manual diagnosis.
        need(created['status'] == 'passed' and created['exitCode'] == 0)
        identifier = raw.decode().strip()
        need(re.fullmatch('[a-f0-9]{64}', identifier))
        actual = commands.inspect(identifier)
        identity(identifier, actual, selected)
        limits = isolation(actual, selected, expected_env)
        need(actual['State']['Status'] == 'created' and actual['State']['Running'] is False
             and actual['RestartCount'] == 0)
        run, _ = commands.run([*DOCKER, 'start', '--attach', identifier], seconds=85,
            logs=[RECEIPTS / ('host-' + role + suffix) for suffix in ('.stdout', '.stderr')])
        finished = commands.inspect(identifier)
        identity(identifier, finished, selected)
        isolation(finished, selected, expected_env)
        terminal, restarts = terminal_projection(finished), finished['RestartCount']
        terminal_state(finished)
        need(run['status'] == 'passed' and run['exitCode'] == 0)
        ok = True
    except BaseException as error:
        error_type = type(error).__name__
    finally:
        try:
            if identifier is not None and re.fullmatch('[a-f0-9]{64}', identifier):
                actual = commands.inspect(identifier)
                identity(identifier, actual, selected)
                isolation(actual, selected, expected_env)
                cleanup_state = {key: actual['State'].get(key) for key in (
                    'Status', 'Pid', 'Running', 'Paused', 'Restarting', 'Dead')}
                need(cleanup_state['Status'] in ('created', 'exited')
                     and type(cleanup_state['Pid']) is int and cleanup_state['Pid'] == 0
                     and all(cleanup_state[key] is False for key in ('Running', 'Paused', 'Restarting', 'Dead')))
                # A race to running is still safe: non-forced rm refuses it.
                # Never stop, kill, or force-remove an uncertain owned process.
                commands.docker('rm', identifier)
            removed = not any(commands.matching(selected))
        except BaseException as error:
            cleanup_error = type(error).__name__
        try:
            unchanged = preservation() == proof
        except BaseException as error:
            cleanup_error = cleanup_error or type(error).__name__
        receipt = {**context, 'schema': SCHEMA, 'role': role,
            'ok': ok and removed and unchanged and cleanup_error is None,
            'sourceProof': proof, 'containerId': identifier, 'containerRemoved': removed,
            'sourceAndCaptureUnchanged': unchanged, 'exitCode': run['exitCode'] if run else None,
            'oomKilled': terminal['OOMKilled'] if terminal else None, 'restartCount': restarts,
            'run': run, 'terminalState': terminal, 'activeLimits': limits,
            'errorType': error_type, 'cleanupErrorType': cleanup_error, 'cleanupState': cleanup_state,
            'liveAccess': False, 'databasePromoted': False, 'automaticRetry': False,
            'automaticRollback': False, 'automaticContinuation': False}
        save(RECEIPTS / (role + '.json'), receipt)
    need(receipt['ok'])
    return receipt


def main():
    need(__debug__ and sys.flags.isolated and sys.dont_write_bytecode
         and os.getuid() == os.geteuid() == 1000)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('role', choices=ROLES)
    parser.add_argument('--inputs-sha256', required=True)
    parser.add_argument('--helper-sha256', required=True)
    parser.add_argument('--execute-reviewed', action='store_true')
    args = parser.parse_args()
    need(args.execute_reviewed and ROOT.resolve(strict=True) == ROOT
         and stat.S_IMODE(ROOT.stat().st_mode) == 0o700 and ROOT.stat().st_uid == 1000
         and shutil.disk_usage(ROOT).free >= 16 * 1024**3 + 512 * 1024**2)
    os.umask(0o077)
    pinned(Path(__file__).resolve(), args.helper_sha256)
    cfg = json.loads(pinned(ROOT / 'inputs.json', args.inputs_sha256))
    need(type(cfg) is dict and cfg['schema'] == 'catchplate.sourceRevisionRetainedInputs/v1'
         and cfg['candidateCommit'] == COMMIT and cfg['normalBinarySha256'] == BINARY_SHA)
    # These two reviewed files are separate from the frozen application source.
    helpers = load('operator_source_revision_retained', RUNNER / 'operator_source_revision_retained.py',
        cfg['helpersSha256'])
    worker = load('source_revision_retained_worker', RUNNER / 'run_operator_source_revision_retained.py',
        cfg['workerSha256'])
    need(set(cfg) == worker.INPUT_KEYS and helpers.strict_json(pinned(ROOT / 'inputs.json', args.inputs_sha256)) == cfg)
    worker.validate_inputs(cfg)
    worker.cfg, worker.SOURCE_ROOT, worker.PROOFS = cfg, SOURCE, ROOT / 'proofs'
    helpers.cfg, helpers.SOURCE, helpers.PROOFS, helpers.CAPTURE = cfg, SOURCE, ROOT / 'proofs', CAPTURE
    need(worker.COMMIT == COMMIT and tuple(worker.ROLES) == ROLES and worker.IMAGE == IMAGE)
    # Host receipts are outside /job: even root preparation cannot rewrite them.
    if args.role == 'prepare':
        WORK.mkdir(mode=0o700)
        RECEIPTS.mkdir(mode=0o755)
        RECEIPTS.chmod(0o755)
    for directory, mode in ((WORK, 0o700), (RECEIPTS, 0o755)):
        need(directory.resolve(strict=True) == directory and directory.stat().st_uid == 1000
             and stat.S_IMODE(directory.stat().st_mode) == mode)
    lock = os.open(ROOT / '.host.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    environment_proof = None
    def preservation():
        pinned(Path(__file__).resolve(), args.helper_sha256)
        pinned(ROOT / 'inputs.json', args.inputs_sha256)
        pinned(RUNNER / 'operator_source_revision_retained.py', cfg['helpersSha256'])
        pinned(RUNNER / 'run_operator_source_revision_retained.py', cfg['workerSha256'])
        for name, digest in cfg['capturePins'].items():
            need(not name.startswith('/') and '..' not in Path(name).parts)
            pinned(CAPTURE / name, digest, 128 * 1024**2)
        proof = helpers.source_proof()
        helpers.archives()
        if environment_proof is not None:
            need(startup_environment(cfg) == environment_proof)
        return proof

    proof = preservation()
    environment_proof = startup_environment(cfg, create=args.role == 'prepare')
    previous = previous_receipt(args.role, args.inputs_sha256, args.helper_sha256, cfg, proof, environment_proof)
    files = json.loads(pinned(ROOT / 'proofs/source-files.json', cfg['sourceFilesSha256']))
    lifecycle = load('source_revision_retained_lifecycle', SOURCE / 'scripts/run_ordinary_regression.py',
        files['scripts/run_ordinary_regression.py']['sha256'])
    commands = Commands(lifecycle)
    image = json.loads(commands.docker('image', 'inspect', IMAGE))
    need(type(image) is list and len(image) == 1 and image[0]['Id'] == IMAGE)
    expected_env = expected_environment(image[0]['Config']['Env'], args.role, cfg)
    selected = plan(args.role, args.inputs_sha256)
    context = {'inputsSha256': args.inputs_sha256, 'helperSha256': args.helper_sha256,
        'workerSha256': cfg['workerSha256'], 'helpersSha256': cfg['helpersSha256'],
        'previousReceipt': previous, 'startupEnvironment': environment_proof}
    def interrupted(_signum, _frame):
        raise TimeoutError('bounded host interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    run_role(commands, selected, expected_env, preservation, proof, context)
    print(json.dumps({'role': args.role, 'ok': True, 'containerRemoved': True,
        'liveAccess': False, 'automaticContinuation': False}))


if __name__ == '__main__':
    try:
        main()
    except BaseException as error:
        print(json.dumps({'ok': False, 'errorType': type(error).__name__, 'automaticRetry': False}), file=sys.stderr)
        raise SystemExit(1) from None
