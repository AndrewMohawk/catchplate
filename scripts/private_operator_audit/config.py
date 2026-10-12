"""Fixed-destination, isolated Compose fixture; no live stack inheritance."""
from copy import deepcopy
import ipaddress
from pathlib import Path
import re

APP_IMAGE = 'sha256:ec14a558a42e483a834860521e399b461a2df880fcba495e7127b0d8d2a51e01'
FIXTURE_IMAGE = 'sha256:13fba0146806ccc218afd91dbc2c9087f5d8abdb16fc8c7acbe3c3448e79937d'
PYTHON_IMAGE = 'python@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea'
ORIGIN = 'https://serverware-demo.example.com'
INSTANCE = 'spiffe://operator-demo.serverware/decision-gate/local'
PREFIX = 'serverware-audit-private-'


def bind(source, target, readonly=True):
    return {'type': 'bind', 'source': str(source), 'target': target,
            'read_only': readonly, 'bind': {'create_host_path': False}}


def build(source: Path, binary: Path, runtime: Path, digest: str, project: str, subnet: str):
    if not re.fullmatch(PREFIX + r'[0-9a-f]{12}', project):
        raise ValueError('private fixture project name refused')
    if not re.fullmatch(r'[0-9a-f]{64}', digest):
        raise ValueError('exact executable SHA-256 required')
    network = ipaddress.ip_network(subnet, strict=True)
    if network.version != 4 or network.prefixlen != 28 or not network.subnet_of(ipaddress.ip_network('172.16.0.0/12')):
        raise ValueError('fixture requires a private IPv4 /28')
    addresses = {name: str(network.network_address + offset) for name, offset in (
        ('demo-upstream', 2), ('control-plane', 3), ('decision-gate-rs', 4), ('serverware', 6))}
    fixture_cidr = '["' + addresses['demo-upstream'] + '/32"]'
    common = {
        'image': PYTHON_IMAGE, 'pull_policy': 'never', 'restart': 'no',
        'user': '10001:10001', 'init': True, 'read_only': True,
        'cap_drop': ['ALL'], 'security_opt': ['no-new-privileges:true'],
        'pids_limit': 64, 'cpus': 0.5, 'mem_limit': '256m',
        'working_dir': '/app', 'dns': ['127.0.0.1'],
        'tmpfs': ['/tmp:rw,noexec,nosuid,nodev,size=32m,uid=10001,gid=10001,mode=0700'],
        'logging': {'driver': 'local', 'options': {'max-size': '2m', 'max-file': '2'}},
        'labels': {'traefik.enable': 'false', 'com.centurylinklabs.watchtower.enable': 'false'},
    }
    env = {
        'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONPATH': '/app',
        'SERVERWARE_OPERATOR_DEMO': '1', 'SERVERWARE_RELEASE_CHANNEL': 'dev',
        'SERVERWARE_OPERATOR_DEMO_UPSTREAMS': '["https://demo-upstream:8443"]',
        'SERVERWARE_OPERATOR_DEMO_FIXTURE_CIDRS': fixture_cidr,
        'SERVERWARE_OPERATOR_DEMO_PROXY_URL': 'https://serverware-proxy.example.com:443',
        'SERVERWARE_DATA_PLANE_INSTANCE_ID': INSTANCE,
    }
    services = {}
    for name in addresses:
        services[name] = {**deepcopy(common), 'networks': {'fixture': {'ipv4_address': addresses[name]}}}
    app = services['control-plane']
    app.update(image=APP_IMAGE, cpus=2, mem_limit='1g', pids_limit=128,
        command=['python', '-B', '-m', 'serverware.operator_demo_runner'])
    app['environment'] = {**env, 'SERVERWARE_DATA_DIR': '/data', 'PRIVATE_OPERATOR_AUDIT_FIXTURE': '1',
        'SERVERWARE_PUBLIC_URL': ORIGIN, 'SERVERWARE_DIRECT_CA_DOWNLOAD_ENABLED': '1',
        'SERVERWARE_ADMIN_USER': 'user:operator-demo-operator',
        'SERVERWARE_DATA_PLANE_LEASE_RECIPIENT_ATTESTATION_REQUIRED': '0',
        'SERVERWARE_DECISION_GATE_BASE': 'http://decision-gate-rs:9091',
        'SERVERWARE_EXPECTED_DATA_PLANE_BINARY_DIGEST': 'sha256:' + digest}
    for role in ('admin', 'credential-lease', 'audit', 'grant-consume', 'rate-limit-consume', 'release-authorization', 'management'):
        key = 'SERVERWARE_' + ('ADMIN' if role == 'admin' else 'DATA_PLANE_' + role.upper().replace('-', '_')) + '_TOKEN_FILE'
        app['environment'][key] = '/run/secrets/serverware/' + role + '.token'
    app['volumes'] = [bind(source, '/app'), bind(runtime / 'app-data', '/data', False),
        bind(runtime / 'service-secrets', '/run/secrets/serverware'),
        bind(runtime / 'upstream-data/demo-upstream', '/demo-upstream'),
        bind(runtime / '.private-fixture.json', '/private-audit-fixture.json')]
    app['depends_on'] = {'demo-upstream': {'condition': 'service_healthy'}}
    app['healthcheck'] = {'test': ['CMD', 'python', '-c', "import json,urllib.request; o=urllib.request.build_opener(urllib.request.ProxyHandler({})); r=o.open('http://127.0.0.1:3000/healthz',timeout=2); raise SystemExit(0 if r.status==200 and json.load(r).get('ok') is True else 1)"],
        'interval': '3s', 'timeout': '3s', 'retries': 20, 'start_period': '30s'}
    upstream = services['demo-upstream']
    upstream.update(image=FIXTURE_IMAGE, command=['python', '-B', 'scripts/demo_upstream.py'],
        environment={'PYTHONDONTWRITEBYTECODE': '1'},
        volumes=[bind(source, '/app'), bind(runtime / 'upstream-data', '/data', False)])
    upstream['healthcheck'] = {'test': ['CMD', 'python', '-c', "import ssl,urllib.request; c=ssl.create_default_context(cafile='/data/demo-upstream/ca.pem'); o=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=c)); r=o.open('https://demo-upstream:8443/_test/request-count?method=GET&path=%2Fecho',timeout=2); raise SystemExit(0 if r.status==200 else 1)"],
        'interval': '3s', 'timeout': '3s', 'retries': 10, 'start_period': '10s'}
    relay = services['serverware']
    relay.update(command=['python', '-B', 'scripts/private_operator_audit/relay.py'],
        environment={'PYTHONDONTWRITEBYTECODE': '1'},
        volumes=[bind(source, '/app'), bind(runtime / 'service-secrets/fixture-control.token', '/fixture-control.token')],
        depends_on={'control-plane': {'condition': 'service_healthy'}})
    relay['healthcheck'] = {'test': ['CMD', 'python', '-c', "import urllib.request; o=urllib.request.build_opener(urllib.request.ProxyHandler({})); r=o.open('http://127.0.0.1:3000/__fixture/health',timeout=2); raise SystemExit(0 if r.status==200 else 1)"],
        'interval': '3s', 'timeout': '3s', 'retries': 10}
    gate = services['decision-gate-rs']
    gate.update(entrypoint=['/usr/local/bin/serverware-decision-gate'], command=[],
        cpus=1, mem_limit='512m', pids_limit=128,
        depends_on={'serverware': {'condition': 'service_healthy'}})
    gate['environment'] = {**env,
        'SERVERWARE_ALLOW_INSECURE_DEV_CREDENTIAL_LEASES': '1',
        'SERVERWARE_ATOMIC_RELEASE_AUTHORIZATION_ENABLED': '0',
        'SERVERWARE_POLICY_BUNDLE': '/data/policy-bundle.json',
        'SERVERWARE_POLICY_HIGH_WATER_FILE': '/gate-data/policy-high-water.json',
        'SERVERWARE_POLICY_TRUST_ROOT_ATTESTATION_URL': 'http://serverware:3000/attestation',
        'SERVERWARE_CONTROL_PLANE_CREDENTIAL_LEASE_URL': 'http://serverware:3000/api/data-plane/credential-leases',
        'SERVERWARE_CONTROL_PLANE_AUDIT_URL': 'http://serverware:3000/api/data-plane/audit',
        'SERVERWARE_DATA_PLANE_AUDIT_BATCH_MAX': '16', 'SERVERWARE_DATA_PLANE_AUDIT_QUEUE_MAX': '256',
        'SERVERWARE_DATA_PLANE_AUDIT_FLUSH_MS': '500',
        'SERVERWARE_UPSTREAM_CA_BUNDLE': '/demo-upstream/ca.pem',
        'SERVERWARE_MITM_CA_CERT': '/data/mitmproxy/mitmproxy-ca-cert.pem',
        'SERVERWARE_MITM_CA_KEY': '/data/mitmproxy/mitmproxy-ca.pem',
        'SERVERWARE_PROXY_INGRESS_MODE': 'operator-demo-tls-edge',
        'SERVERWARE_DECISION_GATE_HOST': '0.0.0.0', 'SERVERWARE_DECISION_GATE_PORT': '9090',
        'SERVERWARE_DECISION_GATE_MANAGEMENT_HOST': addresses['decision-gate-rs'],
        'SERVERWARE_DECISION_GATE_MANAGEMENT_PORT': '9091'}
    gate['volumes'] = [bind(binary, '/usr/local/bin/serverware-decision-gate'),
        bind(runtime / 'app-data', '/data'), bind(runtime / 'gate-data', '/gate-data', False),
        bind(runtime / 'upstream-data/demo-upstream', '/demo-upstream')]
    for role in ('credential-lease', 'audit', 'management'):
        key = 'SERVERWARE_DATA_PLANE_' + role.upper().replace('-', '_') + '_TOKEN_FILE'
        target = '/run/secrets/serverware/' + role + '.token'
        gate['environment'][key] = target
        gate['volumes'].append(bind(runtime / 'service-secrets' / (role + '.token'), target))
    gate['healthcheck'] = {'test': ['CMD', 'python', '-c', "import json,urllib.request; o=urllib.request.build_opener(urllib.request.ProxyHandler({})); r=o.open('http://" + addresses['decision-gate-rs'] + ":9091/healthz',timeout=2); raise SystemExit(0 if r.status==200 and json.load(r).get('ok') is True else 1)"],
        'interval': '3s', 'timeout': '3s', 'retries': 20, 'start_period': '20s'}
    services['initialize'] = {**deepcopy(common), 'profiles': ['prepare'], 'user': '0:0',
        'network_mode': 'none', 'cap_add': ['CHOWN', 'DAC_OVERRIDE'], 'cpus': 0.25,
        'mem_limit': '64m', 'pids_limit': 16, 'working_dir': '/',
        'command': ['python', '-B', '/initialize.py'],
        'volumes': [bind(source / 'scripts/private_operator_audit/initialize.py', '/initialize.py'),
            bind(runtime, '/fixture-runtime', False)]}
    config = {'name': project, 'services': services,
        'networks': {'fixture': {'internal': True, 'ipam': {'config': [{'subnet': subnet}]}}}}
    validate(config, source, binary, runtime)
    return config


def validate(config, source, binary, runtime):
    if set(config['services']) != {'initialize', 'control-plane', 'demo-upstream', 'serverware', 'decision-gate-rs'}:
        raise ValueError('unexpected private fixture service')
    if set(config['networks']) != {'fixture'} or config['networks']['fixture'].get('internal') is not True:
        raise ValueError('private network boundary missing')
    if config['networks']['fixture'].get('external'):
        raise ValueError('external network refused')
    roots = (source, runtime)
    for name, service in config['services'].items():
        if any(service.get(key) for key in ('ports', 'privileged', 'devices', 'pid', 'ipc', 'extra_hosts', 'volumes_from')):
            raise ValueError('host exposure refused')
        if service.get('labels', {}).get('traefik.enable') != 'false':
            raise ValueError('ingress refused')
        if service.get('pull_policy') != 'never' or not service.get('read_only') or service.get('cap_drop') != ['ALL']:
            raise ValueError('container guard missing')
        if (service.get('security_opt') != ['no-new-privileges:true'] or service.get('restart') != 'no'
                or not 1 <= service.get('pids_limit', 0) <= 128
                or not 0 < service.get('cpus', 0) <= 2
                or service.get('mem_limit') not in ('64m', '256m', '512m', '1g')):
            raise ValueError('container resource/security limit missing')
        if name == 'initialize':
            if (service.get('network_mode') != 'none' or service.get('profiles') != ['prepare']
                    or service.get('user') != '0:0' or service.get('cap_add') != ['CHOWN', 'DAC_OVERRIDE']):
                raise ValueError('initializer boundary missing')
        elif (set(service.get('networks', {})) != {'fixture'} or service.get('network_mode')
                or service.get('user') != '10001:10001' or service.get('cap_add')):
            raise ValueError('service network/privilege boundary missing')
        for volume in service['volumes']:
            if volume.get('type') != 'bind' or volume.get('bind', {}).get('create_host_path') is not False:
                raise ValueError('implicit mount creation refused')
            path = Path(volume['source'])
            if path != binary and not any(path == root or root in path.parents for root in roots):
                raise ValueError('mount outside selected source/binary/new runtime')
            if not volume.get('read_only') and not (path == runtime or runtime in path.parents):
                raise ValueError('writable source or executable refused')
