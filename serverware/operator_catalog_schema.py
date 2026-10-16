"""Metadata-only operator catalog migration; encrypted secrets stay in db.credentials.

Migration is transactional and never republishes policy, rotates a token, or
rewrites legacy rows. Legacy connection/receipt tables become retained history.
"""
from __future__ import annotations

from datetime import datetime
import json
import re
from urllib.parse import urlsplit
import uuid

_SHA = re.compile(r'sha256:[0-9a-f]{64}\Z')
_TABLES = {
    'credentials': 'operator_catalog_credentials',
    'applications': 'operator_catalog_applications',
    'access_rules': 'operator_catalog_rules',
}


class CatalogConflict(Exception):
    """The reviewed catalog or resource no longer matches."""


class CatalogIntegrityError(Exception):
    """Retained catalog, policy, or credential binding is inconsistent."""


class LegacyCatalogWriteBlocked(Exception):
    """A combined legacy action cannot mutate the separated catalog."""


def _require():
    from serverware.operator_demo_store import _require as admitted_store
    return admitted_store()


def _transaction(conn):
    if getattr(conn, 'in_transaction', False) is not True:
        raise CatalogIntegrityError('catalog mutation requires an existing transaction')


def active(conn=None) -> bool:
    if conn is None:
        with _require().connect() as connection:
            return active(connection)
    exists = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='operator_catalog_state'").fetchone()
    if exists is None:
        return False
    rows = conn.execute('SELECT singleton,schema_version,revision FROM operator_catalog_state').fetchall()
    if not rows:
        return False
    if len(rows) != 1 or rows[0]['singleton'] != 1 or rows[0]['schema_version'] != 1 or type(rows[0]['revision']) is not int or rows[0]['revision'] < 1:
        raise CatalogIntegrityError('catalog schema or revision refused')
    return True


def _records(conn, collection):
    table = _TABLES[collection]
    records = []
    for row in conn.execute('SELECT * FROM ' + table + ' ORDER BY ordinal,id'):
        try:
            data = json.loads(row['data_json'])
            columns = {key: row[key] for key in row.keys() if key != 'data_json'}
            if not isinstance(data, dict) or set(data) & set(columns):
                raise ValueError('catalog metadata overlaps columns')
            records.append({**columns, **data})
        except (TypeError, ValueError, KeyError) as error:
            raise CatalogIntegrityError('catalog metadata refused') from error
    return records


def read_catalog(conn) -> dict:
    if not active(conn):
        raise CatalogIntegrityError('catalog is not initialized')
    revision = conn.execute('SELECT revision FROM operator_catalog_state WHERE singleton=1').fetchone()[0]
    return {'revision': revision, **{collection: _records(conn, collection) for collection in _TABLES}}


def require_revision(conn, expected: int) -> None:
    if type(expected) is not int or expected < 1 or not active(conn):
        raise CatalogConflict()
    actual = conn.execute('SELECT revision FROM operator_catalog_state WHERE singleton=1').fetchone()[0]
    if actual != expected:
        raise CatalogConflict()


def advance_revision(conn, expected: int) -> int:
    _transaction(conn)
    require_revision(conn, expected)
    changed = conn.execute('UPDATE operator_catalog_state SET revision=revision+1 WHERE singleton=1 AND revision=?', (expected,)).rowcount
    if changed != 1:
        raise CatalogConflict()
    return expected + 1


def _legacy_reserved(conn, collection: str) -> set[str]:
    if collection not in _TABLES:
        raise CatalogIntegrityError('catalog collection refused')
    exists = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='operator_demo_revocations'").fetchone()
    if exists is None:
        return set()
    rows = conn.execute('SELECT connection_id,receipt_json FROM operator_demo_revocations ORDER BY rowid LIMIT 1025').fetchall()
    if len(rows) > 1024:
        raise CatalogIntegrityError('legacy revocation retention exceeds bound')
    values = set()
    field = 'credential_id' if collection == 'credentials' else 'connection_id'
    for row in rows:
        try:
            receipt = json.loads(row['receipt_json'])
            if (not isinstance(receipt, dict) or receipt['connection_id'] != row['connection_id']
                    or receipt['principal_id'] != 'agent:operator-demo:' + receipt['connection_id']):
                raise ValueError('legacy revocation identity drift')
            for key in ('credential_id', 'connection_id'):
                if str(uuid.UUID(receipt[key])) != receipt[key]:
                    raise ValueError('legacy revocation identifier refused')
            value = receipt[field]
            if value in values:
                raise ValueError('legacy revocation identity reused')
            values.add(value)
        except (KeyError, TypeError, ValueError, AttributeError) as error:
            raise CatalogIntegrityError('legacy revocation reservation refused') from error
    return values


def reserved_identifiers(conn, collection: str) -> set[str]:
    """IDs retained in pre-catalog receipts still consume identity/lifetime slots."""
    values = _legacy_reserved(conn, collection)
    if collection not in _TABLES:
        raise CatalogIntegrityError('catalog collection refused')
    present = {row[0] for row in conn.execute('SELECT id FROM ' + _TABLES[collection])}
    if values & present:
        raise CatalogIntegrityError('catalog reused a legacy revoked identifier')
    return values


def retained_legacy_count(conn, collection: str) -> int:
    return len(reserved_identifiers(conn, collection))


def save_resource(conn, collection: str, record: dict, create: bool = False) -> dict:
    """Store a complete internal record; never a partial patch or secret value."""
    _transaction(conn)
    if collection not in _TABLES or not isinstance(record, dict):
        raise CatalogIntegrityError('catalog collection refused')
    if any(key in record for key in ('secret', 'client_token', 'encrypted_secret', 'encrypted_dek', 'secret_ciphertext')):
        raise CatalogIntegrityError('secret material is not catalog metadata')
    table = _TABLES[collection]
    value = dict(record)
    identifier = value.get('id')
    try:
        if not isinstance(identifier, str) or str(uuid.UUID(identifier)) != identifier:
            raise ValueError('noncanonical ID')
    except (ValueError, TypeError, AttributeError) as error:
        raise CatalogIntegrityError('catalog identifier refused') from error
    existing = conn.execute('SELECT ordinal,data_json FROM ' + table + ' WHERE id=?', (identifier,)).fetchone()
    if create:
        if existing is not None or identifier in _legacy_reserved(conn, collection):
            raise CatalogConflict()
        value.setdefault('ordinal', conn.execute('SELECT COALESCE(MAX(ordinal),0)+1 FROM ' + table).fetchone()[0])
        value['version'] = 1
    else:
        if existing is None:
            raise CatalogConflict()
        value.setdefault('ordinal', existing['ordinal'])
        if value['ordinal'] != existing['ordinal']:
            raise CatalogIntegrityError('catalog resource ordering changed')
        previous = json.loads(existing['data_json'])
        if type(previous.get('version')) is not int or previous['version'] < 1:
            raise CatalogIntegrityError('catalog resource version refused')
        value['version'] = previous['version'] + 1
    if type(value['ordinal']) is not int or value['ordinal'] < 1:
        raise CatalogIntegrityError('catalog ordering refused')
    columns = ['id', 'ordinal']
    if collection == 'access_rules':
        columns += ['application_id', 'credential_id']
    if any(key not in value for key in columns):
        raise CatalogIntegrityError('catalog binding is missing')
    data = {key: item for key, item in value.items() if key not in columns}
    raw = json.dumps(data, sort_keys=True, separators=(',', ':'), allow_nan=False)
    if len(raw.encode()) > 32768:
        raise CatalogIntegrityError('catalog resource exceeds metadata bound')
    if create:
        conn.execute('INSERT INTO ' + table + ' (' + ','.join(columns) + ',data_json) VALUES ('
            + ','.join('?' for _ in columns) + ',?)', (*[value[key] for key in columns], raw))
    else:
        mutable = [key for key in columns if key != 'id']
        if conn.execute('UPDATE ' + table + ' SET ' + ','.join(key + '=?' for key in mutable)
                + ',data_json=? WHERE id=?', (*[value[key] for key in mutable], raw, identifier)).rowcount != 1:
            raise CatalogConflict()
    return value


def rule_credential_header(rule: dict, credential: dict) -> dict | None:
    """Translate public per-rule input without opening the encrypted credential."""
    from serverware import operator_catalog_ecr
    if operator_catalog_ecr.selected(rule):
        operator_catalog_ecr.validate_rule(rule, credential)
        return None
    from serverware import operator_catalog_aws
    if operator_catalog_aws.selected(credential):
        raise CatalogIntegrityError('AWS credentials have no access-rule signing profile')
    from serverware import operator_catalog_x_oauth, operator_catalog_x_post
    if operator_catalog_x_oauth.selected(credential):
        operator_catalog_x_post.validate_rule(rule, credential)
    mode = rule.get('credential_input', 'insert')
    if mode == 'insert':
        if 'placeholder' in rule:
            raise CatalogIntegrityError('insertion rule retains a placeholder')
        return None
    if mode != 'replace_exact':
        raise CatalogIntegrityError('catalog credential input mode refused')
    if credential.get('auth_type') not in {'bearer', 'header', 'google_oauth', 'x_oauth'}:
        raise CatalogIntegrityError('catalog replacement credential type refused')
    from serverware.policy_bundle import PolicyBundleError, validate_credential_header_replacement
    injection = {'type': 'bearer', 'header': 'Authorization'} if credential.get('auth_type') in {'bearer', 'google_oauth', 'x_oauth'} else {
        'type': 'header', 'name': credential.get('header_name'), 'prefix': ''}
    try:
        return validate_credential_header_replacement(
            {'mode': 'replaceExact', 'expectedValue': rule.get('placeholder')}, injection)
    except PolicyBundleError as error:
        raise CatalogIntegrityError('catalog credential placeholder or target refused') from error


def rule_content_modes(rule: dict) -> tuple[str | None, str]:
    """Validate additive modes without defaulting retained records into them."""
    from serverware import operator_catalog_ecr
    if operator_catalog_ecr.selected(rule):
        operator_catalog_ecr.validate_shape(rule)
        return None, operator_catalog_ecr.RESPONSE_MODE
    from serverware import operator_catalog_x_post
    if operator_catalog_x_post.selected(rule):
        operator_catalog_x_post.validate_shape(rule)
        return None, operator_catalog_x_post.RESPONSE_MODE
    from serverware import operator_catalog_npm_install
    if operator_catalog_npm_install.selected(rule):
        operator_catalog_npm_install.validate_shape(rule)
        return None, operator_catalog_npm_install.RESPONSE_MODE
    from serverware import operator_catalog_github, operator_catalog_gmail, operator_catalog_npm, operator_catalog_npm_publish, operator_catalog_x, operator_catalog_alchemy
    if operator_catalog_alchemy.selected(rule):
        operator_catalog_alchemy.validate_shape(rule)
        return None, operator_catalog_alchemy.RESPONSE_MODE
    if operator_catalog_x.selected(rule):
        operator_catalog_x.validate_shape(rule)
        return None, operator_catalog_x.RESPONSE_MODE
    if operator_catalog_npm_publish.selected(rule):
        operator_catalog_npm_publish.validate_shape(rule)
        return None, operator_catalog_npm_publish.RESPONSE_MODE
    if operator_catalog_npm.selected(rule):
        operator_catalog_npm.validate_shape(rule)
        return None, operator_catalog_npm.RESPONSE_MODE
    if operator_catalog_github.selected(rule):
        operator_catalog_github.validate_shape(rule)
        return 'preserve_json_v1', operator_catalog_github.RESPONSE_MODE
    if operator_catalog_gmail.selected(rule):
        operator_catalog_gmail.validate_shape(rule)
        return None, operator_catalog_gmail.RESPONSE_MODE
    request_mode = rule.get('request_body_mode')
    request_fields = rule.get('request_fields')
    response_mode = rule.get('response_mode', 'projected_json')
    response_fields = rule.get('response_fields')
    if not isinstance(request_fields, list):
        raise CatalogIntegrityError('catalog request fields refused')
    if 'request_body_mode' in rule and (request_mode != 'preserve_json_v1' or request_fields):
        raise CatalogIntegrityError('catalog request preservation mode/fields refused')
    if (not isinstance(response_mode, str)
            or response_mode not in {'projected_json', 'unfiltered_json', 'unfiltered_json_or_empty_v1',
                'unfiltered_json_or_empty_v2'}
            or not isinstance(response_fields, list)
            or (response_mode == 'projected_json') != bool(response_fields)):
        raise CatalogIntegrityError('catalog response mode/fields refused')
    return request_mode, response_mode


def rule_request_body_mode(rule: dict, credential: dict) -> str | None:
    """Google's existing exact GET/no-body contract is not widened by this mode."""
    from serverware import operator_catalog_ecr
    if operator_catalog_ecr.selected(rule):
        operator_catalog_ecr.validate_rule(rule, credential)
        return None
    from serverware import operator_common_apps
    if operator_common_apps.selected(rule) or operator_common_apps.selected(credential):
        operator_common_apps.validate_rule(rule, credential)
        return None
    from serverware import operator_catalog_aws
    if operator_catalog_aws.selected(credential):
        raise CatalogIntegrityError('AWS credentials have no access-rule signing profile')
    from serverware import operator_catalog_x_oauth, operator_catalog_x_post
    if operator_catalog_x_post.selected(rule) or operator_catalog_x_oauth.selected(credential):
        operator_catalog_x_post.validate_rule(rule, credential)
        return None
    request_mode, _ = rule_content_modes(rule)
    from serverware import operator_catalog_npm_install
    if operator_catalog_npm_install.selected(rule):
        operator_catalog_npm_install.validate_rule(rule, credential)
        return None
    from serverware import operator_catalog_github, operator_catalog_npm, operator_catalog_npm_publish, operator_catalog_x, operator_catalog_alchemy
    if operator_catalog_alchemy.selected(rule):
        operator_catalog_alchemy.validate_rule(rule, credential)
        return None
    if operator_catalog_x.selected(rule):
        operator_catalog_x.validate_rule(rule, credential)
        return None
    if operator_catalog_npm_publish.selected(rule):
        operator_catalog_npm_publish.validate_rule(rule, credential)
        return None
    if operator_catalog_npm.selected(rule):
        operator_catalog_npm.validate_rule(rule, credential)
        return None
    if operator_catalog_github.selected(rule):
        operator_catalog_github.validate_rule(rule, credential)
        return request_mode
    if validate_static_connection(credential):
        raise CatalogIntegrityError('provider token connections require their explicit preset')
    if 'operation_bundle' in rule and credential.get('auth_type') != 'google_oauth':
        raise CatalogIntegrityError('Gmail bundle requires a connected Google account')
    if request_mode is not None and credential.get('auth_type') == 'google_oauth':
        raise CatalogIntegrityError('Google account request preservation is unsupported')
    return request_mode


def validate_static_connection(record: dict, metadata: dict | None = None) -> bool:
    """Closed dispatch keeps generic credentials unmarked and retained unchanged."""
    from serverware import operator_common_apps
    if operator_common_apps.selected(record) or (type(metadata) is dict and "app_preset" in metadata):
        return operator_common_apps.validate_credential(record, metadata)
    from serverware import operator_catalog_x_oauth
    if operator_catalog_x_oauth.selected(record) or (type(metadata) is dict
            and operator_catalog_x_oauth.MARKER in metadata):
        operator_catalog_x_oauth.validate_identity(record)
        if metadata is not None:
            operator_catalog_x_oauth.validate_account_metadata(metadata)
        return True
    from serverware import github_app_boundary, operator_github_app
    if (github_app_boundary.selected(record.get('auth_type'), record)
            or github_app_boundary.selected(None, metadata)):
        return operator_github_app.validate_credential(record, metadata)
    from serverware import operator_catalog_github, operator_catalog_npm, operator_catalog_x, operator_catalog_alchemy
    from serverware import operator_catalog_aws, aws_credential_boundary
    if operator_catalog_aws.selected(record) or aws_credential_boundary.selected(None, metadata):
        return operator_catalog_aws.validate_credential(record, metadata)
    if record.get('connection_type') == operator_catalog_alchemy.CONNECTION:
        return operator_catalog_alchemy.validate_credential(record, metadata)
    if record.get('connection_type') == operator_catalog_x.CONNECTION:
        return operator_catalog_x.validate_credential(record, metadata)
    if record.get('connection_type') == operator_catalog_npm.CONNECTION:
        return operator_catalog_npm.validate_credential(record, metadata)
    return operator_catalog_github.validate_credential(record, metadata)


def application_proxy_authentication(application: dict) -> str:
    """Absent retained metadata stays Bearer without rewriting the record."""
    mode = application.get('proxy_authentication', 'bearer')
    if not isinstance(mode, str) or mode not in {'bearer', 'basic_and_bearer_v1'}:
        raise CatalogIntegrityError('catalog application proxy authentication refused')
    if mode == 'basic_and_bearer_v1':
        identifier = application.get('id')
        try:
            if not isinstance(identifier, str) or str(uuid.UUID(identifier)) != identifier:
                raise ValueError('noncanonical application identifier')
        except (ValueError, TypeError, AttributeError) as error:
            raise CatalogIntegrityError('catalog Basic username binding refused') from error
        expiry = application.get('token_expires_at_epoch_ms')
        if type(expiry) is not int or not 1 <= expiry <= 9_007_199_254_740_991:
            raise CatalogIntegrityError('catalog Basic token expiry refused')
    return mode


def validate_bindings(conn, catalog: dict | None = None, *, metadata_profile=None) -> None:
    from serverware import operator_catalog_google
    operator_catalog_google.validate_profile_binding(conn, metadata_profile=metadata_profile)
    catalog = read_catalog(conn) if catalog is None else catalog
    credentials = {row['id']: row for row in catalog['credentials']}
    applications = {row['id']: row for row in catalog['applications']}
    from serverware import operator_catalog_x_oauth
    x_configuration = None
    if any(operator_catalog_x_oauth.selected(row) for row in credentials.values()):
        from serverware import operator_x_configuration
        x_configuration = operator_x_configuration.retained_public_binding(conn)
        if x_configuration is None:
            raise CatalogIntegrityError('retained X account configuration unavailable')
    for collection in _TABLES:
        reserved_identifiers(conn, collection)
        rows = catalog[collection]
        if len({row['id'] for row in rows}) != len(rows) or len({row['ordinal'] for row in rows}) != len(rows):
            raise CatalogIntegrityError('catalog identity/order collision')
        for row in rows:
            statuses = {'active', 'revoked'}
            if collection == 'credentials' and row.get('auth_type') == 'google_oauth':
                statuses = {'active', 'quarantined'}
            if collection == 'credentials' and operator_catalog_x_oauth.selected(row):
                statuses = {'active', 'quarantined', 'revoked'}
            if (row.get('status') not in statuses or not isinstance(row.get('name'), str) or not row['name']
                    or type(row.get('version')) is not int or row['version'] < 1):
                raise CatalogIntegrityError('catalog resource state refused')
    for identifier, row in credentials.items():
        validate_static_connection(row)
        x_account = operator_catalog_x_oauth.selected(row)
        if x_account:
            operator_catalog_x_oauth.validate_configuration_binding(row, x_configuration)
        core = conn.execute('SELECT id,name,kind,metadata,lifecycle_status FROM credentials WHERE id=?', (identifier,)).fetchone()
        if 'key_replaced_at' in row:
            try:
                stamp = row['key_replaced_at']
                if (row.get('auth_type') not in {'bearer', 'header', 'aws_sigv4_v1'} or not isinstance(stamp, str)
                        or not 1 <= len(stamp) <= 64 or not stamp.isascii()
                        or any(ord(char) < 32 or ord(char) == 127 for char in stamp)
                        or datetime.fromisoformat(stamp).tzinfo is None):
                    raise ValueError('replacement timestamp refused')
            except (TypeError, ValueError) as error:
                raise CatalogIntegrityError('static replacement metadata refused') from error
        if row['status'] == 'revoked':
            if core is not None:
                raise CatalogIntegrityError('revoked catalog credential retains a secret row')
            continue
        if row.get('auth_type') == 'google_oauth':
            from serverware import operator_catalog_google
            if row['status'] == 'quarantined':
                operator_catalog_google.validate_quarantined_record(row, core, profile=metadata_profile)
            else:
                operator_catalog_google.validate_record(row, core, profile=metadata_profile)
            continue
        if x_account:
            if row['status'] == 'quarantined':
                operator_catalog_x_oauth.validate_quarantined_record(row, core)
            else:
                operator_catalog_x_oauth.validate_record(row, core)
            continue
        bearer = row.get('auth_type') == 'bearer'
        try:
            metadata = json.loads(core['metadata']) if core is not None else None
        except (ValueError, TypeError) as error:
            raise CatalogIntegrityError('active credential metadata refused') from error
        from serverware import operator_catalog_aws, aws_credential_boundary
        if (operator_catalog_aws.selected(row) or core is not None
                and aws_credential_boundary.selected(core['kind'], metadata)):
            if type(metadata) is not dict:
                raise CatalogIntegrityError('active AWS credential metadata refused')
            operator_catalog_aws.validate_credential(row, metadata)
            if (core is None or core['kind'] != operator_catalog_aws.KIND
                    or core['name'] != row['name'] or core['lifecycle_status'] != 'active'):
                raise CatalogIntegrityError('active AWS credential binding refused')
            continue
        if (row.get('auth_type') not in {'bearer', 'header'} or core is None
                or core['name'] != row['name'] or core['kind'] != ('bearer' if bearer else 'header')
                or core['lifecycle_status'] != 'active' or not isinstance(metadata, dict)
                or metadata.get('provider_id') != 'operator-demo'
                or metadata.get('provider_subject') != row.get('provider_subject')
                or not isinstance(row.get('provider_subject'), str) or not row['provider_subject']
                or metadata.get('secret_class') != ('bearerToken' if bearer else 'customHeader')
                or metadata.get('oauth') is True):
            raise CatalogIntegrityError('active catalog credential binding refused')
        validate_static_connection(row, metadata)
    for identifier, row in applications.items():
        application_proxy_authentication(row)
        if (row.get('principal_id') != 'agent:operator-demo:' + identifier
                or not isinstance(row.get('token_sha256'), str) or not _SHA.fullmatch(row['token_sha256'])
                or type(row.get('token_expires_at_epoch_ms')) is not int or row['token_expires_at_epoch_ms'] <= 0):
            raise CatalogIntegrityError('catalog application verifier refused')
        from serverware import operator_workload_renewal_store
        operator_workload_renewal_store.validate(row)
    for row in catalog['access_rules']:
        from serverware import operator_catalog_approvals
        operator_catalog_approvals.validate(row)
        rule_content_modes(row)
        app, credential = applications.get(row['application_id']), credentials.get(row['credential_id'])
        if app is None or credential is None or row.get('route_id') != 'operator.' + row['id']:
            raise CatalogIntegrityError('catalog rule binding refused')
        rule_credential_header(row, credential)
        rule_request_body_mode(row, credential)
        if row['status'] == 'active' and credential.get('auth_type') == 'google_oauth':
            from serverware import operator_catalog_google
            operator_catalog_google.validate_rule(row, credential, profile=metadata_profile)
        if row['status'] == 'active' and (app['status'] != 'active' or credential['status'] != 'active'):
            raise CatalogIntegrityError('active rule has an inactive parent')
    from serverware import operator_catalog_npm_publish, operator_catalog_x, operator_catalog_alchemy
    operator_catalog_npm_publish.validate_route_coexistence(catalog['access_rules'])
    from serverware import operator_catalog_npm_install
    operator_catalog_npm_install.validate_route_coexistence(catalog['access_rules'])
    operator_catalog_x.validate_route_coexistence(catalog['access_rules'])
    operator_catalog_alchemy.validate_route_coexistence(catalog['access_rules'])
    from serverware import operator_catalog_x_post
    operator_catalog_x_post.validate_route_coexistence(catalog['access_rules'], catalog['credentials'])
    from serverware import operator_catalog_ecr
    operator_catalog_ecr.validate_route_coexistence(catalog['access_rules'])


def initialize(conn) -> None:
    """Upgrade only catalog metadata inside the admitted bootstrap transaction."""
    _transaction(conn)
    from serverware import operator_catalog_google
    operator_catalog_google.initialize_profile(conn)
    if active(conn):
        validate_bindings(conn)
        return
    for statement in (
        'CREATE TABLE IF NOT EXISTS operator_catalog_state (singleton INTEGER PRIMARY KEY CHECK(singleton=1), schema_version INTEGER NOT NULL CHECK(schema_version=1), revision INTEGER NOT NULL CHECK(revision>=1))',
        'CREATE TABLE IF NOT EXISTS operator_catalog_credentials (id TEXT PRIMARY KEY, ordinal INTEGER NOT NULL UNIQUE CHECK(ordinal>0), data_json TEXT NOT NULL)',
        'CREATE TABLE IF NOT EXISTS operator_catalog_applications (id TEXT PRIMARY KEY, ordinal INTEGER NOT NULL UNIQUE CHECK(ordinal>0), data_json TEXT NOT NULL)',
        'CREATE TABLE IF NOT EXISTS operator_catalog_rules (id TEXT PRIMARY KEY, application_id TEXT NOT NULL REFERENCES operator_catalog_applications(id), credential_id TEXT NOT NULL REFERENCES operator_catalog_credentials(id), ordinal INTEGER NOT NULL UNIQUE CHECK(ordinal>0), data_json TEXT NOT NULL)',
    ):
        conn.execute(statement)
    if any(conn.execute('SELECT 1 FROM ' + table + ' LIMIT 1').fetchone() is not None for table in _TABLES.values()):
        raise CatalogIntegrityError('unmarked partial catalog refused')
    legacy = conn.execute('SELECT rowid AS ordinal,id,metadata_json FROM operator_demo_connections ORDER BY rowid').fetchall()
    for old in legacy:
        try:
            row = json.loads(old['metadata_json'])
            if row['id'] != old['id'] or row['principal_id'] != 'agent:operator-demo:' + old['id']:
                raise ValueError('legacy ID drift')
            target = urlsplit(row['upstream_url'])
            origin = target.scheme + '://' + target.netloc
            credential = {'id': row['credential_id'], 'ordinal': old['ordinal'], 'name': row['name'],
                'auth_type': row['auth_type'], 'header_name': row['header_name'], 'provider_subject': row['id'],
                'created_at': row['created_at'], 'status': 'active', 'legacy_upstream_origin': origin}
            application = {'id': row['id'], 'ordinal': old['ordinal'], 'name': row['name'],
                'principal_id': row['principal_id'], 'token_sha256': row['token_sha256'],
                'token_expires_at_epoch_ms': row['token_expires_at_epoch_ms'], 'token_version': 1,
                'created_at': row['created_at'], 'status': 'active'}
            rule = {key: row[key] for key in ('id', 'name', 'upstream_url', 'methods', 'request_fields',
                'response_fields', 'query_keys', 'allowed_headers', 'created_at')}
            rule.update(ordinal=old['ordinal'], application_id=row['id'], credential_id=row['credential_id'],
                route_id='operator.' + row['id'], status='active')
            for collection, record in (('credentials', credential), ('applications', application), ('access_rules', rule)):
                save_resource(conn, collection, record, create=True)
        except (KeyError, TypeError, ValueError) as error:
            raise CatalogIntegrityError('legacy connection cannot be migrated') from error
    catalog = {'revision': 1, **{collection: _records(conn, collection) for collection in _TABLES}}
    validate_bindings(conn, catalog)
    from serverware import operator_catalog_policy
    operator_catalog_policy.verify_retained_policy(conn, catalog)
    # Last catalog write marks the entire metadata import, not authority publication.
    conn.execute('INSERT INTO operator_catalog_state VALUES(1,1,1)')
