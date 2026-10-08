"""Existing signed policy format rendered from reusable catalog references."""
from __future__ import annotations

from copy import deepcopy
import json

from serverware import operator_catalog_schema as schema


def _response_profile(rule: dict, route: dict) -> None:
    mode = rule.get('response_mode', 'projected_json')
    fields = rule.get('response_fields')
    if (mode not in {'projected_json', 'unfiltered_json'} or not isinstance(fields, list)
            or (mode == 'projected_json') != bool(fields)):
        raise schema.CatalogIntegrityError('catalog response mode/fields refused')
    if mode == 'projected_json':
        return  # Preserve the complete legacy profile byte-for-byte.
    config = route['adapter']['config']
    previous = config['response']
    config['response'] = {
        'mode': 'bufferedPassthrough', 'bodyFormat': 'json',
        'maxBodyBytes': previous['maxBodyBytes'], 'contentTypes': ['application/json'],
        'allowedHeaders': [], 'error': {
            'mode': 'bufferedPassthrough', 'bodyFormat': 'json',
            'maxBodyBytes': previous['error']['maxBodyBytes'], 'contentTypes': ['application/json'],
            'allowedHeaders': [], 'onInvalid': 'block',
        },
    }


def render(catalog: dict, sequence: int, initial_hash: str) -> dict:
    from serverware import operator_demo_store as legacy
    credentials = {row['id']: row for row in catalog['credentials']}
    applications = {row['id']: row for row in catalog['applications']}
    selected = [row for row in catalog['access_rules'] if row['status'] == 'active'
        and applications[row['application_id']]['status'] == 'active'
        and credentials[row['credential_id']]['status'] == 'active']
    if not selected:
        return legacy._build([], sequence, initial_hash)
    principals, credential_policies, routes = {}, {}, []
    for rule in selected:
        application = applications[rule['application_id']]
        credential = credentials[rule['credential_id']]
        # Reuse the established request/response envelope and schema constraints.
        flat = {**rule, 'principal_id': application['principal_id'],
            'token_sha256': application['token_sha256'],
            'token_expires_at_epoch_ms': application['token_expires_at_epoch_ms'],
            'auth_type': credential['auth_type'], 'header_name': credential['header_name']}
        google = credential['auth_type'] == 'google_oauth'
        if google:
            # Reuse only the established envelope; replace the complete static
            # binding below with the verified account's OAuth contract.
            flat['auth_type'] = 'bearer'
        generated = legacy._build([flat], sequence, initial_hash)
        principal = generated['principals'][0]
        principal['proxyAuthorization']['tokenId'] = application['id']
        principals[application['id']] = principal
        credential_policy = generated['credentials'][0]
        credential_policy['providerSubject'] = credential['provider_subject']
        credential_policies[credential['id']] = credential_policy
        route = generated['routes'][0]
        route['adapter']['config']['credentialBinding']['subjects'] = [credential['provider_subject']]
        if google:
            from serverware import operator_catalog_google
            operator_catalog_google.validate_rule(rule, credential)
            credential_policies[credential['id']] = operator_catalog_google.credential_policy(credential)
            route['adapter']['config']['credentialBinding'] = operator_catalog_google.route_binding(credential)
        _response_profile(rule, route)
        replacement = schema.rule_credential_header(rule, credential)
        if replacement is not None:
            route['credentialHeader'] = replacement
        routes.append(route)
    bundle = generated
    bundle['principals'] = [principals[row['id']] for row in catalog['applications'] if row['id'] in principals]
    bundle['credentials'] = [credential_policies[row['id']] for row in catalog['credentials'] if row['id'] in credential_policies]
    bundle['routes'] = routes
    return bundle


def unsigned(raw: dict) -> dict:
    value = deepcopy(raw)
    value['metadata'].pop('signature', None)
    value['metadata'].pop('signingKeyId', None)
    return value


def _retained(conn):
    from serverware import policy_bundle
    row = conn.execute('SELECT * FROM operator_demo_policy WHERE singleton=1').fetchone()
    if row is None:
        raise schema.CatalogIntegrityError('retained operator policy unavailable')
    raw = json.loads(row['signed_bundle_json'])
    compiled = policy_bundle.compile_policy_bundle(raw, verify_signature=True, validate_schema=True)
    if (compiled.hash != row['policy_hash'] or raw.get('metadata', {}).get('sequence') != row['sequence']
            or raw.get('metadata', {}).get('id') != 'serverware-operator-demo'
            or raw.get('metadata', {}).get('rollbackEpoch') != 1):
        raise schema.CatalogIntegrityError('retained operator policy binding refused')
    return row, raw


def verify_retained_policy(conn, catalog: dict) -> None:
    """Migration refuses drift without touching signed bytes or policy state."""
    row, signed = _retained(conn)
    if unsigned(signed) != render(catalog, row['sequence'], row['initial_hash']):
        raise schema.CatalogIntegrityError('legacy policy differs from imported catalog')


def publish(conn) -> dict:
    """Publish inside the caller transaction; caller materializes only after commit."""
    from serverware import db, policy_bundle
    from serverware.operator_publication import assert_held
    assert_held()
    schema._transaction(conn)
    catalog = schema.read_catalog(conn)
    schema.validate_bindings(conn, catalog)
    row, previous = _retained(conn)
    current = render(catalog, row['sequence'], row['initial_hash'])
    if current == unsigned(previous):
        return {'policy_hash': row['policy_hash'], 'sequence': row['sequence'], 'changed': False}
    following = render(catalog, row['sequence'] + 1, row['initial_hash'])
    signed = policy_bundle.sign_policy_bundle(following)
    compiled = policy_bundle.compile_policy_bundle(signed, verify_signature=True, validate_schema=True)
    conn.execute('UPDATE operator_demo_policy SET sequence=?,policy_hash=?,signed_bundle_json=?,updated_at=? WHERE singleton=1',
        (row['sequence'] + 1, compiled.hash, policy_bundle.canonical_json(signed), db.iso_now()))
    return {'policy_hash': compiled.hash, 'sequence': row['sequence'] + 1, 'changed': True}
