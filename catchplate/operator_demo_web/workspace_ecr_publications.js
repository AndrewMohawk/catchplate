// A compound image publication is not an ordinary HTTP 428 request/retry.
const ecrPublicationPrefix = '/api/operator-demo/ecr-publications';
const ecrPublicationUUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const ecrPublicationDigest = value => typeof value === 'string' && /^sha256:[0-9a-f]{64}$/.test(value);
const ecrPublicationStates = {staging: 'Staging', awaiting_review: 'Awaiting image review', approved: 'Approved · client has not started',
  active: 'Publishing', suspended: 'Suspended · inspect status', published: 'Published', denied: 'Denied', expired: 'Expired',
  failed: 'Failed', uncertain: 'Outcome unknown · do not retry'};
function projectEcrArtifact(value, manifestDigest) {
  const fail = () => { throw operatorError('Staged image details are invalid. No decision is available.'); };
  const descriptor = (item, maximum) => {
    if (!item || !ecrPublicationDigest(item.digest) || !Number.isSafeInteger(item.size) || item.size < 1 || item.size > maximum ||
        typeof item.media_type !== 'string' || !/^application\/[a-z0-9.+-]{1,128}$/.test(item.media_type)) fail();
    return {media_type: item.media_type, digest: item.digest, size: item.size};
  };
  if (!value || value.schema !== 'catchplate.ecrVerifiedImage/v1' || !Array.isArray(value.layers) || value.layers.length > 128 ||
      !Array.isArray(value.blobs) || !value.blobs.length || value.blobs.length > 129) fail();
  const manifest = descriptor(value.manifest, 4194304), config = descriptor(value.config, 4194304);
  const layers = value.layers.map(item => descriptor(item, 536870912));
  const blobs = value.blobs.map(item => {
    if (!item || !ecrPublicationDigest(item.digest) || !Number.isSafeInteger(item.size) || item.size < 1 || item.size > 536870912) fail();
    return {digest: item.digest, size: item.size};
  });
  const roster = new Map(blobs.map(item => [item.digest, item.size]));
  if (manifest.digest !== manifestDigest || roster.size !== blobs.length ||
      new Set([config, ...layers].map(item => item.digest)).size !== roster.size ||
      [config, ...layers].some(item => roster.get(item.digest) !== item.size) ||
      value.total_blob_bytes !== blobs.reduce((total, item) => total + item.size, 0) || value.total_blob_bytes > 1073741824) fail();
  return {schema: value.schema, manifest, config, layers, blobs, total_blob_bytes: value.total_blob_bytes};
}
function projectEcrPublication(value) {
  const text = (item, maximum) => typeof item === 'string' && item.length > 0 && item.length <= maximum && !/[\u0000-\u001f\u007f]/.test(item);
  const integer = item => Number.isSafeInteger(item) && item >= 0;
  if (!value || value.schema !== 'catchplate.ecrPublication/v1' || value.assurance !== 'host-trusted' ||
      !Object.hasOwn(ecrPublicationStates, value.status) || !['id', 'application_id', 'access_rule_id', 'credential_id'].every(key => ecrPublicationUUID.test(value[key] || '')) ||
      !text(value.principal_id, 512) || !text(value.route_id, 256) || !Number.isSafeInteger(value.credential_generation) || value.credential_generation < 1 ||
      !['policy_hash', 'manifest_digest', 'artifact_sha256'].every(key => ecrPublicationDigest(value[key])) ||
      !['created_at_epoch_ms', 'expires_at_epoch_ms', 'revision'].every(key => integer(value[key])) ||
      value.expires_at_epoch_ms <= value.created_at_epoch_ms || value.expires_at_epoch_ms > 8640000000000000 ||
      value.reviewer_id !== null && !text(value.reviewer_id, 512) || value.decision_note !== null && !text(value.decision_note, 500) ||
      value.terminal_reason !== null && !text(value.terminal_reason, 256)) throw operatorError('Publication status is invalid. Refresh the exact publication; no action was sent.');
  const result = Object.fromEntries(['schema', 'id', 'status', 'assurance', 'application_id', 'access_rule_id', 'principal_id', 'route_id',
    'credential_id', 'credential_generation', 'policy_hash', 'manifest_digest', 'artifact_sha256', 'created_at_epoch_ms', 'expires_at_epoch_ms',
    'revision', 'reviewer_id', 'decision_note', 'terminal_reason'].map(key => [key, value[key]]));
  result.scope = ecrScope(value.scope);
  result.artifact_retirement_status = null; result.artifacts_retired = false; result.artifacts_retired_at_epoch_ms = null;
  const retirementFields = ['artifact_retirement_status', 'artifacts_retired', 'artifacts_retired_at_epoch_ms'];
  if (retirementFields.some(key => Object.hasOwn(value, key))) {
    const retired = value.artifact_retirement_status === 'retired';
    if (!['available', 'pending', 'retired'].includes(value.artifact_retirement_status) || value.artifacts_retired !== retired ||
        (retired ? !integer(value.artifacts_retired_at_epoch_ms) || value.artifacts_retired_at_epoch_ms < value.created_at_epoch_ms ||
          value.artifacts_retired_at_epoch_ms > 8640000000000000 : value.artifacts_retired_at_epoch_ms !== null) ||
        value.artifact_retirement_status !== 'available' && !['published', 'denied', 'expired', 'failed'].includes(value.status))
      throw operatorError('Local staged-file status is invalid. No retirement is available.');
    for (const key of retirementFields) result[key] = value[key];
  }
  result.artifact = value.artifact === null ? null : projectEcrArtifact(value.artifact, value.manifest_digest);
  if (['awaiting_review', 'approved', 'active', 'suspended', 'published'].includes(value.status) && !result.artifact)
    throw operatorError('The publication has no verified image summary. No decision is available.');
  result.child = null; result.progress = null;
  if (value.child !== null) {
    if (!ecrPublicationUUID.test(value.child?.id || '') || !text(value.child.action, 80) || !text(value.child.status, 80) || !ecrPublicationDigest(value.child.request_sha256))
      throw operatorError('Publication request status is invalid.');
    result.child = Object.fromEntries(['id', 'action', 'status', 'request_sha256'].map(key => [key, value.child[key]]));
  }
  if (value.progress !== null) {
    if (!integer(value.progress?.calls) || value.progress.calls > 4096 || !Array.isArray(value.progress.ready_digests) ||
        value.progress.ready_digests.length > 129 || value.progress.ready_digests.some(item => !ecrPublicationDigest(item)))
      throw operatorError('Publication progress is invalid.');
    result.progress = {calls: value.progress.calls, ready_digests: [...value.progress.ready_digests], uploading: value.progress.upload !== null};
  }
  return result;
}
function projectEcrPublications(value) {
  const cursor = value?.next_cursor ?? null;
  if (!value || !Array.isArray(value.publications) || value.publications.length > 10 ||
      new Set(value.publications.map(item => item?.id)).size !== value.publications.length ||
      cursor !== null && (!ecrPublicationUUID.test(cursor) || cursor !== value.publications.at(-1)?.id))
    throw operatorError('Staged publications could not be loaded.');
  return {publications: value.publications.map(projectEcrPublication), next_cursor: cursor};
}
function ecrPublicationRetirable(item) {
  return ['published', 'denied', 'expired', 'failed'].includes(item.status) && item.child?.status !== 'possible_send' &&
    ['available', 'pending'].includes(item.artifact_retirement_status) && item.artifacts_retired === false;
}
function ecrPublicationBinding(value) {
  return Object.fromEntries(['id', 'application_id', 'access_rule_id', 'principal_id', 'route_id', 'credential_id', 'credential_generation',
    'policy_hash', 'scope', 'manifest_digest', 'artifact_sha256', 'artifact', 'created_at_epoch_ms', 'expires_at_epoch_ms'].map(key => [key, value[key]]));
}
function ecrPublicationCurrent(item, catalog) {
  const rule = catalog?.access_rules.find(value => value.id === item.access_rule_id && value.status === 'active');
  const credential = catalog?.credentials.find(value => value.id === item.credential_id && value.status === 'active');
  const application = catalog?.applications.find(value => value.id === item.application_id && value.status === 'active');
  return Boolean(rule && credential && application && operatorRuleSupported(rule, catalog) &&
    rule.application_id === item.application_id && rule.credential_id === item.credential_id && rule.route_id === item.route_id &&
    application.principal_id === item.principal_id && credential.credential_generation === item.credential_generation &&
    catalog.policy.policy_hash === item.policy_hash && operatorExact(ecrScope(rule), item.scope));
}
function projectEcrReview(value, publication) {
  const reviewed = projectEcrPublication(value?.publication);
  if (value.assurance !== 'host-trusted' || !ecrPublicationUUID.test(value.review_receipt_id || '') || !ecrPublicationDigest(value.review_digest) ||
      reviewed.status !== 'awaiting_review' || !operatorExact(ecrPublicationBinding(reviewed), ecrPublicationBinding(publication)) ||
      !Number.isSafeInteger(value.review_expires_at_epoch_ms) || value.review_expires_at_epoch_ms <= Date.now() ||
      value.review_expires_at_epoch_ms > publication.expires_at_epoch_ms)
    throw operatorError('Image review does not match this exact publication. No decision was sent.');
  return {publication: reviewed, review_receipt_id: value.review_receipt_id, review_digest: value.review_digest,
    review_expires_at_epoch_ms: value.review_expires_at_epoch_ms};
}
function ecrPublicationLabel(item) { return item.scope.repository_name + ':' + item.scope.image_tag + ' · ' + item.manifest_digest.slice(0, 19) + '… · ' + ecrPublicationStates[item.status]; }
function createEcrPublicationsView(workspace) {
  let visible = false, rows = [], nextCursor = null, selectedId = '', review = null, busy = false, epoch = 0, controller = null, clientContext = '', retireConfirmationId = '';
  const el = element, node = textNode, selected = () => rows.find(item => item.id === selectedId);
  const capability = () => projectEcrCapability(workspace.state.catalog?.capabilities.ecr_publication);
  const message = text => { el('ecr-publications-status').textContent = text; };
  const marker = id => 'catchplate.ecrPublicationDecisionUncertain.' + id;
  const held = id => { try { return workspace.state.browserRecoveryBlocked || sessionStorage.getItem(marker(id)) !== null; } catch (_) { return true; } };
  const retirementMarker = id => 'catchplate.ecrPublicationRetirementUncertain.' + id;
  const retirementHeld = id => { try { return workspace.state.browserRecoveryBlocked || sessionStorage.getItem(retirementMarker(id)) !== null; } catch (_) { return true; } };
  const update = item => { rows = [item, ...rows.filter(other => other.id !== item.id)]; };
  function names(item) {
    const catalog = projectPendingCatalog(workspace.state.catalog);
    return pendingApprovalLabels({...item, credential_version: item.credential_generation}, catalog);
  }
  function detail(item) {
    const box = node('div'), named = names(item), fields = node('dl', undefined, 'metadata');
    box.append(node('h3', item.scope.repository_name + ':' + item.scope.image_tag),
      node('p', 'Client: ' + named.client + ' · Credential: ' + named.credential),
      node('p', 'Permission: ' + named.permission, 'small'), node('p', ecrPublicationStates[item.status], 'badge'));
    for (const [key, value] of [['AWS account', item.scope.registry_id], ['Region', item.scope.region], ['Repository', item.scope.repository_name],
      ['Tag', item.scope.image_tag], ['Manifest digest', item.manifest_digest], ['Expires', new Date(item.expires_at_epoch_ms).toLocaleString()]])
      fields.append(node('dt', key), node('dd', value));
    box.append(fields);
    if (item.artifact) {
      box.append(node('p', item.artifact.layers.length + ' layer(s) · ' + item.artifact.blobs.length + ' unique blob(s), including configuration · ' +
        item.artifact.total_blob_bytes.toLocaleString() + ' bytes', 'notice'),
        node('p', 'Manifest type: ' + item.artifact.manifest.media_type, 'small'),
        node('p', 'These are verified byte identities, not an image safety assessment, vulnerability scan or contents inspection.', 'small muted'));
      const blobs = node('details'); blobs.append(node('summary', 'Exact manifest, configuration and blob digests'), node('pre', JSON.stringify(item.artifact, null, 2))); box.append(blobs);
    } else box.append(node('p', 'Image staging is incomplete. It cannot be reviewed or approved.'));
    const exact = node('details'); exact.append(node('summary', 'Publication identity and review binding'),
      node('pre', JSON.stringify({...ecrPublicationBinding(item), artifact: undefined, revision: item.revision, child: item.child, progress: item.progress}, null, 2)));
    box.append(exact, node('p', 'Names come from the current catalog and may have changed. Exact captured identifiers, scope, image digests and review binding remain authoritative.', 'small muted'));
    if (['uncertain', 'suspended'].includes(item.status)) box.append(node('p', 'Do not automatically retry or resume. Check this exact publication and its audit history; an unknown result is not proof of failure.', 'notice'));
    if (item.status === 'published') box.append(node('p', 'The server recorded the correlated ECR publication result for this manifest.'));
    if (item.status === 'approved') box.append(node('p', 'Approved for this exact staged image. Approval did not publish it; the client must explicitly select this publication and start publishing before expiry.', 'notice'));
    if (item.artifact_retirement_status === 'retired') box.append(node('p', 'Local staged files have been retired. Any published AWS image and the publication’s audit history are unchanged.', 'notice'));
    if (item.artifact_retirement_status === 'pending') box.append(node('p', 'Local staged-file retirement is pending. No further publication is allowed; inspect status before manually retrying local cleanup.', 'notice'));
    return box;
  }
  function renderClient() {
    const catalog = workspace.state.catalog, applicationId = el('proxy-application').value, ruleId = el('proxy-rule').value;
    const rule = catalog?.access_rules.find(item => item.id === ruleId && item.application_id === applicationId && isEcrRule(item));
    const context = rule ? applicationId + ':' + ruleId : '';
    const select = el('ecr-client-publication'), previous = context === clientContext ? select.value : '';
    clientContext = context;
    const candidates = rows.filter(item => item.application_id === applicationId && item.access_rule_id === ruleId);
    const empty = node('option', 'Choose a publication; never selected automatically'); empty.value = '';
    select.replaceChildren(empty, ...candidates.map(item => { const option = node('option', ecrPublicationLabel(item)); option.value = item.id; return option; }));
    select.value = candidates.some(item => item.id === previous) ? previous : '';
    const item = candidates.find(item => item.id === select.value);
    el('ecr-client-refresh').disabled = busy || !rule;
    el('ecr-client-load-more').hidden = nextCursor === null;
    el('ecr-client-load-more').disabled = busy || !rule;
    select.disabled = busy || !rule;
    el('ecr-client-publication-status').textContent = item ? ecrPublicationStates[item.status] + ' · ' + item.id : 'No publication selected. Load staged publications, then choose the exact image.';
    const status = item ? 'python publish.py status --config ./catchplate-client.private.json --publication ' + item.id : '';
    const application = catalog?.applications.find(value => value.id === applicationId), credential = catalog?.credentials.find(value => value.id === rule?.credential_id);
    const publish = item && item.status === 'approved' && item.expires_at_epoch_ms > Date.now() && rule && operatorRuleSupported(rule, catalog) &&
      workspace.loaded() && !workspace.state.uncertain && application?.token_status === 'valid' && application.token_expires_at_epoch_ms > Date.now() &&
      item.credential_id === credential?.id && item.credential_generation === credential.credential_generation &&
      operatorExact(item.scope, ecrScope(rule)) && item.policy_hash === catalog.policy.policy_hash && !held(item.id);
    el('ecr-client-publication-command').textContent = status + (publish ? '\n\n# Review the local stage and image above before explicitly publishing:\npython publish.py publish --config ./catchplate-client.private.json --stage /absolute/reviewed-stage --publication ' + item.id + ' --execute-write' : '');
  }
  function render() {
    el('ecr-publications-panel').hidden = !capability() && rows.length === 0;
    el('ecr-publications-refresh').disabled = busy;
    el('ecr-publications-load-more').hidden = nextCursor === null;
    el('ecr-publications-load-more').disabled = busy;
    const list = el('ecr-publications-list'); list.replaceChildren();
    for (const item of rows) {
      const card = node('article', undefined, 'card'), named = names(item);
      card.append(node('h3', ecrPublicationLabel(item)), node('p', 'Client: ' + named.client + ' · ' + named.permission, 'small'));
      const button = node('button', 'Inspect staged image', 'secondary'); button.dataset.ecrSelect = item.id; button.disabled = busy;
      button.addEventListener('click', () => { if (busy) return; selectedId = item.id; review = null; retireConfirmationId = ''; render(); void readSelected(); });
      card.append(button); list.append(card);
    }
    const panel = el('ecr-publications-selected'), item = selected(); panel.replaceChildren();
    if (item) {
      panel.append(detail(item));
      const check = node('button', retirementHeld(item.id) ? 'Check retirement status (read only)' : held(item.id) ? 'Check decision status (read only)' : 'Refresh publication status', 'secondary');
      check.disabled = busy; check.addEventListener('click', () => { if (!busy) void readSelected(); }); panel.append(check);
      if (workspace.state.browserRecoveryBlocked) panel.append(node('p', 'Earlier browser recovery markers need review. Only publication status reads are available; no review, decision or retirement can be sent.', 'notice'));
      else if (retirementHeld(item.id)) panel.append(node('p', 'The local retirement outcome is unknown. Check this publication’s status before any manual retry. No AWS deletion was requested.', 'notice'));
      else if (held(item.id)) panel.append(node('p', 'A decision outcome is unknown. Only status reads are available; do not resubmit.', 'notice'));
      else if (item.status === 'awaiting_review' && item.expires_at_epoch_ms > Date.now() && ecrPublicationCurrent(item, workspace.state.catalog)) {
        if (review?.publication.id === item.id && review.review_expires_at_epoch_ms > Date.now()) {
          panel.append(node('p', 'Review the full manifest digest, destination and blob summary above. Approval authorizes this whole staged image, not an arbitrary sequence or a single HTTP retry.', 'notice'));
          for (const [decision, label] of [['approve', 'Approve this image'], ['deny', 'Deny this image']]) {
            const button = node('button', label, decision === 'deny' ? 'secondary' : undefined); button.disabled = busy;
            button.addEventListener('click', () => { if (!busy) void decide(decision); }); panel.append(button);
          }
        } else {
          const button = node('button', 'Review this image'); button.disabled = busy;
          button.addEventListener('click', () => { if (!busy) void openReview(); }); panel.append(button);
        }
      } else if (item.status === 'awaiting_review') panel.append(node('p', 'Review is unavailable: refresh this publication and its client, credential, permission and policy bindings before deciding.', 'notice'));
      if (!held(item.id) && !retirementHeld(item.id) && ecrPublicationRetirable(item)) {
        const confirming = retireConfirmationId === item.id;
        panel.append(node('p', 'Retiring removes only this publication’s local staged files. It does not delete the AWS image or audit history. This is permanent local cleanup, not a publication retry.', 'small'));
        const retire = node('button', confirming ? 'Confirm retire staged files' : item.artifact_retirement_status === 'pending' ? 'Retry retiring staged files' : 'Retire staged files', 'secondary');
        retire.disabled = busy;
        retire.addEventListener('click', () => { if (busy) return; if (confirming) void retireSelected(); else {retireConfirmationId = item.id; render();} });
        panel.append(retire);
        if (confirming) {
          const cancel = node('button', 'Keep staged files', 'secondary'); cancel.disabled = busy;
          cancel.addEventListener('click', () => {retireConfirmationId = ''; render();}); panel.append(cancel);
        }
      }
    }
    renderClient();
  }
  async function request(path, body, version) {
    const response = await fetch(path, {method: body === undefined ? 'GET' : 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error',
      headers: {Accept: 'application/json', ...(body === undefined ? {} : {'Content-Type': 'application/json'})},
      signal: controller.signal, ...(body === undefined ? {} : {body: JSON.stringify(body)})});
    if (version !== epoch) throw new Error('discarded');
    if ([401, 403].includes(response.status)) { workspace.authenticationLost(); throw new Error('authentication'); }
    if (!response.ok || !response.headers.get('content-type')?.includes('application/json')) throw new Error('unavailable');
    const raw = await response.text(); if (raw.length > 2097152) throw new Error('unavailable');
    if (version !== epoch) throw new Error('discarded'); return JSON.parse(raw);
  }
  async function run(work, failure) {
    if (busy) return; busy = true; controller = new AbortController(); const version = ++epoch, activeController = controller;
    const timer = setTimeout(() => activeController.abort(), 30000); render();
    try { await work(version); }
    catch (_) { if (version === epoch) message(failure); }
    finally { clearTimeout(timer); if (version === epoch) { busy = false; controller = null; render(); } }
  }
  async function load(more = false) {
    const cursor = more ? nextCursor : null; if (more && !cursor) return;
    review = null; retireConfirmationId = '';
    await run(async version => {
      const page = projectEcrPublications(await request(ecrPublicationPrefix + (cursor ? '?before=' + cursor : ''), undefined, version));
      if (cursor && (page.next_cursor === cursor || page.publications.some(item => rows.some(old => old.id === item.id)))) throw new Error('repeated page');
      rows = cursor ? [...rows, ...page.publications] : page.publications; nextCursor = page.next_cursor;
      message(rows.length ? rows.length + ' publication(s) loaded. ' + (nextCursor ? 'More are available; use Load more.' : 'All available publications are loaded.') + ' Select one exact image to inspect.' : 'No staged image publications. Stage an image using your configured client.'); },
    'Staged publications could not be loaded. No review, decision or AWS request was sent.');
  }
  async function readSelected() {
    const id = selectedId; if (!ecrPublicationUUID.test(id)) return; review = null; retireConfirmationId = '';
    await run(async version => { const item = projectEcrPublication(await request(ecrPublicationPrefix + '/' + id, undefined, version));
      if (item.id !== id) throw new Error(); update(item);
      if (item.status !== 'awaiting_review') try { sessionStorage.removeItem(marker(id)); } catch (_) {}
      if (item.artifact_retirement_status === 'retired' || item.artifact_retirement_status === 'pending' && ecrPublicationRetirable(item))
        try { sessionStorage.removeItem(retirementMarker(id)); } catch (_) {}
      message('Publication status: ' + ecrPublicationStates[item.status] + '. No action was replayed.'); },
    'Exact publication status is unavailable. No decision or publication was retried.');
  }
  async function openReview() {
    const item = selected(); if (!visible || !item || held(item.id) || item.status !== 'awaiting_review' ||
      !ecrPublicationCurrent(item, workspace.state.catalog) || item.expires_at_epoch_ms <= Date.now()) return;
    await run(async version => { review = projectEcrReview(await request(ecrPublicationPrefix + '/' + item.id + '/review', {}, version), item);
      update(review.publication); message('Review opened for this exact staged image. No decision or AWS request was sent.'); },
    'Image review is unavailable. Refresh this publication before explicitly reviewing it again. No decision was submitted.');
  }
  async function decide(decision) {
    const item = selected(), receipt = review;
    if (!visible || !item || !receipt || !ecrPublicationCurrent(item, workspace.state.catalog) || held(item.id) || item.status !== 'awaiting_review' || receipt.publication.id !== item.id ||
        receipt.review_expires_at_epoch_ms <= Date.now() || item.expires_at_epoch_ms <= Date.now() ||
        !operatorExact(ecrPublicationBinding(item), ecrPublicationBinding(receipt.publication))) return;
    try { sessionStorage.setItem(marker(item.id), item.id); if (sessionStorage.getItem(marker(item.id)) !== item.id) throw new Error(); }
    catch (_) { message('Decision recovery storage is unavailable. No decision was sent.'); return; }
    review = null;
    await run(async version => { const result = projectEcrPublication(await request(ecrPublicationPrefix + '/' + item.id + '/decision',
      {decision, review_receipt_id: receipt.review_receipt_id, review_digest: receipt.review_digest, note: null}, version));
      if (result.id !== item.id || result.status !== (decision === 'approve' ? 'approved' : 'denied') ||
          !operatorExact(ecrPublicationBinding(result), ecrPublicationBinding(item))) throw new Error();
      update(result); sessionStorage.removeItem(marker(item.id)); message(decision === 'approve' ?
        'Image approved. Nothing was published. The client must explicitly select this publication and start publishing.' : 'Image denied. No publication is authorized.'); },
    'The decision outcome is unknown. Check its status; do not submit the decision or publication again.');
  }
  async function retireSelected() {
    const item = selected();
    if (!visible || !item || retireConfirmationId !== item.id || held(item.id) || retirementHeld(item.id) || !ecrPublicationRetirable(item)) return;
    try { sessionStorage.setItem(retirementMarker(item.id), item.id); if (sessionStorage.getItem(retirementMarker(item.id)) !== item.id) throw new Error(); }
    catch (_) {message('Retirement recovery storage is unavailable. No staged files were retired.'); return;}
    retireConfirmationId = ''; review = null;
    await run(async version => {
      const result = projectEcrPublication(await request(ecrPublicationPrefix + '/' + item.id + '/retire', {}, version));
      if (result.id !== item.id || result.status !== item.status || result.revision < item.revision ||
          result.artifact_retirement_status !== 'retired' || !operatorExact(ecrPublicationBinding(result), ecrPublicationBinding(item))) throw new Error();
      update(result); sessionStorage.removeItem(retirementMarker(item.id));
      message('Local staged files retired. The AWS image and audit history were not deleted.');
    }, 'The local retirement outcome is unknown. Check its status before any manual retry. No AWS deletion was requested.');
  }
  function authenticationLost() {
    ++epoch; controller?.abort(); controller = null; busy = false; rows = []; nextCursor = null; selectedId = ''; review = null; retireConfirmationId = ''; render();
    message('Your session could not be verified. Reload and sign in again.');
  }
  el('ecr-publications-refresh').addEventListener('click', () => { if (!busy) void load(); });
  el('ecr-client-refresh').addEventListener('click', () => { if (!busy) void load(); });
  for (const id of ['ecr-publications-load-more', 'ecr-client-load-more']) el(id).addEventListener('click', () => { if (!busy) void load(true); });
  el('ecr-client-publication').addEventListener('change', () => {
    const id = el('ecr-client-publication').value; if (!ecrPublicationUUID.test(id) || busy) { renderClient(); return; }
    selectedId = id; review = null; retireConfirmationId = ''; void readSelected();
  });
  for (const id of ['proxy-application', 'proxy-rule']) el(id).addEventListener('change', renderClient);
  workspace.subscribe(render); workspace.onAuthenticationLost(authenticationLost);
  window.addEventListener('pagehide', authenticationLost);
  render();
  return {show(value) {
    const first = !visible && value; visible = Boolean(value);
    if (!visible) { ++epoch; controller?.abort(); controller = null; busy = false; review = null; retireConfirmationId = ''; }
    render(); if (first && capability() && !rows.length) void load();
  }, load, authenticationLost};
}
