// Opening this queue only reads public metadata. Host-trusted review and
// decisions require separate explicit gestures; native review stays separate.
const pendingApprovalUUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const hostApprovalWarning = 'Host-trusted approvals: a server administrator can bypass this control. Hardware-backed protection is not enabled.';
const hostApprovalPrefix = '/api/operator-demo/approvals';
function projectApprovalCapabilities(value) {
  if (value?.schema === 'catchplate.approvalCapabilities/v2') {
    const fields = ['schema', 'mode', 'can_list', 'can_review', 'can_decide', 'reason'];
    if (Array.isArray(value) || Object.keys(value).length !== fields.length || !fields.every(key => Object.hasOwn(value, key)) ||
        value.mode !== 'host_trusted_v1' || !fields.slice(2, 5).every(key => typeof value[key] === 'boolean') ||
        ![null, 'host_trusted_approvals_unavailable', 'role_required'].includes(value.reason) ||
        value.can_decide && !value.can_review || value.can_review && !value.can_list ||
        value.can_decide && value.reason !== null || !value.can_review && value.reason === null ||
        value.reason === 'role_required' && value.can_decide) throw new Error('Invalid host-trusted approval capability');
    return Object.fromEntries(fields.map(key => [key, value[key]]));
  }
  const fields = ['schema', 'can_list', 'can_open_native_review', 'can_decide', 'reason'];
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).length !== fields.length || !fields.every(key => Object.hasOwn(value, key)) ||
      value.schema !== 'catchplate.approvalCapabilities/v1' ||
      !fields.slice(1, 4).every(key => typeof value[key] === 'boolean') ||
      ![null, 'role_required', 'protected_review_unavailable', 'authority_unavailable'].includes(value.reason) ||
      value.can_decide && !value.can_open_native_review || value.can_open_native_review && !value.can_list ||
      value.can_decide && value.reason !== null || !value.can_open_native_review && value.reason === null ||
      value.reason === 'role_required' && value.can_list) throw new Error('Invalid pending-action capability');
  return Object.fromEntries(fields.map(key => [key, value[key]]));
}
function projectApprovalMetadata(item) {
  const text = (item, maximum) => typeof item === 'string' && item.length > 0 && item.length <= maximum &&
    !/[\u0000-\u001f\u007f]/.test(item);
  const date = item => text(item, 64) && /^\d{4}-\d{2}-\d{2}T/.test(item) && Number.isFinite(Date.parse(item));
  const optionalText = (item, maximum) => item === null || text(item, maximum);
  const credential = item && (item.credential_id === null && item.credential_version === null ||
    item.credential_id === '' && item.credential_version === 0 ||
    text(item.credential_id, 512) && Number.isSafeInteger(item.credential_version) && item.credential_version >= 1);
  if (!item || typeof item.id !== 'string' || !pendingApprovalUUID.test(item.id) ||
      !(item.assurance === 'host-trusted' ? ['pending', 'approved', 'denied', 'expired', 'consumed'] : ['pending', 'approved', 'denied', 'expired']).includes(item.status) ||
      !text(item.route_id, 256) || typeof item.method !== 'string' || !/^[A-Z]{1,16}$/.test(item.method) || !text(item.url, 4096) ||
      !date(item.requested_at) || !date(item.expires_at) || !optionalText(item.principal_id, 512) ||
      !credential ||
      !(item.policy_hash === null || typeof item.policy_hash === 'string' && /^sha256:[0-9a-f]{64}$/.test(item.policy_hash)))
    throw new Error('Invalid pending-action metadata');
  // Explicitly discard all other fields, even if an unexpected server sends
  // private review material. Nothing from the raw response enters DOM/state.
  const result = Object.fromEntries(['id', 'status', 'route_id', 'method', 'url', 'requested_at', 'expires_at',
    'principal_id', 'credential_id', 'credential_version', 'policy_hash'].map(key => [key, item[key]]));
  if (item.assurance === 'host-trusted') {
    if (!optionalText(item.reviewer_id, 512) || !(item.consumed_at === null || date(item.consumed_at)) ||
        !(item.approved_until === null || date(item.approved_until))) throw new Error('Invalid host-trusted approval metadata');
    Object.assign(result, {assurance: 'host-trusted', reviewer_id: item.reviewer_id,
      consumed_at: item.consumed_at, approved_until: item.approved_until});
  }
  return result;
}
function projectHostApprovalReview(value, id) {
  const digest = item => typeof item === 'string' && /^sha256:[0-9a-f]{64}$/.test(item);
  if (!value || value.assurance !== 'host-trusted' || !pendingApprovalUUID.test(value.review_receipt_id || '') ||
      !digest(value.review_digest) || typeof value.review_expires_at !== 'string' ||
      !Number.isFinite(Date.parse(value.review_expires_at)) || Date.parse(value.review_expires_at) <= Date.now())
    throw new Error('Invalid host-trusted review');
  const approval = projectApprovalMetadata(value.approval);
  const source = value.document;
  if (approval.id !== id || approval.assurance !== 'host-trusted' || approval.status !== 'pending' ||
      !source || typeof source !== 'object' || Array.isArray(source) || JSON.stringify(source).length > 65536 ||
      !['method', 'url', 'principal_id', 'route_id', 'credential_id', 'credential_version', 'policy_hash']
        .every(key => source[key] === approval[key]) || !digest(source.request_digest) || !digest(source.operation_digest))
    throw new Error('Invalid host-trusted review document');
  const document = Object.fromEntries(['method', 'url', 'principal_id', 'route_id', 'credential_id', 'credential_version',
    'policy_hash', 'request_digest', 'operation_digest', 'headers', 'query', 'body_sha256', 'operation']
    .filter(key => Object.hasOwn(source, key)).map(key => [key, source[key]]));
  return {approval, document, review_receipt_id: value.review_receipt_id,
    review_digest: value.review_digest, review_expires_at: value.review_expires_at};
}
function projectPendingApprovals(value) {
  if (!Array.isArray(value) || value.length > 100 || new Set(value.map(item => item?.id)).size !== value.length)
    throw new Error('Invalid pending-action metadata');
  return value.map(item => {
    const projected = projectApprovalMetadata(item);
    if (projected.status !== 'pending') throw new Error('Invalid pending-action metadata');
    return projected;
  });
}
function pendingApprovalLocation(pathname) {
  if (typeof pathname !== 'string') return null;
  if (pathname === '/approvals' || pathname === '/approvals/') return {id: null, invalid: false};
  if (!pathname.startsWith('/approvals/')) return null;
  const id = pathname.slice('/approvals/'.length);
  return pendingApprovalUUID.test(id) ? {id, invalid: false} : {id: null, invalid: true};
}
function projectPendingCatalog(value) {
  // Labels only: never retain credentials, authority documents or client tokens.
  if (!value || !['applications', 'credentials', 'access_rules'].every(key => Array.isArray(value[key]) && value[key].length <= 1024)) return null;
  const fields = {applications: ['id', 'principal_id', 'name', 'status'], credentials: ['id', 'name', 'status'],
    access_rules: ['id', 'route_id', 'application_id', 'credential_id', 'name', 'status']};
  return Object.fromEntries(Object.entries(fields).map(([collection, keys]) => [collection,
    value[collection].map(item => Object.fromEntries(keys.map(key => [key, typeof item?.[key] === 'string' ? item[key] : null])))]));
}
function pendingApprovalLabels(item, catalog) {
  const match = (collection, key, id, kind) => {
    if (!catalog || !id) return {label: kind + ' name unavailable', record: null};
    const found = catalog[collection].filter(record => record[key] === id);
    if (found.length > 1) return {label: 'Ambiguous ' + kind.toLowerCase(), record: null};
    if (!found.length) return {label: 'Unknown ' + kind.toLowerCase(), record: null};
    const record = found[0];
    if (record.status === 'revoked') return {label: 'Revoked ' + kind.toLowerCase(), record: null};
    if (record.status !== 'active' || !record.id || !record.name || record.name.length > 128 || /[\u0000-\u001f\u007f]/.test(record.name))
      return {label: kind + ' name unavailable', record: null};
    return {label: record.name, record};
  };
  const client = match('applications', 'principal_id', item.principal_id, 'Client');
  const credential = match('credentials', 'id', item.credential_id, 'Credential');
  const permission = match('access_rules', 'route_id', item.route_id, 'Permission');
  // An exact route label is not enough if its current resource bindings changed.
  if (permission.record && (!client.record || !credential.record || permission.record.application_id !== client.record.id ||
      permission.record.credential_id !== credential.record.id)) permission.label = 'Permission binding unavailable or changed';
  return {client: client.label, credential: credential.label, permission: permission.label};
}
function createPendingActionsView({onAuthenticationLost = () => {}, recoveryBlocked = () => false} = {}) {
  const el = id => document.getElementById(id);
  const node = (tag, text, className) => {
    const value = document.createElement(tag);
    if (text !== undefined) value.textContent = text;
    if (className) value.className = className;
    return value;
  };
  let visible = false, generation = 0, controller = null, loading = false;
  let capability = null, rows = null, requestedId = null, invalidLink = false, opener = null, opening = false;
  let selectedRecord, hostReview = null, publicCatalog = null;
  const hostMode = () => capability?.mode === 'host_trusted_v1';
  const status = message => { el('pending-actions-status').textContent = message; };
  const hold = id => {
    if (recoveryBlocked()) return 'Earlier browser recovery markers need review. No request review or decision can be sent; status checks remain available.';
    try {
      if (hostMode()) {
        const marker = sessionStorage.getItem('catchplate.hostApprovalDecisionUncertain.' + id);
        return marker === null ? '' : 'A decision needs status recovery. Check its status; do not submit it again.';
      }
      const reviewMarker = sessionStorage.getItem('catchplate.nativeJitReviewUncertain.' + id);
      if (reviewMarker !== null) return reviewMarker === id ?
        'A protected opening has an uncertain outcome. No new review or decision will be attempted here.' :
        'The protected opening recovery marker is invalid. Review is unavailable.';
      const marker = sessionStorage.getItem('catchplate.approvalDecisionUncertain.' + id);
      return marker === null ? '' : marker === id ?
        'A submitted decision needs status recovery. No review or decision will be retried here.' :
        'The decision recovery marker is invalid. Protected review is unavailable.';
    } catch (_) { return hostMode() ? 'Browser decision recovery storage is unavailable. No decision can be sent.' :
      'Browser decision recovery storage is unavailable. Protected review is unavailable.'; }
  };
  function openingReason() {
    if (hostMode()) return hostApprovalWarning + (capability.can_review ?
      ' Review an exact request before approving it once or denying it. The original HTTP 428 request has stopped.' :
      ' Reviews and decisions are currently unavailable for this session.');
    if (!capability) return 'Protected review availability has not been established.';
    if (!capability.can_list) return capability.reason === 'role_required' ?
      'Your Catchplate role does not allow access to this queue.' : 'The approval authority is unavailable.';
    if (!capability.can_open_native_review) return capability.reason === 'authority_unavailable' ?
      'The protected review authority is unavailable. These are saved request details, not an authorization to decide.' :
      'Protected review and decisions for individual requests are not available in this instance. Ordinary credential and proxy access remain separate.';
    return !opener ? 'Protected review is not connected in this workspace. No private review or decision has been opened.' :
      capability.can_decide ? 'Open a request to inspect its protected review before deciding.' :
        'Protected review is available; this session cannot decide requests.';
  }
  function metadata(item) {
    const details = node('dl', undefined, 'metadata');
    for (const [label, value] of [['Request ID', item.id], ['Client / principal', item.principal_id || 'Unavailable'],
      ['Route', item.route_id], ['Method', item.method],
      [/^sha256:/.test(item.url) ? 'Destination commitment' : 'Destination', item.url],
      ['Requested', item.requested_at], ['Expires', item.expires_at],
      ['Credential', item.credential_id || 'Unavailable'], ['Version', item.credential_id ? String(item.credential_version) : 'Unavailable'],
      ['Policy', item.policy_hash || 'Unavailable']]) details.append(node('dt', label), node('dd', value));
    return details;
  }
  function exactDetails(item) {
    const details = node('details'); details.dataset.pendingExactDetails = item.id;
    details.append(node('summary', 'Exact request details'), metadata(item));
    return details;
  }
  function namedSummary(item) {
    const names = pendingApprovalLabels(item, publicCatalog), summary = node('div');
    summary.dataset.pendingNames = item.id;
    summary.append(node('p', 'Client: ' + names.client, 'small'), node('p', 'Credential: ' + names.credential, 'small'));
    return {names, summary};
  }
  function renderSelected() {
    const selected = el('pending-actions-selected');
    selected.replaceChildren(); selected.hidden = !requestedId && !invalidLink;
    if (invalidLink) { selected.append(node('p', 'This approval link is invalid. No private review was requested.')); return; }
    if (!requestedId) return;
    if (rows === null) { selected.append(node('h2', 'Selected request'), node('code', requestedId), node('p', 'Refresh pending actions to locate this exact request.')); return; }
    const item = rows.find(row => row.id === requestedId) || (selectedRecord?.id === requestedId ? selectedRecord : null);
    if (!item) {
      selected.append(node('h2', 'Selected request'), node('code', requestedId));
      selected.append(node('p', selectedRecord === null ?
        'This request was not found. No other request was selected.' :
        'Loading the status of this exact request…'));
      return;
    }
    const {names, summary} = namedSummary(item);
    selected.append(node('h2', names.permission), summary,
      node('p', 'Names are labels from the current catalog and may have changed. The exact request identifiers and review binding remain authoritative.', 'small muted'));
    selected.append(node('p', 'Status: ' + item.status[0].toUpperCase() + item.status.slice(1), 'badge'));
    selected.append(exactDetails(item));
    if (item.status !== 'pending') {
      if (hostMode()) {
        selected.append(node('p', item.status === 'approved' ?
          'Approved once. The original request stopped with HTTP 428. Explicitly retry exactly the same request once before ' + item.approved_until + '. Catchplate will not replay it automatically.' :
          item.status === 'consumed' ? 'This approval has been consumed. Do not resend automatically; check the audit log for the provider outcome.' :
          item.status === 'denied' ? 'This request was denied. No retry is authorized.' : 'This request expired. No retry is authorized.', 'notice'));
        return;
      }
      selected.append(node('p', item.status === 'approved' ?
        'Approval was recorded. This does not confirm that the provider request completed; check audit logging for its outcome.' :
        item.status === 'denied' ? 'This request was denied.' : 'This request expired.', 'small muted'));
      const recovery = hold(item.id);
      if (recovery) selected.append(node('p', recovery, 'small muted'));
      return;
    }
    if (hostMode()) { renderHostReview(selected, item); return; }
    const reason = hold(item.id) || (Date.parse(item.expires_at) <= Date.now() ? 'This request has expired; refresh its metadata.' : openingReason());
    selected.append(node('p', reason, 'small muted'));
    if (!capability?.can_open_native_review || !opener) return;
    const button = node('button', 'Review request'); button.dataset.pendingReview = item.id;
    button.disabled = loading || opening || Boolean(hold(item.id)) || Date.parse(item.expires_at) <= Date.now();
    button.addEventListener('click', async () => {
      if (!visible || loading || opening || !capability?.can_open_native_review || !opener ||
          requestedId !== item.id || !(rows?.some(row => row === item) || selectedRecord === item) ||
          hold(item.id) || Date.parse(item.expires_at) <= Date.now()) return;
      const version = generation, open = opener;
      opening = true; render();
      try { await open(item.id); }
      catch (_) { if (version === generation) status('Protected review could not be opened. Refresh metadata before trying again.'); }
      finally { if (version === generation) { opening = false; render(); } }
    });
    selected.append(button);
  }
  async function hostPost(id, action, body, version) {
    const response = await fetch(hostApprovalPrefix + '/' + id + '/' + action, {method: 'POST', credentials: 'same-origin',
      cache: 'no-store', redirect: 'error', headers: {'Accept': 'application/json', 'Content-Type': 'application/json'},
      signal: AbortSignal.timeout(30000), body: JSON.stringify(body)});
    if (!visible || version !== generation) throw new Error('discarded');
    if ([401, 403].includes(response.status)) { onAuthenticationLost(); throw new Error('authentication'); }
    if (!response.ok || !response.headers.get('content-type')?.includes('application/json')) throw new Error('unavailable');
    const raw = await response.text();
    if (raw.length > 1048576) throw new Error('unavailable');
    return JSON.parse(raw);
  }
  function retireHostDecision(item) {
    if (item.assurance !== 'host-trusted' || item.status === 'pending') return;
    try { sessionStorage.removeItem('catchplate.hostApprovalDecisionUncertain.' + item.id); } catch (_) { /* terminal status is still readable */ }
  }
  function renderHostReview(selected, item) {
    const recovery = hold(item.id);
    if (recovery) {
      selected.append(node('p', recovery, 'notice'));
      const check = node('button', 'Check decision status', 'secondary'); check.dataset.hostStatus = item.id;
      check.disabled = opening || loading;
      check.addEventListener('click', async () => {
        if (!visible || opening || loading || requestedId !== item.id) return;
        const version = generation; opening = true; render();
        try {
          const value = projectApprovalMetadata(await request(hostApprovalPrefix + '/' + item.id, AbortSignal.timeout(15000)));
          if (version !== generation || !visible) return;
          if (value.id !== item.id || value.assurance !== 'host-trusted') throw new Error('unavailable');
          retireHostDecision(value); selectedRecord = value; rows = (rows || []).filter(row => row.id !== item.id);
          status(value.status === 'pending' ? 'The request is still pending. The interrupted decision is not being resubmitted.' : 'Decision status: ' + value.status + '.');
        } catch (_) { if (version === generation) status('Decision status is unavailable. No decision was retried.'); }
        finally { if (version === generation) { opening = false; render(); } }
      }); selected.append(check); return;
    }
    if (Date.parse(item.expires_at) <= Date.now()) { selected.append(node('p', 'This request expired. Refresh its status.')); return; }
    if (!capability.can_review) { selected.append(node('p', openingReason())); return; }
    if (hostReview?.approval.id !== item.id || Date.parse(hostReview.review_expires_at) <= Date.now()) {
      const button = node('button', 'Review request'); button.dataset.hostReview = item.id;
      button.disabled = opening || loading;
      button.addEventListener('click', async () => {
        if (!visible || opening || loading || !hostMode() || !capability.can_review || requestedId !== item.id || hold(item.id)) return;
        const version = generation; opening = true; hostReview = null; render();
        try {
          const review = projectHostApprovalReview(await hostPost(item.id, 'review', {}, version), item.id);
          if (version !== generation || !visible) return;
          hostReview = review; status('Review the exact request below. No decision has been submitted.');
        } catch (_) { if (version === generation) status('Review could not be opened. Refresh the request before explicitly reviewing it again. No decision was submitted.'); }
        finally { if (version === generation) { opening = false; render(); } }
      }); selected.append(button); return;
    }
    const reviewedDetails = node('details'); reviewedDetails.dataset.hostReviewDetails = item.id;
    reviewedDetails.append(node('summary', 'Exact reviewed request · headers, queries and hashes'), node('pre', JSON.stringify(hostReview.document, null, 2)));
    selected.append(node('h3', 'Request review'), node('p', hostApprovalWarning, 'notice'), reviewedDetails,
      node('p', 'Request body contents are not displayed; the body hash binds this approval to the exact submitted bytes. Approve only if you recognize the request.', 'notice'),
      node('p', 'Approval permits one explicit retry of exactly this request; it does not execute it. Never automatically replay an uncertain provider operation.', 'small muted'));
    for (const [decision, label] of [['approve', 'Approve once'], ['deny', 'Deny']]) {
      const button = node('button', label, decision === 'deny' ? 'secondary' : undefined); button.dataset.hostDecision = decision;
      button.disabled = opening || loading || !capability.can_decide;
      button.addEventListener('click', async () => {
        if (!visible || opening || loading || !hostMode() || !capability.can_decide || requestedId !== item.id ||
            hostReview?.approval.id !== item.id || Date.parse(hostReview.review_expires_at) <= Date.now() ||
            Date.parse(item.expires_at) <= Date.now() || hold(item.id)) return;
        const version = generation, review = hostReview;
        const key = 'catchplate.hostApprovalDecisionUncertain.' + item.id;
        try { sessionStorage.setItem(key, item.id); if (sessionStorage.getItem(key) !== item.id) throw new Error(); }
        catch (_) { status('Decision recovery storage is unavailable. No decision was sent.'); return; }
        opening = true; hostReview = null; render();
        try {
          const value = projectApprovalMetadata(await hostPost(item.id, 'decision', {decision,
            review_receipt_id: review.review_receipt_id, review_digest: review.review_digest, note: null}, version));
          if (version !== generation || !visible) return;
          if (value.id !== item.id || value.assurance !== 'host-trusted' ||
              !(decision === 'approve' ? ['approved', 'consumed'] : ['denied']).includes(value.status)) throw new Error('unavailable');
          retireHostDecision(value); selectedRecord = value; rows = (rows || []).filter(row => row.id !== item.id);
          status('Decision recorded: ' + value.status + '. No provider request was sent by this page.');
        } catch (_) { if (version === generation) status('The decision outcome is unknown. Check decision status; do not submit it again.'); }
        finally { if (version === generation) { opening = false; render(); } }
      }); selected.append(button);
    }
  }
  function render() {
    el('pending-actions-refresh').disabled = loading || opening;
    el('pending-actions').setAttribute('aria-busy', String(loading));
    el('pending-actions-access').textContent = openingReason();
    el('pending-actions-list').replaceChildren(...(rows || []).map(item => {
      const card = node('article', undefined, 'card'); card.dataset.pendingApprovalId = item.id;
      const {names, summary} = namedSummary(item);
      const heading = node('div', undefined, 'connection-head');
      heading.append(node('h3', names.permission), node('span', Date.parse(item.expires_at) <= Date.now() ? 'Expired · refresh status' : 'Pending', 'badge'));
      card.append(heading, summary, node('p', item.method + ' · Expires ' + new Date(item.expires_at).toLocaleString(), 'small muted'), exactDetails(item));
      const button = node('button', 'Select request', 'secondary'); button.dataset.pendingSelect = item.id;
      button.disabled = loading || opening;
      button.addEventListener('click', () => {
        if (!visible || loading || opening || !rows?.some(row => row === item)) return;
        requestedId = item.id; invalidLink = false; selectedRecord = undefined;
        hostReview = null;
        history.replaceState(null, '', '/approvals/' + item.id + '#pending-actions');
        renderSelected(); el('pending-actions-selected').focus({preventScroll: true});
      });
      card.append(button); return card;
    }));
    renderSelected();
  }
  async function request(path, signal, allowMissing = false) {
    const response = await fetch(path, {method: 'GET', credentials: 'same-origin', cache: 'no-store',
      redirect: 'error', headers: {'Accept': 'application/json'}, signal});
    if (!visible || signal.aborted) throw new Error('discarded');
    if ([401, 403].includes(response.status)) {
      onAuthenticationLost();
      throw new Error('authentication');
    }
    if (allowMissing && response.status === 404) return null;
    if (!response.ok || !response.headers.get('content-type')?.includes('application/json')) throw new Error('unavailable');
    const raw = await response.text();
    if (raw.length > 1048576) throw new Error('unavailable');
    return JSON.parse(raw);
  }
  async function refresh() {
    if (!visible || loading || opening) return false;
    const version = ++generation;
    controller?.abort(); controller = new AbortController();
    const signal = AbortSignal.any([controller.signal, AbortSignal.timeout(15000)]);
    loading = true; capability = null; rows = null; selectedRecord = undefined; hostReview = null;
    status('Loading individual request approvals…'); render();
    try {
      const nextCapability = projectApprovalCapabilities(await request('/api/approvals/capabilities', signal));
      if (version !== generation || !visible) return false;
      capability = nextCapability;
      if (!capability.can_list) { status('Individual request approvals are unavailable for this session.'); return false; }
      const prefix = hostMode() ? hostApprovalPrefix : '/api/approvals';
      const nextRows = projectPendingApprovals(await request(hostMode() ? prefix : prefix + '?status=pending', signal));
      if (hostMode() && nextRows.some(row => row.assurance !== 'host-trusted')) throw new Error('unavailable');
      if (version !== generation || !visible) return false;
      if (requestedId && !nextRows.some(row => row.id === requestedId)) {
        const result = await request(prefix + '/' + requestedId, signal, true);
        if (version !== generation || !visible) return false;
        selectedRecord = result === null ? null : projectApprovalMetadata(result);
        if (selectedRecord && selectedRecord.id !== requestedId) throw new Error('unavailable');
        if (hostMode() && selectedRecord) {
          if (selectedRecord.assurance !== 'host-trusted') throw new Error('unavailable');
          retireHostDecision(selectedRecord);
        }
      }
      rows = nextRows;
      status(rows.length ? rows.length + ' individual request' + (rows.length === 1 ? '' : 's') + ' awaiting approval. Showing at most the first 100.' :
        'No individual requests awaiting approval.');
      return true;
    } catch (error) {
      if (version !== generation || !visible) return false;
      capability = null; rows = null; selectedRecord = undefined;
      status(error.message === 'authentication' ? 'Your Catchplate session could not be verified. Reload and sign in again.' :
        'Individual request approvals could not be loaded. Refresh to try again; no private review or decision was requested.');
      return false;
    } finally {
      if (version === generation) { loading = false; controller = null; render(); }
    }
  }
  function show(value, selection = {}) {
    const changed = visible !== Boolean(value);
    const previousId = requestedId;
    visible = Boolean(value);
    if (!visible || previousId !== selection.requestedId) hostReview = null;
    requestedId = typeof selection.requestedId === 'string' && pendingApprovalUUID.test(selection.requestedId) ? selection.requestedId : null;
    invalidLink = selection.invalidLink === true || Boolean(selection.requestedId && !requestedId);
    if (!visible) {
      ++generation; controller?.abort(); controller = null; loading = false; opening = false; capability = null; rows = null; selectedRecord = undefined;
      render(); return;
    }
    if (previousId !== requestedId && !opening) {
      ++generation; controller?.abort(); controller = null; loading = false; selectedRecord = undefined;
    }
    render(); if (changed || previousId !== requestedId) void refresh();
  }
  function authenticationLost() {
    ++generation; controller?.abort(); controller = null; loading = false; opening = false;
    capability = null; rows = null; selectedRecord = undefined; hostReview = null; publicCatalog = null;
    status('Your Catchplate session could not be verified. Reload and sign in again.'); render();
  }
  el('pending-actions-refresh').addEventListener('click', () => { void refresh(); });
  window.addEventListener('pagehide', () => show(false));
  render();
  return {show, refresh, authenticationLost, setCatalog(value) {
    publicCatalog = projectPendingCatalog(value);
    if (visible) render(); // Display-only: no fetch, review reset, decision or token change.
  }, setReviewOpener(value) {
    if (value !== null && typeof value !== 'function') throw new Error('Invalid review controller');
    opener = value; render();
  }};
}
if (typeof module !== 'undefined' && module.exports) module.exports = {
  projectApprovalCapabilities, projectApprovalMetadata, projectPendingApprovals, projectHostApprovalReview,
  pendingApprovalLocation, projectPendingCatalog, pendingApprovalLabels, createPendingActionsView};
