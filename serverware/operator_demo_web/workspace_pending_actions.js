// A public-metadata queue, not a review-opening or decision authority. Merely
// visiting this view never opens private material, issues a receipt or decides.
const pendingApprovalUUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
function projectApprovalCapabilities(value) {
  const fields = ['schema', 'can_list', 'can_open_native_review', 'can_decide', 'reason'];
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).length !== fields.length || !fields.every(key => Object.hasOwn(value, key)) ||
      value.schema !== 'serverware.approvalCapabilities/v1' ||
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
      !['pending', 'approved', 'denied', 'expired'].includes(item.status) ||
      !text(item.route_id, 256) || typeof item.method !== 'string' || !/^[A-Z]{1,16}$/.test(item.method) || !text(item.url, 4096) ||
      !date(item.requested_at) || !date(item.expires_at) || !optionalText(item.principal_id, 512) ||
      !credential ||
      !(item.policy_hash === null || typeof item.policy_hash === 'string' && /^sha256:[0-9a-f]{64}$/.test(item.policy_hash)))
    throw new Error('Invalid pending-action metadata');
  // Explicitly discard all other fields, even if an unexpected server sends
  // private review material. Nothing from the raw response enters DOM/state.
  return Object.fromEntries(['id', 'status', 'route_id', 'method', 'url', 'requested_at', 'expires_at',
    'principal_id', 'credential_id', 'credential_version', 'policy_hash'].map(key => [key, item[key]]));
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
function createPendingActionsView({onAuthenticationLost = () => {}} = {}) {
  const el = id => document.getElementById(id);
  const node = (tag, text, className) => {
    const value = document.createElement(tag);
    if (text !== undefined) value.textContent = text;
    if (className) value.className = className;
    return value;
  };
  let visible = false, generation = 0, controller = null, loading = false;
  let capability = null, rows = null, requestedId = null, invalidLink = false, opener = null, opening = false;
  let selectedRecord;
  const status = message => { el('pending-actions-status').textContent = message; };
  const hold = id => {
    try {
      const reviewMarker = sessionStorage.getItem('serverware.nativeJitReviewUncertain.' + id);
      if (reviewMarker !== null) return reviewMarker === id ?
        'A protected opening has an uncertain outcome. No new review or decision will be attempted here.' :
        'The protected opening recovery marker is invalid. Review is unavailable.';
      const marker = sessionStorage.getItem('serverware.approvalDecisionUncertain.' + id);
      return marker === null ? '' : marker === id ?
        'A submitted decision needs status recovery. No review or decision will be retried here.' :
        'The decision recovery marker is invalid. Protected review is unavailable.';
    } catch (_) { return 'Browser decision recovery storage is unavailable. Protected review is unavailable.'; }
  };
  function openingReason() {
    if (!capability) return 'Protected review availability has not been established.';
    if (!capability.can_list) return capability.reason === 'role_required' ?
      'Your Serverware role does not allow access to this queue.' : 'The approval authority is unavailable.';
    if (!capability.can_open_native_review) return capability.reason === 'authority_unavailable' ?
      'The protected review authority is unavailable. These are saved request details, not an authorization to decide.' :
      'Protected review and decisions are not available in this instance. Ordinary credential and proxy access remain separate.';
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
  function renderSelected() {
    const selected = el('pending-actions-selected');
    selected.replaceChildren(); selected.hidden = !requestedId && !invalidLink;
    if (invalidLink) { selected.append(node('p', 'This approval link is invalid. No private review was requested.')); return; }
    if (!requestedId) return;
    selected.append(node('h2', 'Selected request'), node('code', requestedId));
    if (rows === null) { selected.append(node('p', 'Refresh pending actions to locate this exact request.')); return; }
    const item = rows.find(row => row.id === requestedId) || (selectedRecord?.id === requestedId ? selectedRecord : null);
    if (!item) {
      selected.append(node('p', selectedRecord === null ?
        'This request was not found. No other request was selected.' :
        'Loading the status of this exact request…'));
      return;
    }
    selected.append(node('p', 'Status: ' + item.status[0].toUpperCase() + item.status.slice(1), 'badge'));
    selected.append(metadata(item));
    if (item.status !== 'pending') {
      selected.append(node('p', item.status === 'approved' ?
        'Approval was recorded. This does not confirm that the provider request completed; check audit logging for its outcome.' :
        item.status === 'denied' ? 'This request was denied.' : 'This request expired.', 'small muted'));
      const recovery = hold(item.id);
      if (recovery) selected.append(node('p', recovery, 'small muted'));
      return;
    }
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
  function render() {
    el('pending-actions-refresh').disabled = loading || opening;
    el('pending-actions').setAttribute('aria-busy', String(loading));
    el('pending-actions-access').textContent = openingReason();
    el('pending-actions-list').replaceChildren(...(rows || []).map(item => {
      const card = node('article', undefined, 'card'); card.dataset.pendingApprovalId = item.id;
      const heading = node('div', undefined, 'connection-head');
      heading.append(node('h3', item.route_id), node('span', Date.parse(item.expires_at) <= Date.now() ? 'Expired · refresh status' : 'Pending', 'badge'));
      card.append(heading, node('p', item.method + ' · ' + (item.principal_id || 'Principal unavailable'), 'small'), node('p', 'Expires ' + item.expires_at, 'small muted'));
      const button = node('button', 'Select request', 'secondary'); button.dataset.pendingSelect = item.id;
      button.disabled = loading || opening;
      button.addEventListener('click', () => {
        if (!visible || loading || opening || !rows?.some(row => row === item)) return;
        requestedId = item.id; invalidLink = false; selectedRecord = undefined;
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
    loading = true; capability = null; rows = null; selectedRecord = undefined;
    status('Loading pending actions…'); render();
    try {
      const nextCapability = projectApprovalCapabilities(await request('/api/approvals/capabilities', signal));
      if (version !== generation || !visible) return false;
      capability = nextCapability;
      if (!capability.can_list) { status('Pending actions are unavailable for this session.'); return false; }
      const nextRows = projectPendingApprovals(await request('/api/approvals?status=pending', signal));
      if (version !== generation || !visible) return false;
      if (requestedId && !nextRows.some(row => row.id === requestedId)) {
        const result = await request('/api/approvals/' + requestedId, signal, true);
        if (version !== generation || !visible) return false;
        selectedRecord = result === null ? null : projectApprovalMetadata(result);
        if (selectedRecord && selectedRecord.id !== requestedId) throw new Error('unavailable');
      }
      rows = nextRows;
      status(rows.length ? rows.length + ' pending action' + (rows.length === 1 ? '' : 's') + ' visible to you. Showing at most the first 100.' :
        'No pending actions visible to you.');
      return true;
    } catch (error) {
      if (version !== generation || !visible) return false;
      capability = null; rows = null; selectedRecord = undefined;
      status(error.message === 'authentication' ? 'Your Serverware session could not be verified. Reload and sign in again.' :
        'Pending actions could not be loaded. Refresh to try again; no private review or decision was requested.');
      return false;
    } finally {
      if (version === generation) { loading = false; controller = null; render(); }
    }
  }
  function show(value, selection = {}) {
    const changed = visible !== Boolean(value);
    const previousId = requestedId;
    visible = Boolean(value);
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
    capability = null; rows = null; selectedRecord = undefined;
    status('Your Serverware session could not be verified. Reload and sign in again.'); render();
  }
  el('pending-actions-refresh').addEventListener('click', () => { void refresh(); });
  window.addEventListener('pagehide', () => show(false));
  render();
  return {show, refresh, authenticationLost, setReviewOpener(value) {
    if (value !== null && typeof value !== 'function') throw new Error('Invalid review controller');
    opener = value; render();
  }};
}
if (typeof module !== 'undefined' && module.exports) module.exports = {
  projectApprovalCapabilities, projectApprovalMetadata, projectPendingApprovals, pendingApprovalLocation, createPendingActionsView};
