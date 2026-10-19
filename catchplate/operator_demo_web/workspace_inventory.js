// Local presentation of the already-loaded public catalog. Filtering never
// fetches, changes authority, persists search text, or recovers a private token.
function createResourceInventory(containerId, label, {includeExpired = false, jump = false} = {}) {
  const container = element(containerId), prefix = containerId + '-inventory';
  const toolbar = textNode('div', undefined, 'resource-inventory');
  toolbar.setAttribute('role', 'search'); toolbar.setAttribute('aria-label', 'Saved ' + label);
  const fields = textNode('div', undefined, 'inventory-controls');
  const searchField = textNode('div'), searchLabel = textNode('label', 'Search saved ' + label);
  const search = textNode('input'); search.id = prefix + '-search'; search.type = 'search';
  search.maxLength = 256; search.autocomplete = 'off'; search.spellcheck = false;
  search.placeholder = 'Name, provider, related resource or ID'; searchLabel.htmlFor = search.id;
  searchField.append(searchLabel, search);
  const groupField = textNode('div'), groupLabel = textNode('label', 'Show');
  const group = textNode('select'); group.id = prefix + '-group'; groupLabel.htmlFor = group.id;
  const groups = [['all', 'All saved records'], ['current', 'Main list'],
    ...(includeExpired ? [['expired', 'Expired linked client access']] : []),
    ['diagnostic', 'Connection checks'], ['revoked', 'Revoked history']];
  for (const [value, name] of groups) { const option = textNode('option', name); option.value = value; group.append(option); }
  groupField.append(groupLabel, group);
  const clear = textNode('button', 'Clear filters', 'secondary'); clear.type = 'button'; clear.disabled = true;
  const summary = textNode('p', 'Loading saved ' + label + '…', 'small muted');
  summary.id = prefix + '-summary'; summary.setAttribute('role', 'status'); summary.setAttribute('aria-live', 'polite');
  search.setAttribute('aria-controls', containerId); group.setAttribute('aria-controls', containerId);
  fields.append(searchField, groupField, clear); toolbar.append(fields, summary); container.before(toolbar);
  let jumpButton;
  if (jump) {
    jumpButton = textNode('button', 'Find saved ' + label, 'secondary inventory-jump');
    jumpButton.type = 'button'; jumpButton.disabled = true; jumpButton.dataset.inventoryJump = containerId;
    jumpButton.setAttribute('aria-controls', search.id);
    container.closest('.page').querySelector('.intro').after(jumpButton);
    jumpButton.addEventListener('click', () => { search.focus(); toolbar.scrollIntoView({block: 'start'}); });
  }
  let entries = [], emptyText = '', available = false, filteredBefore = false;
  const normalGroups = new Map();
  function paint() {
    if (!filteredBefore) for (const details of container.querySelectorAll('details[data-resource-group]'))
      normalGroups.set(details.dataset.resourceGroup, details.open);
    const terms = search.value.trim().toLocaleLowerCase().split(/\s+/).filter(Boolean);
    const filtered = terms.length > 0 || group.value !== 'all';
    const selected = entries.filter(entry => (group.value === 'all' || entry.group === group.value) &&
      terms.every(term => entry.searchText.includes(term)));
    renderResourceGroups(containerId, selected, filtered ? 'No saved ' + label + ' match. Try another search or clear the filters.' : emptyText,
      {expanded: filtered, groupState: normalGroups});
    filteredBefore = filtered;
    search.disabled = group.disabled = !available; clear.disabled = !filtered;
    if (jumpButton) { jumpButton.disabled = !available || !entries.length; jumpButton.textContent = 'Find saved ' + label + ' (' + entries.length + ')'; }
    summary.textContent = !available ? 'Saved ' + label + ' are unavailable. Refresh workspace status before managing access.' :
      (filtered ? selected.length + ' of ' : '') + entries.length + ' saved ' + label +
      (filtered ? ' match. Matching retained groups are expanded; their status is unchanged.' : '. Connection checks and retained history stay grouped below.');
    for (const option of group.options) {
      const name = groups.find(([value]) => value === option.value)[1];
      const count = option.value === 'all' ? entries.length : entries.filter(entry => entry.group === option.value).length;
      option.textContent = name + ' (' + count + ')';
    }
  }
  search.addEventListener('input', paint); group.addEventListener('change', paint);
  clear.addEventListener('click', () => { search.value = ''; group.value = 'all'; paint(); search.focus(); });
  search.disabled = group.disabled = true;
  return {
    render(items, empty) {
      available = items !== null; emptyText = empty || 'Saved resources are unavailable.';
      entries = (items || []).map(entry => ({...entry, searchText: [
        ...[...entry.card.querySelectorAll('h3, .badge, .metadata dd')].map(node => node.textContent),
        ...(entry.keywords || [])].join(' ').toLocaleLowerCase()}));
      paint();
    }
  };
}
