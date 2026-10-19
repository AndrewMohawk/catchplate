// Public help only: never inspect, persist, transform or validate a secret.
function credentialGuideFor(credential) {
  if (credential?.app_preset && Object.hasOwn(operatorCredentialGuides, credential.app_preset)) return credential.app_preset;
  const connections = {github_token_v1: 'github_token', github_app_v1: 'github_app',
    npm_token_v1: 'npm', x_app_bearer_v1: 'x', alchemy_key_v1: 'alchemy'};
  return connections[credential?.connection_type] || 'manual';
}

function renderCredentialGuide(containerId, guideId, fieldIds = {}) {
  const container = element(containerId);
  const guide = Object.hasOwn(operatorCredentialGuides, guideId) ? operatorCredentialGuides[guideId] : null;
  container.hidden = !guide;
  if (container.dataset.provider !== (guide ? guideId : '')) {
    container.dataset.provider = guide ? guideId : '';
    container.replaceChildren();
    if (guide) {
      const heading = textNode('h3', guide.title);
      heading.id = containerId + '-title';
      container.setAttribute('aria-labelledby', heading.id);
      const steps = document.createElement('ol');
      steps.append(...guide.steps.map(step => textNode('li', step)));
      const links = textNode('div', undefined, 'credential-guide-links');
      for (const source of guide.links) {
        const url = new URL(source.url);
        if (url.protocol !== 'https:' || url.username || url.password) continue;
        const link = textNode('a', source.label);
        link.href = url.href; link.target = '_blank';
        link.rel = 'noopener noreferrer'; link.referrerPolicy = 'no-referrer';
        link.append(textNode('span', ' (opens in a new tab)', 'sr-only'));
        links.append(link);
      }
      if (['github_app', 'google_application', 'x_application'].includes(guideId)) {
        const help = document.createElement('details'), summary = document.createElement('summary');
        summary.append(heading); help.append(summary, steps, links); container.append(help);
      } else container.append(heading, steps, links);
    }
  }
  for (const [field, id] of Object.entries(fieldIds)) {
    const input = element(id), hintId = id + '-format-hint';
    const description = guide?.fields[field];
    input.placeholder = description?.placeholder || '';
    let hint = element(hintId);
    if (!hint) {
      hint = textNode('p', undefined, 'small muted credential-format-hint');
      hint.id = hintId; input.after(hint);
    }
    hint.textContent = description?.hint || '';
    hint.hidden = !description;
    const describedBy = (input.getAttribute('aria-describedby') || '').split(/\s+/).filter(value => value && value !== hintId);
    if (description) describedBy.push(hintId);
    if (describedBy.length) input.setAttribute('aria-describedby', describedBy.join(' '));
    else input.removeAttribute('aria-describedby');
  }
}

function initializeCredentialGuides() {
  renderCredentialGuide('google-consent-guide', 'google');
  renderCredentialGuide('x-account-guide', 'x_account');
  renderCredentialGuide('google-configuration-guide', 'google_application', {
    client_id: 'google-configuration-client-id', client_secret: 'google-configuration-client-secret'});
  renderCredentialGuide('x-configuration-guide', 'x_application', {
    client_id: 'x-configuration-client-id', client_secret: 'x-configuration-client-secret'});
  renderCredentialGuide('github-app-replace-guide', 'github_app', {private_key: 'github-app-replace-private-key'});
}
