// Presentation-only navigation. It never changes access or persists UI state.
function createWorkspaceNavigation() {
  const sidebar = element('workspace-sidebar');
  const toggle = element('workspace-menu-toggle');
  const mobile = window.matchMedia('(max-width: 800px)');
  function setOpen(open) {
    sidebar.dataset.menuOpen = String(open);
    toggle.setAttribute('aria-expanded', String(open));
    toggle.textContent = open ? 'Close menu' : 'Menu';
  }
  function close(focusToggle = false) {
    setOpen(false);
    if (focusToggle && mobile.matches) toggle.focus();
  }
  toggle.addEventListener('click', () => setOpen(toggle.getAttribute('aria-expanded') !== 'true'));
  sidebar.addEventListener('keydown', event => {
    if (event.key === 'Escape' && toggle.getAttribute('aria-expanded') === 'true') {
      event.preventDefault(); close(true);
    }
  });
  sidebar.addEventListener('click', event => {
    const link = event.target.closest('a[href^="#"]');
    if (link && link.getAttribute('href') === (location.hash || '#overview')) close(true);
  });
  mobile.addEventListener('change', () => {
    const focusHidden = mobile.matches && sidebar.contains(document.activeElement) && document.activeElement !== toggle;
    close(focusHidden);
  });
  setOpen(false);
  document.body.classList.add('navigation-ready');
  return {changed(view) {
    const focusHeading = mobile.matches && toggle.getAttribute('aria-expanded') === 'true';
    close();
    if (focusHeading) {
      const heading = element(view).querySelector('h1');
      heading.setAttribute('tabindex', '-1'); heading.focus({preventScroll: true});
    }
    window.scrollTo(0, 0);
  }};
}
