#!/usr/bin/env node
// Compatibility entrypoint: the current UI uses the separated catalog model.
// Historical combined-connection fixtures remain available in Git at 5af81cdd.
// The successor suite intercepts all browser requests with synthetic fixtures.
require('./test_operator_catalog_browser.cjs').main().catch(error => {
  console.error(error.stack);
  process.exitCode = 1;
});
