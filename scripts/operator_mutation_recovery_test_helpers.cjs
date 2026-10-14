'use strict';
const assert = require('node:assert/strict');
// Independent literal oracle. No production helper is imported by privacy
// assertions, and no other browser-storage key/value is exempted.
const MUTATION_REVIEW_KEY = 'serverware.operator.mutation.review.v1';
const MUTATION_REVIEW_VALUE = 'required';
function mutationReviewStorage() {
  const values = new Map();
  return {
    getItem(key) { assert.equal(key, MUTATION_REVIEW_KEY); return values.get(key) ?? null; },
    setItem(key, value) { assert.equal(key, MUTATION_REVIEW_KEY); assert.equal(value, MUTATION_REVIEW_VALUE); values.set(key, value); },
    removeItem(key) { assert.equal(key, MUTATION_REVIEW_KEY); values.delete(key); }
  };
}
function withoutMutationReview(entries) {
  return entries.filter(([key, value]) => {
    if (key !== MUTATION_REVIEW_KEY) return true;
    assert.equal(value, MUTATION_REVIEW_VALUE, 'shared review retains only its exact public constant');
    return false;
  });
}
async function acknowledgeMutationReview(page) {
  assert.equal(await page.evaluate(key => sessionStorage.getItem(key), MUTATION_REVIEW_KEY), MUTATION_REVIEW_VALUE);
  await page.locator('#mutation-review').waitFor({state: 'visible'});
  await page.waitForFunction(() => !document.getElementById('mutation-review-confirm').disabled);
  await page.locator('#mutation-review-confirm').click();
  assert.equal(await page.evaluate(key => sessionStorage.getItem(key), MUTATION_REVIEW_KEY), null);
}
module.exports = {MUTATION_REVIEW_KEY, MUTATION_REVIEW_VALUE, mutationReviewStorage, withoutMutationReview, acknowledgeMutationReview};
