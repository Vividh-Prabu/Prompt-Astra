/**
 * PROMPTASTRA - Settings & Policy JavaScript
 * Live threshold slider sync with real-time Enforced Gateway Policy cards reflection.
 */

document.addEventListener('DOMContentLoaded', () => {
  initSettingsManager();
});

function initSettingsManager() {
  // Sliders and numeric labels
  const threshBlock = document.getElementById('threshBlock');
  const threshReview = document.getElementById('threshReview');
  const valThreshBlock = document.getElementById('valThreshBlock');
  const valThreshReview = document.getElementById('valThreshReview');

  // Top Enforced Gateway Policy Range Labels
  const policyAllowRange = document.getElementById('policyAllowRange');
  const policyReviewRange = document.getElementById('policyReviewRange');
  const policyBlockRange = document.getElementById('policyBlockRange');

  // Interactive buttons
  const btnSaveSettings = document.getElementById('btnSaveSettings');
  const btnResetIntro = document.getElementById('btnResetIntro');

  const triggerToast = (type, title, message) => {
    if (typeof window.showToast === 'function') {
      window.showToast(type, title, message);
    }
  };

  function syncThresholds() {
    let blockVal = parseInt(threshBlock ? threshBlock.value : 75, 10);
    let reviewVal = parseInt(threshReview ? threshReview.value : 40, 10);

    // Prevent review threshold from overlapping or exceeding block threshold
    if (reviewVal >= blockVal) {
      reviewVal = blockVal - 1;
      if (threshReview) threshReview.value = reviewVal;
    }

    // 1. Update slider values in the form
    if (valThreshBlock) valThreshBlock.textContent = blockVal;
    if (valThreshReview) valThreshReview.textContent = reviewVal;

    // 2. Directly update the top 3 Enforced Gateway Security Policy cards
    if (policyAllowRange) {
      policyAllowRange.innerHTML = `RISK &lt; ${reviewVal}`;
    }
    if (policyReviewRange) {
      policyReviewRange.textContent = `RISK ${reviewVal} – ${blockVal - 1}`;
    }
    if (policyBlockRange) {
      policyBlockRange.innerHTML = `RISK &ge; ${blockVal}`;
    }
  }

  // Bind input listeners for real-time dragging reflection
  if (threshBlock) {
    threshBlock.addEventListener('input', syncThresholds);
    threshBlock.addEventListener('change', syncThresholds);
  }

  if (threshReview) {
    threshReview.addEventListener('input', syncThresholds);
    threshReview.addEventListener('change', syncThresholds);
  }

  // Save Preferences Button
  if (btnSaveSettings) {
    btnSaveSettings.addEventListener('click', () => {
      const block = threshBlock ? threshBlock.value : 75;
      const review = threshReview ? threshReview.value : 40;
      
      // Store locally for current session state
      localStorage.setItem('promptguard_thresh_block', block);
      localStorage.setItem('promptguard_thresh_review', review);
      
      triggerToast('success', 'Policy Updated', `Enforced thresholds: Allow < ${review}, Review ${review}–${block-1}, Block ≥ ${block}`);
    });
  }

  // Reset Intro Animation
  if (btnResetIntro) {
    btnResetIntro.addEventListener('click', () => {
      sessionStorage.removeItem('promptastra_intro_seen');
      triggerToast('info', 'Session Reset', 'Brand opening animation will show on the next page reload.');
    });
  }

  // Initial synchronization on page render
  syncThresholds();
}