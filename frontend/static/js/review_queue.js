/**
 * PROMPTASTRA - Review Queue JavaScript
 * Handles human-in-the-loop quarantine intervention (Approve, Reject, Escalate).
 */

document.addEventListener('DOMContentLoaded', () => {
  initReviewQueue();
});

function initReviewQueue() {
  const tableBody = document.getElementById('reviewTableBody');
  const modal = document.getElementById('reviewActionModal');
  const btnClose = document.getElementById('btnRevClose');
  const actionButtons = document.querySelectorAll('.btn-exec-action');
  const noteInput = document.getElementById('revAnalystNote');

  let currentItemId = null;

  if (tableBody) {
    tableBody.addEventListener('click', (e) => {
      const btn = e.target.closest('.btn-open-review');
      if (!btn) return;

      const row = btn.closest('tr');
      if (!row) return;

      currentItemId = btn.getAttribute('data-id');
      const rawJson = row.getAttribute('data-json');
      let data = {};
      try {
        data = JSON.parse(rawJson);
      } catch (err) {
        data = {
          id: currentItemId,
          attack_type: 'Instruction Override',
          timestamp: '2026-09-07',
          risk_score: 62,
          full_prompt: row.querySelector('.snippet-cell')?.textContent.trim(),
          explanation: 'Quarantined due to borderline policy tension.'
        };
      }

      openReviewModal(data);
    });
  }

  function openReviewModal(data) {
    if (!modal) return;

    document.getElementById('revModalId').textContent = `Review Event: ${data.id}`;
    document.getElementById('revCategory').textContent = data.attack_type || 'Unknown';
    document.getElementById('revTimestamp').textContent = data.timestamp || '';
    document.getElementById('revRisk').textContent = `${data.risk_score || 0} / 100`;
    document.getElementById('revPayload').textContent = data.full_prompt || data.prompt_snippet || '';
    document.getElementById('revExplanation').textContent = data.explanation || '';
    if (noteInput) noteInput.value = '';

    modal.classList.remove('hide-modal');
  }

  function closeReviewModal() {
    if (modal) modal.classList.add('hide-modal');
    currentItemId = null;
  }

  if (btnClose) btnClose.addEventListener('click', closeReviewModal);
  if (modal) {
    modal.addEventListener('click', (e) => {
      if (e.target === modal) closeReviewModal();
    });
  }

  // Handle Approve, Reject, Escalate actions
  actionButtons.forEach(btn => {
    btn.addEventListener('click', async () => {
      if (!currentItemId) return;
      const action = btn.getAttribute('data-action');
      const note = (noteInput ? noteInput.value : '').trim();

      try {
        const resp = await fetch('/api/review-action', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            id: currentItemId,
            action: action,
            note: note
          })
        });

        const result = await resp.json();

        // Update status pill in table
        const statusPill = document.getElementById(`status-${currentItemId}`);
        if (statusPill) {
          if (action === 'APPROVE') {
            statusPill.textContent = 'Approved by Analyst (Demo)';
            statusPill.className = 'status-pill status-approved font-mono';
            window.showToast('success', 'Payload Approved', `${currentItemId} cleared for ARGUS forwarding.`);
          } else if (action === 'REJECT') {
            statusPill.textContent = 'Rejected & Quarantined (Demo)';
            statusPill.className = 'status-pill status-rejected font-mono';
            window.showToast('error', 'Payload Quarantined', `${currentItemId} blocked permanently.`);
          } else {
            statusPill.textContent = 'Escalated to SOC (Demo)';
            statusPill.className = 'status-pill status-escalated font-mono';
            window.showToast('warning', 'Escalated', `${currentItemId} assigned to Tier-2 SOC.`);
          }
        }

        closeReviewModal();
      } catch (err) {
        window.showToast('error', 'Action Failed', 'Could not record review decision.');
      }
    });
  });
}
