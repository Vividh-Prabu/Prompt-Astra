/**
 * PROMPTASTRA - Threat Monitor JavaScript
 * Handles real-time search, multi-field filtering, and deep packet inspection modal.
 */

document.addEventListener('DOMContentLoaded', () => {
  initThreatMonitor();
});

function initThreatMonitor() {
  const searchInput = document.getElementById('threatSearchInput');
  const typeFilter = document.getElementById('filterAttackType');
  const decisionFilter = document.getElementById('filterDecision');
  const severityFilter = document.getElementById('filterSeverity');
  const resetBtn = document.getElementById('btnResetFilters');

  const tableBody = document.getElementById('monitorTableBody');
  const emptyState = document.getElementById('monitorEmptyState');

  const modal = document.getElementById('threatInspectModal');
  const btnClose = document.getElementById('btnModalClose');
  const btnDismiss = document.getElementById('btnModalDismiss');

  // Filter Rows
  function filterRows() {
    if (!tableBody) return;
    const query = (searchInput ? searchInput.value : '').toLowerCase().trim();
    const selType = (typeFilter ? typeFilter.value : 'ALL');
    const selDecision = (decisionFilter ? decisionFilter.value : 'ALL');
    const selSeverity = (severityFilter ? severityFilter.value : 'ALL');

    const rows = tableBody.querySelectorAll('tr');
    let visibleCount = 0;

    rows.forEach(row => {
      const id = (row.getAttribute('data-id') || '').toLowerCase();
      const type = row.getAttribute('data-type') || '';
      const decision = row.getAttribute('data-decision') || '';
      const severity = row.getAttribute('data-severity') || '';
      const textContent = row.textContent.toLowerCase();

      const matchesSearch = !query || id.includes(query) || textContent.includes(query);
      const matchesType = (selType === 'ALL') || (type.toLowerCase() === selType.toLowerCase());
      const matchesDecision = (selDecision === 'ALL') || (decision.toUpperCase() === selDecision.toUpperCase());
      const matchesSeverity = (selSeverity === 'ALL') || (severity.toUpperCase() === selSeverity.toUpperCase());

      if (matchesSearch && matchesType && matchesDecision && matchesSeverity) {
        row.style.display = '';
        visibleCount++;
      } else {
        row.style.display = 'none';
      }
    });

    if (emptyState) {
      if (visibleCount === 0) {
        emptyState.classList.remove('hide-empty');
      } else {
        emptyState.classList.add('hide-empty');
      }
    }
  }

  if (searchInput) searchInput.addEventListener('input', filterRows);
  if (typeFilter) typeFilter.addEventListener('change', filterRows);
  if (decisionFilter) decisionFilter.addEventListener('change', filterRows);
  if (severityFilter) severityFilter.addEventListener('change', filterRows);

  if (resetBtn) {
    resetBtn.addEventListener('click', () => {
      if (searchInput) searchInput.value = '';
      if (typeFilter) typeFilter.value = 'ALL';
      if (decisionFilter) decisionFilter.value = 'ALL';
      if (severityFilter) severityFilter.value = 'ALL';
      filterRows();
    });
  }

  // Deep Packet Inspection Modal
  if (tableBody) {
    tableBody.addEventListener('click', (e) => {
      const btn = e.target.closest('.btn-inspect-threat');
      if (!btn) return;

      const row = btn.closest('tr');
      if (!row) return;

      const rawJson = row.getAttribute('data-json');
      let threatData = null;
      try {
        threatData = JSON.parse(rawJson);
      } catch (err) {
        threatData = {
          id: row.getAttribute('data-id'),
          attack_type: row.getAttribute('data-type'),
          decision: row.getAttribute('data-decision'),
          severity: row.getAttribute('data-severity'),
          prompt_snippet: row.querySelector('.snippet-cell')?.textContent.trim() || '',
          timestamp: row.querySelector('.time-cell')?.textContent.trim() || '',
          risk_score: row.querySelector('.score-indicator')?.textContent.trim() || 0,
          confidence: 95,
          signals: ['Perimeter inspection event recorded'],
          explanation: 'Threat event logged by PromptGuard security telemetry.'
        };
      }

      openInspectionModal(threatData);
    });
  }

  function openInspectionModal(threat) {
    if (!modal) return;

    const modalEventId = document.getElementById('modalEventId');
    const modalDecisionBadge = document.getElementById('modalDecisionBadge');
    const modalAttackType = document.getElementById('modalAttackType');
    const modalTimestamp = document.getElementById('modalTimestamp');
    const modalRiskScore = document.getElementById('modalRiskScore');
    const modalArgusStatus = document.getElementById('modalArgusStatus');
    const modalPayload = document.getElementById('modalPayload');
    const modalExplanation = document.getElementById('modalExplanation');
    const modalSignalsList = document.getElementById('modalSignalsList');

    if (modalEventId) modalEventId.textContent = `Event Inspection: ${threat.id || 'THR-LIVE'}`;
    if (modalDecisionBadge) {
      modalDecisionBadge.textContent = threat.decision || 'BLOCK';
      modalDecisionBadge.className = `badge ${threat.decision === 'BLOCK' ? 'badge-block' : threat.decision === 'REVIEW' ? 'badge-review' : 'badge-allow'}`;
    }

    if (modalAttackType) modalAttackType.textContent = threat.attack_type || 'Unknown';
    if (modalTimestamp) modalTimestamp.textContent = threat.timestamp || '';
    if (modalRiskScore) modalRiskScore.textContent = `${threat.risk_score || 0} / 100`;

    if (modalArgusStatus) {
      if (threat.decision === 'BLOCK') {
        modalArgusStatus.textContent = 'ZERO EXPOSURE · BLOCKED AT GATEWAY';
        modalArgusStatus.className = 'modal-val font-mono font-bold text-emerald';
      } else if (threat.decision === 'REVIEW') {
        modalArgusStatus.textContent = 'HELD AT GATEWAY · HUMAN REVIEW';
        modalArgusStatus.className = 'modal-val font-mono font-bold text-amber';
      } else {
        modalArgusStatus.textContent = 'FORWARDED TO ARGUS CORE (SAFE)';
        modalArgusStatus.className = 'modal-val font-mono font-bold text-cyan';
      }
    }

    if (modalPayload) modalPayload.textContent = threat.full_prompt || threat.prompt_snippet || 'No payload recorded';
    if (modalExplanation) modalExplanation.textContent = threat.explanation || 'No explanation provided.';

    if (modalSignalsList) {
      modalSignalsList.innerHTML = '';
      const signals = threat.signals || [];
      if (signals.length === 0) {
        signals.push('Standard perimeter logging');
      }
      signals.forEach(sig => {
        const li = document.createElement('li');
        li.className = 'modal-signal-bullet';
        li.textContent = sig;
        modalSignalsList.appendChild(li);
      });
    }

    modal.classList.remove('hide-modal');
  }

  function closeModal() {
    if (modal) modal.classList.add('hide-modal');
  }

  if (btnClose) btnClose.addEventListener('click', closeModal);
  if (btnDismiss) btnDismiss.addEventListener('click', closeModal);
  if (modal) {
    modal.addEventListener('click', (e) => {
      if (e.target === modal) closeModal();
    });
  }
}
