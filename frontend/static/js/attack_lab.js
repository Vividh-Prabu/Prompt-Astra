/**
 * PROMPTASTRA - Attack Lab JavaScript
 * Orchestrates multi-stage pipeline animation and live test execution
 * against adversarial attack scenarios.
 */

document.addEventListener('DOMContentLoaded', () => {
  initAttackLab();
});

function initAttackLab() {
  const runButtons = document.querySelectorAll('.btn-run-test');
  const dockRunStatus = document.getElementById('dockRunStatus');
  const labResultBanner = document.getElementById('labResultBanner');

  const labInputName = document.getElementById('labInputName');
  const labRiskStatus = document.getElementById('labRiskStatus');
  const labGateDecision = document.getElementById('labGateDecision');
  const labArgusStatus = document.getElementById('labArgusStatus');

  const labNodeInput = document.getElementById('labNodeInput');
  const labNodeGateway = document.getElementById('labNodeGateway');
  const labNodeDetection = document.getElementById('labNodeDetection');
  const labNodeGate = document.getElementById('labNodeGate');
  const labNodeArgus = document.getElementById('labNodeArgus');

  const labPacket1 = document.getElementById('labPacket1');
  const labPacket2 = document.getElementById('labPacket2');
  const labPacket3 = document.getElementById('labPacket3');
  const labPacket4 = document.getElementById('labPacket4');

  runButtons.forEach(btn => {
    btn.addEventListener('click', async () => {
      const prompt = btn.getAttribute('data-prompt');
      const name = btn.getAttribute('data-name');
      const category = btn.getAttribute('data-category');

      // Scroll smoothly to pipeline dock if needed
      document.querySelector('.pipeline-dock-card').scrollIntoView({ behavior: 'smooth', block: 'nearest' });

      await executeTestSequence(prompt, name, category);
    });
  });

  async function executeTestSequence(prompt, name, category) {
    // Reset classes
    resetPipeline();

    if (dockRunStatus) {
      dockRunStatus.className = 'dock-status-idle font-mono text-cyan';
      dockRunStatus.innerHTML = `<span class="status-dot-pulse"></span><span>TRANSMITTING ADVERSARIAL PAYLOAD: ${name.toUpperCase()}</span>`;
    }

    if (labInputName) labInputName.textContent = name;
    if (labNodeInput) labNodeInput.classList.add('node-active');

    // Step 1: Packet from Input to Gateway
    if (labPacket1) {
      labPacket1.classList.add('firing');
    }

    await sleep(250);
    if (labNodeGateway) labNodeGateway.classList.add('node-active');
    if (labPacket2) labPacket2.classList.add('firing');

    await sleep(250);
    if (labNodeDetection) labNodeDetection.classList.add('node-active');
    if (labRiskStatus) labRiskStatus.textContent = 'Calculating signals...';
    if (labPacket3) labPacket3.classList.add('firing');

    // Send API Request
    try {
      const resp = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ prompt: prompt })
      });

      const data = await resp.json();
      await sleep(200);

      renderLabDecision(data, name);
    } catch (err) {
      if (dockRunStatus) {
        dockRunStatus.innerHTML = `<span class="text-crimson">API Communication Error</span>`;
      }
      window.showToast('error', 'Test Failed', 'Could not reach PromptGuard Gateway.');
    }
  }

  function renderLabDecision(data, scenarioName) {
    const decision = data.decision || 'BLOCK';

    if (labRiskStatus) labRiskStatus.textContent = `Score: ${data.risk_score} (${data.risk_level})`;
    if (labGateDecision) labGateDecision.textContent = decision;

    if (decision === 'BLOCK') {
      labNodeGate.classList.add('node-blocked');
      // Packet 4 is intercepted and NOT forwarded to ARGUS
      if (labNodeArgus) {
        labNodeArgus.classList.remove('node-active', 'node-blocked');
        labArgusStatus.textContent = 'Zero Exposure · Protected';
        labArgusStatus.className = 'lab-node-sub text-emerald font-mono font-bold';
      }

      if (dockRunStatus) {
        dockRunStatus.innerHTML = `<span class="status-dot dot-block"></span><span class="text-crimson">PAYLOAD BLOCKED BY PROMPTGUARD · ARGUS UNTOUCHED</span>`;
      }

      window.showToast('error', 'Threat Blocked', `Intercepted ${scenarioName}. ARGUS isolated.`);
    } else if (decision === 'REVIEW') {
      labNodeGate.classList.add('node-active');
      if (labNodeArgus) {
        labArgusStatus.textContent = 'Held in Quarantine';
        labArgusStatus.className = 'lab-node-sub text-amber font-mono';
      }
      if (dockRunStatus) {
        dockRunStatus.innerHTML = `<span class="status-dot dot-review"></span><span class="text-amber">HELD FOR HUMAN REVIEW</span>`;
      }
      window.showToast('warning', 'Review Required', `${scenarioName} requires human operator validation.`);
    } else {
      labNodeGate.classList.add('node-allowed');
      if (labPacket4) labPacket4.classList.add('firing');
      if (labNodeArgus) {
        labNodeArgus.classList.add('node-allowed');
        labArgusStatus.textContent = 'Safe Ingestion Approved';
        labArgusStatus.className = 'lab-node-sub text-emerald font-mono';
      }
      if (dockRunStatus) {
        dockRunStatus.innerHTML = `<span class="status-dot dot-allow"></span><span class="text-emerald">PAYLOAD VERIFIED SAFE · INGESTED BY ARGUS</span>`;
      }
      window.showToast('success', 'Safe Payload', `${scenarioName} cleared and forwarded to ARGUS.`);
    }

    // Populate Result Banner
    if (labResultBanner) {
      labResultBanner.classList.remove('hide-lab-result');

      const badge = document.getElementById('labBadgeDecision');
      const title = document.getElementById('labDecisionTitle');
      const score = document.getElementById('labScoreVal');
      const conf = document.getElementById('labConfVal');
      const latency = document.getElementById('labLatencyVal');
      const explanation = document.getElementById('labExplanation');
      const assuranceText = document.getElementById('labAssuranceText');

      badge.textContent = decision;
      badge.className = `badge ${decision === 'BLOCK' ? 'badge-block' : decision === 'REVIEW' ? 'badge-review' : 'badge-allow'}`;
      
      title.textContent = decision === 'BLOCK' ? 'Adversarial Payload Blocked at Perimeter' :
                          decision === 'REVIEW' ? 'Borderline Payload Quarantined for Review' :
                          'Payload Verified Safe for ARGUS';

      score.textContent = data.risk_score;
      conf.textContent = `${data.confidence}%`;
      latency.textContent = `${data.latency_ms || 15.2}ms`;
      explanation.textContent = data.explanation;

      if (decision === 'BLOCK') {
        assuranceText.textContent = 'ARGUS WAS NOT EXPOSED TO THE PAYLOAD';
        assuranceText.parentElement.style.display = 'flex';
      } else if (decision === 'REVIEW') {
        assuranceText.textContent = 'ARGUS EXPOSURE SUSPENDED PENDING SOC APPROVAL';
        assuranceText.parentElement.style.display = 'flex';
      } else {
        assuranceText.textContent = 'FORWARDED SAFELY TO ARGUS CORE';
        assuranceText.parentElement.style.display = 'flex';
      }
    }
  }

  function resetPipeline() {
    [labNodeInput, labNodeGateway, labNodeDetection, labNodeGate, labNodeArgus].forEach(n => {
      if (n) n.className = 'lab-node';
    });
    [labPacket1, labPacket2, labPacket3, labPacket4].forEach(p => {
      if (p) p.className = 'lab-packet';
    });
    if (labArgusStatus) {
      labArgusStatus.textContent = 'Isolated & Secure';
      labArgusStatus.className = 'lab-node-sub';
    }
    if (labResultBanner) labResultBanner.classList.add('hide-lab-result');
  }

  function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}
