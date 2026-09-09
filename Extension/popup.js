document.addEventListener('DOMContentLoaded', () => {
  const promptInput = document.getElementById('promptInput');
  const clearBtn = document.getElementById('clearBtn');
  const decisionBadge = document.getElementById('decisionBadge');
  const latencyText = document.getElementById('latencyText');
  const riskScore = document.getElementById('riskScore');
  const threatCategory = document.getElementById('threatCategory');
  const explanationText = document.getElementById('explanationText');
  const sanitizedWrap = document.getElementById('sanitizedWrap');
  const sanitizedText = document.getElementById('sanitizedText');
  const copySanitizedBtn = document.getElementById('copySanitizedBtn');
  const scanState = document.getElementById('scanState');

  let debounceTimer = null;
  let abortController = null;

  async function performLiveScan(prompt) {
    if (!prompt.trim()) {
      resetToIdle();
      return;
    }

    // Cancel pending request if user is still actively typing
    if (abortController) {
      abortController.abort();
    }
    abortController = new AbortController();

    scanState.textContent = 'SCANNING...';

    try {
      const startTime = performance.now();
      const response = await fetch('http://127.0.0.1:8000/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ prompt: prompt, sanitize: true }),
        signal: abortController.signal
      });

      const data = await response.json();
      const latency = Math.round(performance.now() - startTime);

      // Render Dynamic Decision & Badges
      const decision = (data.decision || 'ALLOW').toUpperCase();
      decisionBadge.textContent = decision;
      decisionBadge.className = `badge badge-${decision}`;
      latencyText.textContent = `${latency}ms`;

      // Render Metrics
      riskScore.textContent = `${data.risk_score !== undefined ? data.risk_score : 0}/100`;
      threatCategory.textContent = data.label || 'Benign';
      explanationText.textContent = data.explanation || 'No malicious indicators detected.';

      // Render Sanitized Safe Output
      if (data.sanitized_prompt && data.sanitized_prompt !== prompt) {
        sanitizedWrap.classList.remove('hidden');
        sanitizedText.textContent = data.sanitized_prompt;
      } else {
        sanitizedWrap.classList.add('hidden');
      }

      scanState.textContent = 'LIVE STREAM';
    } catch (err) {
      if (err.name !== 'AbortError') {
        scanState.textContent = 'OFFLINE';
        explanationText.textContent = 'Could not connect to FastAPI at http://127.0.0.1:8000';
      }
    }
  }

  function resetToIdle() {
    decisionBadge.textContent = 'READY';
    decisionBadge.className = 'badge badge-IDLE';
    latencyText.textContent = '0ms';
    riskScore.textContent = '--/100';
    threatCategory.textContent = 'Idle';
    explanationText.textContent = 'Start typing to stream threat signals in real time.';
    sanitizedWrap.classList.add('hidden');
    scanState.textContent = 'LIVE STREAM';
  }

  // 150ms debounce for instantaneous feel while protecting the loop
  promptInput.addEventListener('input', () => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
      performLiveScan(promptInput.value);
    }, 150);
  });

  clearBtn.addEventListener('click', () => {
    promptInput.value = '';
    resetToIdle();
    promptInput.focus();
  });

  copySanitizedBtn.addEventListener('click', () => {
    if (sanitizedText.textContent) {
      navigator.clipboard.writeText(sanitizedText.textContent);
      copySanitizedBtn.textContent = 'Copied!';
      setTimeout(() => (copySanitizedBtn.textContent = 'Copy'), 1200);
    }
  });
});