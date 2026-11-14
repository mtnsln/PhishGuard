const form = document.querySelector('#scan-form');
const input = document.querySelector('#url-input');
const button = document.querySelector('#scan-button');
const errorBox = document.querySelector('#error');
const result = document.querySelector('#result');

function showError(message) {
  errorBox.textContent = message;
  errorBox.hidden = false;
  result.hidden = true;
}

function renderReport(report) {
  document.querySelector('#risk-level').textContent = `${report.risk_level} risk`;
  document.querySelector('#risk-score').textContent = report.risk_score;
  document.querySelector('#summary').textContent = report.summary;
  document.querySelector('#hostname').textContent = report.hostname;
  document.querySelector('#registrable-domain').textContent = report.registrable_domain_estimate;
  document.querySelector('#disclaimer').textContent = report.disclaimer;

  const meter = document.querySelector('.meter');
  meter.setAttribute('aria-valuenow', String(report.risk_score));
  const fill = document.querySelector('#meter-fill');
  fill.style.width = `${report.risk_score}%`;
  fill.style.background = report.risk_level === 'high'
    ? 'var(--danger)'
    : report.risk_level === 'medium' ? 'var(--warn)' : 'var(--accent)';

  const list = document.querySelector('#findings');
  list.replaceChildren();
  for (const finding of report.findings) {
    const item = document.createElement('li');
    const head = document.createElement('div');
    head.className = 'finding-head';
    const title = document.createElement('span');
    title.textContent = finding.title;
    const points = document.createElement('span');
    points.className = 'finding-points';
    points.textContent = `+${finding.points} points`;
    const detail = document.createElement('p');
    detail.textContent = finding.detail;
    head.append(title, points);
    item.append(head, detail);
    list.append(item);
  }
  errorBox.hidden = true;
  result.hidden = false;
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const url = input.value.trim();
  if (!url) return;

  button.disabled = true;
  button.textContent = 'Analysing…';
  errorBox.hidden = true;
  result.hidden = true;

  try {
    const response = await fetch('/api/analyze', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({url})
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const message = typeof payload.detail === 'string'
        ? payload.detail
        : 'The URL could not be analysed.';
      throw new Error(message);
    }
    renderReport(payload);
  } catch (error) {
    showError(error.message || 'Could not connect to PhishGuard. Is the server running?');
  } finally {
    button.disabled = false;
    button.innerHTML = 'Analyse link <span aria-hidden="true">→</span>';
  }
});
