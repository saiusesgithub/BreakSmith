const state = { tab: null, url: '', report: null };
const severityPenalty = { critical: 20, high: 10, medium: 5, low: 2, info: 0 };

const $ = selector => document.querySelector(selector);
const setStatus = (message = '', error = false) => {
  const status = $('#status');
  status.textContent = message;
  status.className = `status${message ? ' visible' : ''}${error ? ' error' : ''}`;
};

function githubRepository(url) {
  try {
    const parsed = new URL(url);
    if (parsed.hostname !== 'github.com') return null;
    const [owner, repository] = parsed.pathname.split('/').filter(Boolean);
    if (!owner || !repository || ['features', 'topics', 'marketplace', 'settings'].includes(owner)) return null;
    return `https://github.com/${owner}/${repository.replace(/\.git$/, '')}`;
  } catch {
    return null;
  }
}

function riskLevel(score) {
  if (score >= 90) return 'LOW';
  if (score >= 75) return 'GUARDED';
  if (score >= 50) return 'MODERATE';
  if (score >= 25) return 'HIGH';
  return 'CRITICAL';
}

function makeFinding(ruleId, title, severity, description, evidence = '') {
  return { id: `${ruleId}-${crypto.randomUUID()}`, ruleId, title, severity, description, evidence };
}

function inspectDocument() {
  const findings = [];
  const add = (ruleId, title, severity, description, evidence = '') => findings.push({ ruleId, title, severity, description, evidence });
  const pageUrl = new URL(location.href);

  document.querySelectorAll('form').forEach((form, index) => {
    const method = (form.method || 'get').toLowerCase();
    const action = form.action || location.href;
    const hasPassword = Boolean(form.querySelector('input[type="password"]'));
    if (hasPassword && method === 'get') add('live.password-get', 'Password submitted with GET', 'high', 'Password fields should not be transmitted in URLs.', `Form ${index + 1}`);
    if (pageUrl.protocol === 'https:' && action.startsWith('http:')) add('live.insecure-form', 'Insecure form destination', 'high', 'An HTTPS page submits form data over unencrypted HTTP.', action);
  });

  const mixed = [...document.querySelectorAll('script[src], iframe[src], link[href], img[src], video[src], audio[src]')]
    .map(node => node.src || node.href)
    .filter(value => pageUrl.protocol === 'https:' && value?.startsWith('http:'));
  if (mixed.length) add('live.mixed-content', 'Mixed HTTP content', 'high', 'The HTTPS page references resources over insecure HTTP.', `${mixed.length} resource(s)`);

  const externalScripts = [...document.scripts].filter(script => {
    if (!script.src) return false;
    try { return new URL(script.src).origin !== location.origin && !script.integrity; } catch { return false; }
  });
  if (externalScripts.length) add('live.external-script-integrity', 'Third-party scripts without integrity metadata', 'low', 'External scripts are loaded without Subresource Integrity. Confirm they are trusted and version-pinned.', `${externalScripts.length} script(s)`);

  return { title: document.title, findings };
}

async function responseFindings(url) {
  const findings = [];
  const response = await fetch(url, { method: 'GET', cache: 'no-store', credentials: 'omit', redirect: 'follow' });
  const headers = response.headers;
  const csp = headers.get('content-security-policy') || '';
  const add = (...args) => findings.push(makeFinding(...args));

  if (new URL(response.url).protocol !== 'https:') add('live.insecure-http', 'Website does not use HTTPS', 'high', 'Traffic can be intercepted or modified in transit.', response.url);
  if (!csp) add('live.missing-csp', 'Content Security Policy missing', 'medium', 'A CSP can reduce the impact of injected scripts and untrusted resources.');
  if (new URL(response.url).protocol === 'https:' && !headers.get('strict-transport-security')) add('live.missing-hsts', 'HSTS header missing', 'medium', 'HSTS instructs browsers to use HTTPS for future requests.');
  if (!headers.get('x-content-type-options')?.toLowerCase().includes('nosniff')) add('live.missing-nosniff', 'MIME sniffing protection missing', 'low', 'Set X-Content-Type-Options to nosniff.');
  if (!headers.get('x-frame-options') && !/frame-ancestors/i.test(csp)) add('live.frame-protection', 'Clickjacking protection not visible', 'medium', 'Use CSP frame-ancestors or X-Frame-Options to control embedding.');
  if (headers.get('access-control-allow-origin') === '*') add('live.permissive-cors', 'Permissive CORS response', 'medium', 'The response allows reads from any origin. Confirm that no sensitive data is exposed.');
  if (!headers.get('referrer-policy')) add('live.referrer-policy', 'Referrer Policy missing', 'low', 'Define a Referrer-Policy to limit URL information sent to other origins.');
  return { findings, finalUrl: response.url, status: response.status };
}

function normalizeLiveReport(url, findings, metadata) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  findings.forEach(finding => { counts[finding.severity] = (counts[finding.severity] || 0) + 1; });
  const penalty = findings.reduce((sum, finding) => sum + (severityPenalty[finding.severity] || 0), 0);
  const score = Math.max(0, 100 - Math.min(75, penalty));
  return { type: 'live', url, score, riskLevel: riskLevel(score), summary: { ...counts, total: findings.length }, findings, metadata, scannedAt: new Date().toISOString() };
}

function renderReport(report) {
  state.report = report;
  $('#report').hidden = false;
  $('#report-type').textContent = report.type === 'repository' ? 'Repository scan' : 'Live surface scan';
  $('#score').textContent = report.score;
  $('#risk').textContent = report.riskLevel;
  $('#total').textContent = report.summary.total;
  $('#high').textContent = (report.summary.critical || 0) + (report.summary.high || 0);
  $('#medium').textContent = report.summary.medium || 0;
  $('#low').textContent = report.summary.low || 0;
  $('#findings').innerHTML = report.findings.length ? report.findings.map(finding => `
    <article class="finding">
      <div class="finding-top"><h3></h3><span class="severity"></span></div>
      <p></p><code></code>
    </article>`).join('') : '<div class="empty">No issues detected by this scan mode.</div>';

  [...$('#findings').querySelectorAll('.finding')].forEach((card, index) => {
    const finding = report.findings[index];
    card.querySelector('h3').textContent = finding.title;
    card.querySelector('.severity').textContent = finding.severity;
    card.querySelector('p').textContent = finding.description || finding.remediation || 'Review this finding.';
    card.querySelector('code').textContent = finding.evidence || finding.file || finding.ruleId;
  });
}

async function scanLive() {
  const button = $('#scan-live');
  button.disabled = true;
  setStatus('Inspecting response headers and the active page…');
  try {
    const url = new URL(state.url);
    if (!['http:', 'https:'].includes(url.protocol)) throw new Error('Open a normal HTTP or HTTPS website first.');
    const [responseData, injection] = await Promise.all([
      responseFindings(state.url),
      chrome.scripting.executeScript({ target: { tabId: state.tab.id }, func: inspectDocument }),
    ]);
    const pageData = injection[0]?.result || { findings: [] };
    const domFindings = pageData.findings.map(item => makeFinding(item.ruleId, item.title, item.severity, item.description, item.evidence));
    renderReport(normalizeLiveReport(responseData.finalUrl, [...responseData.findings, ...domFindings], { status: responseData.status, title: pageData.title }));
    setStatus('Live surface analysis complete. Backend source code was not inspected.');
  } catch (error) {
    setStatus(error?.message || 'The live page could not be inspected.', true);
  } finally {
    button.disabled = false;
  }
}

async function scanRepository() {
  const repository = githubRepository(state.url);
  if (!repository) return;
  const button = $('#scan-repo');
  button.disabled = true;
  setStatus('Sending the public repository to the BreakSmith deterministic scanner…');
  try {
    const stored = await chrome.storage.local.get('apiUrl');
    const apiUrl = (stored.apiUrl || $('#api-url').value || 'http://localhost:3000').replace(/\/$/, '');
    const response = await fetch(`${apiUrl}/api/scan`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ repoUrl: repository }),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(payload.error || 'BreakSmith repository scan failed.');
    renderReport({ ...payload, type: 'repository' });
    setStatus(`Repository analysis complete: ${payload.scannedFiles} files scanned.`);
  } catch (error) {
    setStatus(`${error?.message || 'Repository scan unavailable'} Check the configured backend URL.`, true);
  } finally {
    button.disabled = false;
  }
}

async function initialize() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  state.tab = tab;
  state.url = tab?.url || '';
  $('#detected-url').textContent = state.url || 'No active website detected';
  $('#scan-repo').hidden = !githubRepository(state.url);
  const stored = await chrome.storage.local.get('apiUrl');
  if (stored.apiUrl) $('#api-url').value = stored.apiUrl;
}

$('#scan-live').addEventListener('click', scanLive);
$('#scan-repo').addEventListener('click', scanRepository);
$('#save-api').addEventListener('click', async () => {
  const value = $('#api-url').value.trim().replace(/\/$/, '');
  await chrome.storage.local.set({ apiUrl: value });
  setStatus('BreakSmith API URL saved locally in the extension.');
});
$('#export-report').addEventListener('click', () => {
  if (!state.report) return;
  const blob = new Blob([JSON.stringify(state.report, null, 2)], { type: 'application/json' });
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = `breaksmith-${state.report.type}-report.json`;
  link.click();
  URL.revokeObjectURL(link.href);
});

initialize().catch(error => setStatus(error?.message || 'Could not detect the active tab.', true));
