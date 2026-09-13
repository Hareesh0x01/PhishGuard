/**
 * PhishGuard — report.js
 * Reads scan data from chrome.storage.session and renders the full report.
 */

'use strict';

// ============================================================
//  SVG ICON HELPERS
// ============================================================
const verdictIcons = {
  safe: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none"
    stroke="#3fb950" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    <polyline points="9 12 11 14 15 10"/>
  </svg>`,
  warning: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none"
    stroke="#e3b341" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
    <line x1="12" y1="9" x2="12" y2="13"/>
    <line x1="12" y1="17" x2="12.01" y2="17"/>
  </svg>`,
  danger: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none"
    stroke="#f85149" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    <line x1="15" y1="9" x2="9" y2="15"/>
    <line x1="9" y1="9" x2="15" y2="15"/>
  </svg>`,
};

const verdictText = {
  safe:    { label: 'SAFE',              sub: 'No threats detected', color: '#3fb950' },
  warning: { label: 'SUSPICIOUS',        sub: 'Risk factors detected — proceed with caution', color: '#e3b341' },
  danger:  { label: 'THREAT DETECTED',   sub: 'Strong phishing / malware indicators found', color: '#f85149' },
};

// ============================================================
//  RENDER HELPERS
// ============================================================

/** Returns a severity badge <span> HTML string. */
function sevBadge(level) {
  const map = { safe: 'Safe', info: 'Info', warn: 'Warning', danger: 'Danger' };
  return `<span class="sev-badge sev-${level}">${map[level] || level}</span>`;
}

/** Returns a engine badge <span> HTML string. */
function engineBadge(status, label) {
  const cls = { clean: 'clean', threat: 'threat', warn: 'warn', error: 'error', nokey: 'nokey' }[status] || 'error';
  return `<span class="engine-card-badge badge-${cls}">${label}</span>`;
}

/** Populates a findings <tbody> from an array of {text, level} objects. */
function populateFindings(tbodyId, findings) {
  const tbody = document.getElementById(tbodyId);
  if (!tbody) return;
  tbody.innerHTML = '';
  if (!findings?.length) {
    tbody.innerHTML = '<tr><td colspan="2" style="color:var(--t3);font-style:italic;">No findings</td></tr>';
    return;
  }
  findings.forEach(({ text, level }) => {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${escHtml(text)}</td><td>${sevBadge(level)}</td>`;
    tbody.appendChild(tr);
  });
}

/** Renders the page-content signal summary cards. */
function renderSignalCards(signals) {
  const grid = document.getElementById('signals-grid');
  if (!grid || !signals) return;

  const cards = [
    { label: 'Password Fields', value: signals.passwordFields, bad: signals.passwordFields > 0 },
    { label: 'Forms',           value: signals.forms,          bad: false },
    { label: 'Iframes',         value: signals.iframeCount,    bad: signals.hiddenIframes > 0 },
    { label: 'Hidden Iframes',  value: signals.hiddenIframes,  bad: signals.hiddenIframes > 0 },
    { label: 'Ext. Scripts',    value: signals.externalScripts,bad: signals.externalScripts > 8 },
    { label: 'Link Mismatch',   value: signals.linkMismatch,   bad: signals.linkMismatch > 0 },
    { label: 'Meta Refresh',    value: signals.metaRefresh ? 'Yes' : 'No', bad: signals.metaRefresh },
    { label: 'Ext. Favicon',    value: signals.faviconExternal ? 'Yes' : 'No', bad: signals.faviconExternal },
  ];

  grid.innerHTML = cards.map(c => {
    const cls = c.bad ? 'bad' : (c.value === 0 || c.value === 'No' ? 'ok' : 'neu');
    return `<div class="signal-card">
      <div class="signal-card-label">${escHtml(c.label)}</div>
      <div class="signal-card-value ${cls}">${c.value}</div>
    </div>`;
  }).join('');
}

/** Sets an engine card's state. */
function setEngineCard(id, status, label, detail, meta) {
  const card = document.getElementById(`card-${id}`);
  if (card) {
    card.classList.remove('clean', 'threat', 'warn', 'nokey', 'error');
    const cls = { clean: 'clean', threat: 'threat', warn: 'warn', nokey: 'nokey', error: 'error' }[status];
    if (cls) card.classList.add(cls);
  }

  const badge = document.getElementById(`badge-${id}`);
  if (badge) badge.outerHTML = engineBadge(status, label);

  const det = document.getElementById(`detail-${id}`);
  if (det) det.textContent = detail || '';

  const met = document.getElementById(`meta-${id}`);
  if (met && meta) met.textContent = meta;
}

/** Simple HTML escaping. */
function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/** Formats an ISO timestamp to a readable local string. */
function fmtTime(iso) {
  try {
    return new Intl.DateTimeFormat(undefined, {
      dateStyle: 'medium', timeStyle: 'medium',
    }).format(new Date(iso));
  } catch { return iso; }
}

// ============================================================
//  MAIN RENDER
// ============================================================
function renderReport(data) {
  const {
    url, hostname, timestamp, finalScore, state,
    urlAnalysis, contentAnalysis, rawSignals, apiResults,
  } = data;

  // ── Verdict banner ─────────────────────────────────────────
  const banner = document.getElementById('verdict-banner');
  banner.className = `verdict-banner ${state}`;

  document.getElementById('verdict-icon').innerHTML = verdictIcons[state] || verdictIcons.safe;

  const vt = verdictText[state] || verdictText.safe;
  const vLabel = document.getElementById('verdict-label');
  const vSub   = document.getElementById('verdict-sub');
  vLabel.textContent = vt.label;
  vLabel.style.color = vt.color;
  vSub.textContent   = vt.sub;

  const vScore = document.getElementById('verdict-score');
  vScore.textContent = finalScore;
  vScore.style.color = vt.color;

  // ── Meta ───────────────────────────────────────────────────
  document.getElementById('report-url').textContent      = url;
  document.getElementById('report-url').title            = url;
  document.getElementById('report-hostname').textContent = hostname;
  document.getElementById('report-time').textContent     = fmtTime(timestamp);

  // ── Score bar ──────────────────────────────────────────────
  document.getElementById('score-badge').textContent     = `${finalScore} / 100`;
  document.getElementById('score-badge').style.color     = vt.color;
  document.getElementById('score-bar-fill').style.width  = `${finalScore}%`;
  document.getElementById('score-bar-marker').style.left = `${finalScore}%`;

  // ── Engine cards ───────────────────────────────────────────
  const uh = apiResults.urlhaus;
  setEngineCard('urlhaus', uh.status, uh.label, uh.detail,
    uh.ms ? `Response: ${uh.ms} ms` : 'No response');

  const pt = apiResults.phishtank;
  setEngineCard('phishtank', pt.status, pt.label, pt.detail,
    pt.ms ? `Response: ${pt.ms} ms` : (pt.status === 'nokey' ? 'Add key below to enable' : 'No response'));

  const sb = apiResults.safeBrowsing;
  setEngineCard('safebrowsing', sb.status, sb.label, sb.detail,
    sb.ms ? `Response: ${sb.ms} ms` : (sb.status === 'nokey' ? 'Add key below to enable' : 'No response'));

  // Heuristic engine card
  const hScore = Math.round(urlAnalysis.score * 0.6 + (contentAnalysis?.score || 0) * 0.4);
  const hStatus = hScore <= 25 ? 'clean' : hScore <= 55 ? 'warn' : 'threat';
  const hLabel  = hScore <= 25 ? 'Clean' : hScore <= 55 ? 'Suspicious' : 'Threat';
  setEngineCard('heuristic', hStatus, hLabel,
    `Heuristic score: ${hScore} / 100`,
    `${urlAnalysis.findings?.length || 0} URL checks + ${contentAnalysis?.findings?.length || 0} DOM checks`);

  // ── URL findings table ─────────────────────────────────────
  populateFindings('url-tbody', urlAnalysis.findings);

  // ── Page content signals ───────────────────────────────────
  renderSignalCards(rawSignals);
  populateFindings('page-tbody', contentAnalysis?.findings || []);

  // ── Show report ────────────────────────────────────────────
  document.getElementById('report-content').hidden = false;
  document.getElementById('no-data').hidden = true;
}

// ============================================================
//  API KEY CONFIGURATION
// ============================================================
async function loadStoredKeys() {
  const keys = await chrome.storage.sync.get(['phishtank_key', 'safebrowsing_key']).catch(() => ({}));
  const ptInput = document.getElementById('input-phishtank');
  const sbInput = document.getElementById('input-safebrowsing');
  if (ptInput && keys.phishtank_key)    ptInput.placeholder = '••••••••••••••••';
  if (sbInput && keys.safebrowsing_key) sbInput.placeholder = '••••••••••••••••';
}

function setupConfigSaveButtons() {
  document.querySelectorAll('.config-save-btn').forEach(btn => {
    btn.addEventListener('click', async () => {
      const storageKey = btn.dataset.key;
      const inputEl    = document.getElementById(btn.dataset.input);
      const statusEl   = document.getElementById(
        `status-${storageKey.replace('_key', '')}`
      );
      const val = inputEl?.value.trim();

      if (!val) {
        if (statusEl) { statusEl.textContent = 'Please enter a key.'; statusEl.className = 'config-status error'; }
        return;
      }
      try {
        await chrome.storage.sync.set({ [storageKey]: val });
        inputEl.value = '';
        inputEl.placeholder = '••••••••••••••••';
        if (statusEl) { statusEl.textContent = '✓ Key saved. Re-scan to activate.'; statusEl.className = 'config-status'; }
      } catch (e) {
        if (statusEl) { statusEl.textContent = `Error: ${e.message}`; statusEl.className = 'config-status error'; }
      }
    });
  });
}

// ============================================================
//  NAV BUTTON ACTIONS
// ============================================================
function setupNavButtons(reportData) {
  const copyBtn   = document.getElementById('copy-url-btn');
  const rescanBtn = document.getElementById('rescan-btn');

  if (copyBtn && reportData?.url) {
    copyBtn.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(reportData.url);
        copyBtn.textContent = '✓ Copied!';
        setTimeout(() => { copyBtn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg> Copy URL`; }, 2000);
      } catch { /* clipboard API not available */ }
    });
  }

  if (rescanBtn) {
    rescanBtn.addEventListener('click', () => window.close());
  }
}

// ============================================================
//  INIT
// ============================================================
(async function init() {
  try {
    const stored = await chrome.storage.session.get('phishguard_last_scan');
    const data   = stored?.phishguard_last_scan ?? null;

    if (data) {
      renderReport(data);
      setupNavButtons(data);
    } else {
      document.getElementById('no-data').hidden = false;
      document.getElementById('report-content').hidden = true;
    }

    await loadStoredKeys();
    setupConfigSaveButtons();
  } catch (err) {
    console.error('[PhishGuard Report] Error:', err);
    document.getElementById('no-data').hidden = false;
  }
})();
