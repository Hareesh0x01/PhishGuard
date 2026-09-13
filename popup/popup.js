/**
 * PhishGuard — popup.js
 *
 * Scan pipeline:
 *  1. URL Heuristics  (local, instant)
 *  2. Page DOM scan   (chrome.scripting injection)
 *  3. URLhaus API     (no key required)
 *  4. PhishTank API   (free key from storage)
 *  5. Safe Browsing   (free key from storage)
 *
 * All 5 checks run in parallel via Promise.allSettled.
 * Results are stored in chrome.storage.session for the report page.
 */

'use strict';

// ============================================================
//  DOM REFERENCES
// ============================================================
const scanBtn         = document.getElementById('scan-btn');
const scanBtnIcon     = document.getElementById('scan-btn-icon');
const scanBtnLabel    = document.getElementById('scan-btn-label');
const statusCard      = document.getElementById('status-card');
const statusTitle     = document.getElementById('status-title');
const statusMessage   = document.getElementById('status-message');
const statusIconWrap  = document.getElementById('status-icon-wrap');
const riskValue       = document.getElementById('risk-value');
const riskBarFill     = document.getElementById('risk-bar-fill');
const riskBarTrack    = document.querySelector('.risk-bar-track');
const currentUrlEl    = document.getElementById('current-url');
const findingsSection = document.getElementById('findings-section');
const findingsList    = document.getElementById('findings-list');
const enginesRow      = document.getElementById('engines-row');
const reportBtn       = document.getElementById('report-btn');

// ============================================================
//  SVG ICONS
// ============================================================
const ICONS = {
  idle: cls => `<svg class="status-icon ${cls}" xmlns="http://www.w3.org/2000/svg"
    viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
    stroke-linecap="round" stroke-linejoin="round">
    <circle cx="12" cy="12" r="10"/>
    <line x1="12" y1="8" x2="12" y2="12"/>
    <line x1="12" y1="16" x2="12.01" y2="16"/>
  </svg>`,

  scanning: cls => `<svg class="status-icon ${cls}" xmlns="http://www.w3.org/2000/svg"
    viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
    stroke-linecap="round" stroke-linejoin="round"
    style="animation:spin .9s linear infinite;">
    <path d="M21 12a9 9 0 1 1-6.219-8.56"/>
  </svg>`,

  safe: cls => `<svg class="status-icon ${cls}" xmlns="http://www.w3.org/2000/svg"
    viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
    stroke-linecap="round" stroke-linejoin="round">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    <polyline points="9 12 11 14 15 10"/>
  </svg>`,

  warning: cls => `<svg class="status-icon ${cls}" xmlns="http://www.w3.org/2000/svg"
    viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
    stroke-linecap="round" stroke-linejoin="round">
    <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
    <line x1="12" y1="9" x2="12" y2="13"/>
    <line x1="12" y1="17" x2="12.01" y2="17"/>
  </svg>`,

  danger: cls => `<svg class="status-icon ${cls}" xmlns="http://www.w3.org/2000/svg"
    viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
    stroke-linecap="round" stroke-linejoin="round">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    <line x1="15" y1="9" x2="9" y2="15"/>
    <line x1="9" y1="9" x2="15" y2="15"/>
  </svg>`,
};

// ============================================================
//  UI STATES
// ============================================================
const UI_STATES = {
  idle:       { cardClass: '',             iconKey: 'idle',    iconClass: 'idle',   title: 'Not Scanned',         message: 'Click <strong>Scan Now</strong> to analyse this page for threats.' },
  scanning:   { cardClass: '',             iconKey: 'scanning',iconClass: 'idle',   title: 'Scanning…',           message: 'Running URL heuristics &amp; querying threat databases.' },
  safe:       { cardClass: 'state-safe',   iconKey: 'safe',    iconClass: 'safe',   title: 'No Threats Detected', message: 'This website appears safe to browse.' },
  warning:    { cardClass: 'state-warning',iconKey: 'warning', iconClass: 'warn',   title: 'Suspicious Signals',  message: 'Proceed with caution — risk factors detected.' },
  danger:     { cardClass: 'state-danger', iconKey: 'danger',  iconClass: 'danger', title: 'Threat Detected!',    message: 'Strong phishing indicators found. <strong>Do not enter credentials.</strong>' },
  restricted: { cardClass: '',             iconKey: 'idle',    iconClass: 'idle',   title: 'Cannot Scan',         message: 'Browser-internal pages cannot be analysed.' },
};

// ============================================================
//  LAYER 1 — URL HEURISTICS
// ============================================================
function analyzeUrl(urlString) {
  const findings = [];
  let score = 0;

  let parsed;
  try { parsed = new URL(urlString); }
  catch { return { score: 30, findings: [{ text: 'Could not parse URL', level: 'warn' }] }; }

  const hostname = parsed.hostname.toLowerCase();
  const fullUrl  = urlString.toLowerCase();
  const parts    = hostname.split('.');
  const domain   = parts.slice(-2).join('.');
  const domainPart = parts[parts.length - 2] || '';

  // 1. HTTPS
  if (parsed.protocol === 'http:') {
    score += 20;
    findings.push({ text: 'No HTTPS — connection is unencrypted', level: 'danger' });
  } else {
    findings.push({ text: 'HTTPS is enabled', level: 'safe' });
  }

  // 2. IP as hostname
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
    score += 35;
    findings.push({ text: 'IP address used as hostname', level: 'danger' });
  }

  // 3. @ symbol
  if (fullUrl.includes('@')) {
    score += 30;
    findings.push({ text: 'URL contains @ (credential spoofing trick)', level: 'danger' });
  }

  // 4. Punycode / IDN
  if (hostname.includes('xn--')) {
    score += 20;
    findings.push({ text: 'Punycode / IDN domain — possible homograph attack', level: 'danger' });
  }

  // 5. Suspicious TLDs
  const badTlds = ['.tk','.ml','.ga','.cf','.gq','.xyz','.top','.work',
                   '.click','.link','.loan','.win','.download','.bid','.racing'];
  const tldHit = badTlds.find(t => hostname.endsWith(t));
  if (tldHit) {
    score += 15;
    findings.push({ text: `High-risk TLD: ${tldHit}`, level: 'warn' });
  }

  // 6. Excessive subdomains
  if (parts.length > 4) {
    score += 15;
    findings.push({ text: `Excessive subdomains (${parts.length - 2} levels)`, level: 'warn' });
  }

  // 7. Phishing keywords in domain
  const phishWords = ['login','signin','verify','secure','update','account','confirm',
                      'billing','support','recover','validate','credential','password','banking'];
  const foundWords = phishWords.filter(w => hostname.includes(w));
  if (foundWords.length) {
    score += Math.min(foundWords.length * 12, 36);
    findings.push({ text: `Phishing keywords in domain: ${foundWords.join(', ')}`, level: foundWords.length >= 2 ? 'danger' : 'warn' });
  }

  // 8. Brand typosquatting
  const brandTypos = {
    Google:    ['g00gle','gooogle','googel','gogle'],
    PayPal:    ['paypa1','paypai','pay-pal','paypall'],
    Microsoft: ['micros0ft','mircosoft','microsft'],
    Facebook:  ['faceb00k','facebok','faceboook'],
    Amazon:    ['arnazon','amazzon','am4zon','amaz0n'],
    Apple:     ['app1e','aple','aplle'],
    Netflix:   ['netfl1x','netfliix'],
    Twitter:   ['tw1tter','twltter','twiiter'],
  };
  for (const [brand, typos] of Object.entries(brandTypos)) {
    if (typos.some(t => hostname.includes(t))) {
      score += 45;
      findings.push({ text: `Possible ${brand} typosquatting`, level: 'danger' });
    }
  }

  // 9. Brand impersonated in subdomain
  const brands = ['google','facebook','amazon','microsoft','apple','paypal','netflix',
                  'instagram','twitter','linkedin','chase','wellsfargo','bankofamerica'];
  for (const brand of brands) {
    if (hostname.includes(brand) && !domain.startsWith(brand)) {
      score += 25;
      findings.push({ text: `"${brand}" used in subdomain (impersonation?)`, level: 'danger' });
      break;
    }
  }

  // 10. Hyphens
  const hyphens = (domainPart.match(/-/g) || []).length;
  if (hyphens >= 3) {
    score += 10;
    findings.push({ text: `Many hyphens in domain (${hyphens})`, level: 'warn' });
  }

  // 11. Digits in domain
  if (/[0-9]/.test(domainPart)) {
    score += 8;
    findings.push({ text: 'Digits in domain name (leet-speak substitution?)', level: 'info' });
  }

  // 12. Long URL
  if (fullUrl.length > 100) {
    score += 10;
    findings.push({ text: `Unusually long URL (${fullUrl.length} chars)`, level: 'info' });
  }

  // 13. Open redirect params
  const redirectParams = ['redirect=','url=','returnurl=','goto=','next=','return=','rurl='];
  const pathQ = (parsed.pathname + parsed.search).toLowerCase();
  const rHit = redirectParams.find(p => pathQ.includes(p));
  if (rHit) {
    score += 15;
    findings.push({ text: `Open redirect param: ${rHit}`, level: 'warn' });
  }

  // 14. Non-standard port
  if (parsed.port && !['80','443',''].includes(parsed.port)) {
    score += 15;
    findings.push({ text: `Non-standard port: :${parsed.port}`, level: 'warn' });
  }

  // 15. Double slash in path
  if (parsed.pathname.includes('//')) {
    score += 10;
    findings.push({ text: 'Double slashes in URL path (obfuscation?)', level: 'warn' });
  }

  if (!findings.some(f => f.level === 'danger' || f.level === 'warn')) {
    findings.push({ text: 'URL structure looks clean', level: 'safe' });
  }

  return { score: Math.min(score, 100), findings };
}

// ============================================================
//  LAYER 2 — PAGE CONTENT COLLECTOR (injected into page)
// ============================================================
function collectPageSignals() {
  /* global document, location, window */
  function countExt(els, attr) {
    return Array.from(els).filter(el => {
      try { return new URL(el[attr]).hostname !== location.hostname; } catch { return false; }
    }).length;
  }

  const passwordFields = document.querySelectorAll('input[type="password"]').length;
  const emailFields    = document.querySelectorAll(
    'input[type="email"],input[name*="email" i],input[name*="user" i],input[name*="phone" i]'
  ).length;
  const forms       = document.querySelectorAll('form').length;
  const allIframes  = document.querySelectorAll('iframe');
  const iframeCount = allIframes.length;
  const hiddenIframes = Array.from(allIframes).filter(f => {
    const s = window.getComputedStyle(f);
    return s.display === 'none' || s.visibility === 'hidden' || f.hasAttribute('hidden');
  }).length;

  const scriptEls      = document.querySelectorAll('script[src]');
  const externalScripts = countExt(scriptEls, 'src');
  const metaRefresh     = !!document.querySelector('meta[http-equiv="refresh" i]');

  let linkMismatch = 0;
  document.querySelectorAll('a[href]').forEach(a => {
    try {
      const t = a.textContent.trim();
      if (!t.startsWith('http')) return;
      if (new URL(t).hostname !== new URL(a.href).hostname) linkMismatch++;
    } catch { /* ignore */ }
  });

  const allLinks     = document.querySelectorAll('a[href]').length;
  const extLinks     = countExt(document.querySelectorAll('a[href]'), 'href');
  const extLinkRatio = allLinks > 0 ? extLinks / allLinks : 0;

  let faviconExternal = false;
  const fav = document.querySelector('link[rel~="icon"][href]');
  if (fav) {
    try { faviconExternal = new URL(fav.href).hostname !== location.hostname; } catch {}
  }

  const bodyOnload = document.body ? !!document.body.getAttribute('onload') : false;

  return {
    passwordFields, emailFields, forms,
    iframeCount, hiddenIframes, externalScripts,
    metaRefresh, linkMismatch, allLinks, extLinks, extLinkRatio,
    faviconExternal, bodyOnload, title: document.title || '',
  };
}

// ============================================================
//  LAYER 2 — PAGE CONTENT SCORER
// ============================================================
function scorePageSignals(s) {
  const findings = [];
  let score = 0;

  if (s.passwordFields > 0) {
    findings.push({ text: `Login form: ${s.passwordFields} password, ${s.emailFields} user/email field(s)`, level: 'info' });
  }
  if (s.hiddenIframes > 0) {
    score += 25;
    findings.push({ text: `${s.hiddenIframes} hidden iframe(s) detected`, level: 'danger' });
  } else if (s.iframeCount > 3) {
    score += 10;
    findings.push({ text: `High iframe count: ${s.iframeCount}`, level: 'warn' });
  }
  if (s.metaRefresh) {
    score += 15;
    findings.push({ text: 'Meta-refresh redirect present', level: 'warn' });
  }
  if (s.linkMismatch > 0) {
    score += Math.min(s.linkMismatch * 10, 30);
    findings.push({ text: `${s.linkMismatch} link(s) display different URL from actual href`, level: 'danger' });
  }
  if (s.externalScripts > 8) {
    score += 10;
    findings.push({ text: `High external script count: ${s.externalScripts}`, level: 'warn' });
  }
  if (s.faviconExternal) {
    score += 10;
    findings.push({ text: 'Favicon loaded from external domain', level: 'warn' });
  }
  if (s.extLinkRatio > 0.8 && s.allLinks > 5) {
    score += 8;
    findings.push({ text: `${Math.round(s.extLinkRatio * 100)}% of links point externally`, level: 'info' });
  }
  if (s.bodyOnload && s.forms > 0) {
    score += 10;
    findings.push({ text: 'body onload with forms present (auto-submit risk)', level: 'warn' });
  }
  if (!findings.some(f => f.level !== 'info')) {
    findings.push({ text: 'Page content appears normal', level: 'safe' });
  }

  return { score: Math.min(score, 100), findings };
}

// ============================================================
//  API LAYER — URLhaus (no key needed)
// ============================================================
async function checkURLhaus(url) {
  const t0 = Date.now();
  try {
    const res  = await fetch('https://urlhaus-api.abuse.ch/v1/url/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `url=${encodeURIComponent(url)}`,
    });
    const data = await res.json();
    const ms   = Date.now() - t0;

    if (data.query_status === 'is_malware') {
      return { status: 'threat', label: 'Malware', detail: data.threat || 'Malware distribution URL', raw: data, ms };
    }
    if (data.query_status === 'phishing') {
      return { status: 'threat', label: 'Phishing', detail: 'Phishing URL in URLhaus', raw: data, ms };
    }
    return { status: 'clean', label: 'Clean', detail: 'Not in URLhaus database', raw: data, ms };
  } catch (e) {
    return { status: 'error', label: 'Error', detail: e.message, raw: null, ms: Date.now() - t0 };
  }
}

// ============================================================
//  API LAYER — PhishTank (free key from storage)
// ============================================================
async function checkPhishTank(url, apiKey) {
  if (!apiKey) {
    return { status: 'nokey', label: 'No Key', detail: 'Configure PhishTank key in report settings', raw: null, ms: 0 };
  }
  const t0 = Date.now();
  try {
    const body = new URLSearchParams({ url, format: 'json', app_key: apiKey });
    const res  = await fetch('https://checkurl.phishtank.com/checkurl/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });
    const data = await res.json();
    const ms   = Date.now() - t0;

    if (data.results?.in_database) {
      if (data.results.valid) {
        return { status: 'threat', label: 'Phishing', detail: `Verified phishing (${data.results.verified_at || '?'})`, raw: data, ms };
      }
      return { status: 'warn', label: 'Disputed', detail: 'In database but not verified', raw: data, ms };
    }
    return { status: 'clean', label: 'Clean', detail: 'Not in PhishTank database', raw: data, ms };
  } catch (e) {
    return { status: 'error', label: 'Error', detail: e.message, raw: null, ms: Date.now() - t0 };
  }
}

// ============================================================
//  API LAYER — Google Safe Browsing (free key from storage)
// ============================================================
async function checkSafeBrowsing(url, apiKey) {
  if (!apiKey) {
    return { status: 'nokey', label: 'No Key', detail: 'Configure Safe Browsing key in report settings', raw: null, ms: 0 };
  }
  const t0 = Date.now();
  try {
    const res = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client: { clientId: 'phishguard', clientVersion: '1.0.0' },
          threatInfo: {
            threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
            platformTypes: ['ANY_PLATFORM'],
            threatEntryTypes: ['URL'],
            threatEntries: [{ url }],
          },
        }),
      }
    );
    const data = await res.json();
    const ms   = Date.now() - t0;

    if (data.matches?.length) {
      const types = [...new Set(data.matches.map(m => m.threatType))];
      return { status: 'threat', label: 'Threat', detail: types.join(', '), threats: data.matches, raw: data, ms };
    }
    return { status: 'clean', label: 'Clean', detail: 'No threats found', raw: data, ms };
  } catch (e) {
    return { status: 'error', label: 'Error', detail: e.message, raw: null, ms: Date.now() - t0 };
  }
}

// ============================================================
//  SCORE COMBINER
// ============================================================
function buildFinalScore(urlScore, contentScore, apiResults) {
  // Each API threat hit contributes extra score
  let apiScore = 0;
  if (apiResults.urlhaus.status    === 'threat') apiScore += 35;
  if (apiResults.phishtank.status  === 'threat') apiScore += 40;
  if (apiResults.safeBrowsing.status === 'threat') apiScore += 35;
  if (apiResults.phishtank.status  === 'warn')   apiScore += 15;
  apiScore = Math.min(apiScore, 55);

  const heuristic = Math.round(urlScore * 0.6 + contentScore * 0.4);
  let final = Math.round(heuristic * 0.6 + apiScore * 0.4);

  // Any confirmed API threat raises minimum to 65
  if (apiScore >= 35) final = Math.max(final, 65);

  return Math.min(100, Math.max(0, final));
}

function scoreToState(score) {
  if (score <= 25) return 'safe';
  if (score <= 55) return 'warning';
  return 'danger';
}

// ============================================================
//  UI HELPERS
// ============================================================
function applyUIState(name) {
  const s = UI_STATES[name];
  if (!s) return;
  statusCard.className = 'status-card' + (s.cardClass ? ` ${s.cardClass}` : '');
  statusIconWrap.innerHTML = ICONS[s.iconKey](s.iconClass);
  statusTitle.textContent  = s.title;
  statusMessage.innerHTML  = s.message;
}

function updateRiskScore(score) {
  if (score === null) {
    riskValue.textContent = '—';
    riskBarFill.style.width = '0%';
    riskBarTrack.setAttribute('aria-valuenow', 0);
    return;
  }
  const c = Math.max(0, Math.min(100, score));
  riskValue.textContent   = `${c} / 100`;
  riskBarFill.style.width = `${c}%`;
  riskBarTrack.setAttribute('aria-valuenow', c);
}

function renderFindings(all) {
  findingsList.innerHTML = '';
  if (!all?.length) { findingsSection.hidden = true; return; }
  all.forEach(({ text, level }) => {
    const li  = document.createElement('li');
    li.className = `finding-item level-${level}`;
    const dot = document.createElement('span');
    dot.className = 'finding-dot';
    const msg = document.createElement('span');
    msg.textContent = text;
    li.append(dot, msg);
    findingsList.appendChild(li);
  });
  findingsSection.hidden = false;
}

/**
 * Updates one engine chip's dot colour + label.
 * @param {'urlhaus'|'phishtank'|'safebrowsing'} engineId
 * @param {'clean'|'threat'|'warn'|'error'|'nokey'} status
 * @param {string} label
 */
function updateEngineChip(engineId, status, label) {
  const dot = document.getElementById(`dot-${engineId}`);
  const val = document.getElementById(`val-${engineId}`);
  if (!dot || !val) return;

  dot.className = 'engine-dot';
  if (status === 'clean')  dot.classList.add('clean');
  else if (status === 'threat') dot.classList.add('threat');
  else if (status === 'warn')   dot.classList.add('warn');
  else if (status === 'error')  dot.classList.add('error');
  else                          dot.classList.add('nokey');

  val.textContent = label;
}

function setScanBtnState(scanning) {
  scanBtn.disabled = scanning;
  scanBtn.classList.toggle('scanning', scanning);
  scanBtnLabel.textContent = scanning ? 'Scanning…' : 'Scan Now';
}

// ============================================================
//  CONTENT INJECTION WRAPPER
// ============================================================
async function injectContentAnalyzer(tabId) {
  try {
    const result = await chrome.scripting.executeScript({
      target: { tabId },
      func:   collectPageSignals,
    });
    return result?.[0]?.result ?? null;
  } catch (err) {
    console.warn('[PhishGuard] Injection failed:', err.message);
    return null;
  }
}

// ============================================================
//  CURRENT TAB HELPERS
// ============================================================
async function getActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab || null;
}

function displayUrl(fullUrl) {
  if (!fullUrl) { currentUrlEl.textContent = 'Unable to read URL'; return; }
  try {
    currentUrlEl.textContent = new URL(fullUrl).hostname;
    currentUrlEl.title = fullUrl;
  } catch {
    currentUrlEl.textContent = fullUrl;
  }
}

// ============================================================
//  MAIN SCAN ORCHESTRATION
// ============================================================
async function runScan() {
  // ── Reset UI ──────────────────────────────────────────────
  setScanBtnState(true);
  reportBtn.hidden = true;
  enginesRow.hidden = true;
  applyUIState('scanning');
  updateRiskScore(null);
  renderFindings([]);

  // ── Get tab ───────────────────────────────────────────────
  const tab = await getActiveTab();
  const fullUrl = tab?.url ?? null;
  displayUrl(fullUrl);

  // Reject non-http(s) pages
  const scheme = (fullUrl || '').split(':')[0].toLowerCase();
  if (!fullUrl || !['http', 'https'].includes(scheme)) {
    applyUIState('restricted');
    setScanBtnState(false);
    return;
  }

  // ── Load stored API keys ──────────────────────────────────
  const keys = await chrome.storage.sync.get(['phishtank_key', 'safebrowsing_key']).catch(() => ({}));

  // ── Run all checks in parallel ────────────────────────────
  const [urlR, sigR, uhR, ptR, sbR] = await Promise.allSettled([
    Promise.resolve(analyzeUrl(fullUrl)),                           // URL heuristics
    injectContentAnalyzer(tab.id),                                  // DOM signals
    checkURLhaus(fullUrl),                                          // URLhaus
    checkPhishTank(fullUrl, keys.phishtank_key),                   // PhishTank
    checkSafeBrowsing(fullUrl, keys.safebrowsing_key),             // Safe Browsing
  ]);

  // ── Unwrap results ────────────────────────────────────────
  const urlAnalysis     = urlR.status === 'fulfilled' ? urlR.value : { score: 0, findings: [] };
  const rawSignals      = sigR.status === 'fulfilled' ? sigR.value : null;
  const contentAnalysis = rawSignals
    ? scorePageSignals(rawSignals)
    : { score: 0, findings: [{ text: 'Page content scan unavailable', level: 'info' }] };

  const apiResults = {
    urlhaus:     uhR.status === 'fulfilled' ? uhR.value : { status: 'error', label: 'Error', detail: 'Request failed', ms: 0 },
    phishtank:   ptR.status === 'fulfilled' ? ptR.value : { status: 'error', label: 'Error', detail: 'Request failed', ms: 0 },
    safeBrowsing: sbR.status === 'fulfilled' ? sbR.value : { status: 'error', label: 'Error', detail: 'Request failed', ms: 0 },
  };

  // ── Calculate score ───────────────────────────────────────
  const finalScore = buildFinalScore(urlAnalysis.score, contentAnalysis.score, apiResults);
  const stateName  = scoreToState(finalScore);

  // ── Store full report for report.html ─────────────────────
  const report = {
    url: fullUrl,
    hostname: new URL(fullUrl).hostname,
    timestamp: new Date().toISOString(),
    finalScore,
    state: stateName,
    urlAnalysis,
    contentAnalysis,
    rawSignals,
    apiResults,
  };
  chrome.storage.session.set({ phishguard_last_scan: report }).catch(() => {});

  // ── Update UI ─────────────────────────────────────────────
  applyUIState(stateName);
  updateRiskScore(finalScore);
  renderFindings([...urlAnalysis.findings, ...contentAnalysis.findings]);

  // Engine chips
  updateEngineChip('urlhaus',     apiResults.urlhaus.status,     apiResults.urlhaus.label);
  updateEngineChip('phishtank',   apiResults.phishtank.status,   apiResults.phishtank.label);
  updateEngineChip('safebrowsing',apiResults.safeBrowsing.status,apiResults.safeBrowsing.label);
  enginesRow.hidden = false;

  // Report button
  reportBtn.hidden = false;
  setScanBtnState(false);
}

// ============================================================
//  EVENT LISTENERS
// ============================================================
scanBtn.addEventListener('click', runScan);

reportBtn.addEventListener('click', () => {
  chrome.tabs.create({ url: chrome.runtime.getURL('report/report.html') });
});

// ============================================================
//  INIT
// ============================================================
(async function init() {
  applyUIState('idle');
  updateRiskScore(null);
  const tab = await getActiveTab();
  displayUrl(tab?.url ?? null);
})();
