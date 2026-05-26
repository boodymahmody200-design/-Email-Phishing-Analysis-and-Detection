/* ============================================================
   X-Ray Analyzer — Core Utilities & API Helpers
   js/core.js
   ============================================================ */

'use strict';

// Brand: Cyber X-Ray

// ═══════════════════════════════════════════════════════════
// CONFIG
// ═══════════════════════════════════════════════════════════
const CONFIG = {
  VT_API_KEY: '7e2ca33ee2cd53947bf74e35b4a261e2cbff594949c33fcf5977a13e0d66b13d',
  SCREENSHOT_KEY: 'key=4baabf',
  GEMINI_MODEL: 'gemini-2.0-flash',
  GEMINI_API_KEY: 'AIzaSyDs-0BLkpN2_hXRFb7Q0SV7_dhILptcqtQ',
};

// ═══════════════════════════════════════════════════════════
// NAVIGATION
// ═══════════════════════════════════════════════════════════
const XRay = {
  currentPage: null,
  navigate(page) {
    // Update nav active state
    document.querySelectorAll('.nav-item').forEach(el =>
      el.classList.toggle('active', el.dataset.page === page));
    // Show/hide pages
    document.querySelectorAll('.pg').forEach(el =>
      el.style.display = el.id === 'pg-' + page ? 'block' : 'none');
    this.currentPage = page;
    // Update topbar title
    const titles = {
      dashboard:   'Dashboard',
      url:         'Full Website Scan',
      email:       'Email Header Analyzer',
      whois:       'Who Owns This Domain?',
      dns:         'DNS Records Lookup',
      geo:         'Trace Server Location',
      ssl:         'SSL Certificate Check',
      virustotal:  'Virus & Blacklist Check',
      screenshot:  'Safe Site Preview',
      network:     'Network & Subdomains',
    };
    const titleEl = document.getElementById('topbar-title');
    if (titleEl) titleEl.textContent = titles[page] || 'Cyber X-Ray';
    // Update mobile topbar title
    const mobileTitle = document.getElementById('mobile-page-title');
    if (mobileTitle) mobileTitle.textContent = titles[page] || 'Cyber X-Ray';
    // Auto-close sidebar on mobile
    if (window.innerWidth < 768) {
      const sb  = document.getElementById('sidebar');
      const ov  = document.getElementById('sidebar-overlay');
      if (sb) sb.classList.remove('open');
      if (ov) ov.classList.remove('open');
      document.body.style.overflow = '';
    }
    // Scroll content to top on navigation
    const content = document.querySelector('.content');
    if (content) content.scrollTop = 0;
    window.scrollTo(0, 0);
  }
};

// ═══════════════════════════════════════════════════════════
// RENDER HELPERS
// ═══════════════════════════════════════════════════════════
function renderLoading(msg = 'Analyzing…') {
  return `<div class="loading"><div class="spinner"></div><span>${msg}</span></div>`;
}

function renderError(msg) {
  return `<div class="flags" style="margin-top:8px">${renderFlag('danger', msg)}</div>`;
}

function renderEmpty(msg = 'Enter a value above and click Analyze to see results.') {
  return `<div class="empty-state">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    </svg><div>${msg}</div></div>`;
}

function renderFlag(level, text) {
  const icons = {
    danger:  `<circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>`,
    warning: `<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>`,
    safe:    `<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>`,
    info:    `<circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/>`,
  };
  return `<div class="flag flag-${level}">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
         stroke-linecap="round" stroke-linejoin="round"
         style="width:15px;height:15px;flex-shrink:0;margin-top:2px">
      ${icons[level] || icons.info}
    </svg><span>${text}</span></div>`;
}

function renderVerdictBanner(verdict, summary) {
  const v   = (verdict || '').toUpperCase();
  const cls = v === 'SAFE' ? 'safe' : v === 'DANGEROUS' || v === 'MALICIOUS' ? 'danger' : 'warning';
  const icon = v === 'SAFE'
    ? `<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/>`
    : (v === 'DANGEROUS' || v === 'MALICIOUS')
    ? `<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>`
    : `<circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>`;
  const color = v === 'SAFE' ? 'var(--safe)' : (v === 'DANGEROUS' || v === 'MALICIOUS') ? 'var(--danger)' : 'var(--warning)';
  const dispVerdict = v === 'DANGEROUS' ? 'MALICIOUS' : v;
  return `<div class="verdict-banner ${cls} fade-in">
    <svg viewBox="0 0 24 24" fill="none" stroke="${color}" stroke-width="2"
         stroke-linecap="round" stroke-linejoin="round">${icon}</svg>
    <div>
      <div class="verdict-label">${dispVerdict || 'UNKNOWN'}</div>
      <div class="verdict-sub">${summary || ''}</div>
    </div></div>`;
}

function renderTable(rows) {
  const trs = rows.map(([k, v]) =>
    `<tr><td>${k}</td><td>${v ?? '<span class="text-muted">—</span>'}</td></tr>`
  ).join('');
  return `<table class="data-table"><tbody>${trs}</tbody></table>`;
}

function formatDate(val) {
  if (!val || val === '—') return '—';
  try {
    const d = Array.isArray(val) ? new Date(val[0]) : new Date(val);
    if (isNaN(d.getTime())) return String(val);
    return d.toLocaleDateString('en-GB', { year:'numeric', month:'short', day:'2-digit' });
  } catch { return String(val); }
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ═══════════════════════════════════════════════════════════
// DOMAIN / IP UTILITIES
// ═══════════════════════════════════════════════════════════
function extractDomain(input) {
  try {
    const u = /^https?:\/\//i.test(input) ? input : 'https://' + input;
    return new URL(u).hostname.replace(/^www\./i, '');
  } catch {
    return input.trim().replace(/^www\./i, '').split('/')[0].split('?')[0];
  }
}

function normalizeURL(input) {
  return /^https?:\/\//i.test(input) ? input : 'https://' + input;
}

function getFlagEmoji(code) {
  if (!code || code.length !== 2) return '';
  try {
    return String.fromCodePoint(
      ...[...code.toUpperCase()].map(c => 0x1F1E6 - 65 + c.charCodeAt(0))
    );
  } catch { return ''; }
}

// ═══════════════════════════════════════════════════════════
// API: WHOIS
// ═══════════════════════════════════════════════════════════
async function fetchWHOIS(domain) {
  // Helper: extract value from vCard array by field name
  const getVcard = (arr, key) => {
    if (!Array.isArray(arr)) return '—';
    for (const e of arr) {
      if (Array.isArray(e) && e[0] === key) {
        const val = e[3];
        if (!val || val === '') return '—';
        if (typeof val === 'object' && val.type) return JSON.stringify(val);
        return String(val);
      }
    }
    return '—';
  };

  // Helper: get all entities of a role
  const getEntities = (entities, role) =>
    (entities || []).filter(e => (e.roles||[]).includes(role));

  // Helper: extract abuse email from entity remarks/links
  const getAbuseEmail = (entity) => {
    const vc = entity?.vcardArray?.[1] || [];
    return getVcard(vc, 'email');
  };

  // Helper: extract phone from vcard
  const getPhone = (vc) => {
    for (const e of vc) {
      if (Array.isArray(e) && e[0] === 'tel') return e[3] || '—';
    }
    return '—';
  };

  // Helper: extract address from vcard adr field
  const getAddress = (vc) => {
    for (const e of vc) {
      if (Array.isArray(e) && e[0] === 'adr') {
        const parts = e[3];
        if (Array.isArray(parts)) return parts.filter(Boolean).join(', ');
        return String(parts || '—');
      }
    }
    return '—';
  };

  try {
    const r = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`,
      { signal: AbortSignal.timeout(12000) });
    if (r.ok) {
      const d = await r.json();

      // ── Registrar ──
      const registrarEnts = getEntities(d.entities, 'registrar');
      const registrar     = registrarEnts[0];
      const registrarVc   = registrar?.vcardArray?.[1] || [];
      const registrarName = getVcard(registrarVc, 'fn') !== '—'
        ? getVcard(registrarVc, 'fn')
        : (registrar?.publicIds?.[0]?.identifier || registrar?.handle || '—');
      const registrarUrl  = (registrar?.links||[]).find(l=>l.rel==='self')?.href || '—';
      const registrarIANA = registrar?.publicIds?.find(p=>p.type==='IANA Registrar ID')?.identifier || '—';

      // ── Registrant (may be nested inside registrar entity) ──
      let registrantEnt = getEntities(d.entities, 'registrant')[0];
      if (!registrantEnt && registrar) {
        registrantEnt = getEntities(registrar.entities || [], 'registrant')[0]
          || getEntities(registrar.entities || [], 'administrative')[0];
      }
      const registrantVc      = registrantEnt?.vcardArray?.[1] || [];
      const registrantName    = getVcard(registrantVc, 'fn');
      const registrantOrg     = getVcard(registrantVc, 'org');
      const registrantEmail   = getVcard(registrantVc, 'email');
      const registrantPhone   = getPhone(registrantVc);
      const registrantAddress = getAddress(registrantVc);
      const registrantCountry = (() => {
        for (const e of registrantVc) {
          if (Array.isArray(e) && e[0] === 'adr') {
            const v = e[3];
            if (Array.isArray(v)) return v[6] || v[5] || '—';
          }
        }
        return '—';
      })();

      // ── Technical / Admin contacts ──
      const techEnt  = getEntities(d.entities, 'technical')[0]
        || getEntities(registrar?.entities||[], 'technical')[0];
      const adminEnt = getEntities(d.entities, 'administrative')[0]
        || getEntities(registrar?.entities||[], 'administrative')[0];
      const abuseEnt = getEntities(d.entities, 'abuse')[0]
        || getEntities(registrar?.entities||[], 'abuse')[0];

      const techVc  = techEnt?.vcardArray?.[1]  || [];
      const adminVc = adminEnt?.vcardArray?.[1] || [];
      const abuseVc = abuseEnt?.vcardArray?.[1] || [];

      return {
        domain:      d.ldhName || domain,
        // Registrar info
        registrarName,
        registrarUrl,
        registrarIANA,
        registrarAbuseEmail: getAbuseEmail(abuseEnt) !== '—' ? getAbuseEmail(abuseEnt) : getVcard(abuseVc, 'email'),
        registrarAbusePhone: getPhone(abuseVc),
        // Dates
        created:  (d.events||[]).find(e=>e.eventAction==='registration')?.eventDate || '—',
        expires:  (d.events||[]).find(e=>e.eventAction==='expiration')?.eventDate   || '—',
        updated:  (d.events||[]).find(e=>e.eventAction==='last changed')?.eventDate
               || (d.events||[]).find(e=>e.eventAction==='last update of RDAP database')?.eventDate || '—',
        // Registrant contact
        registrantName,
        registrantOrg,
        registrantEmail,
        registrantPhone,
        registrantAddress,
        registrantCountry,
        // Tech / admin
        techName:  getVcard(techVc,  'fn'),
        techEmail: getVcard(techVc,  'email'),
        adminName: getVcard(adminVc, 'fn'),
        adminEmail:getVcard(adminVc, 'email'),
        // Domain info
        nameservers: (d.nameservers||[]).map(n=>n.ldhName||n.unicodeName).filter(Boolean).join('\n') || '—',
        status: (Array.isArray(d.status) ? d.status : [d.status||'—']).filter(Boolean).join(', '),
        dnssec: d.secureDNS?.delegationSigned ? 'Signed' : 'Unsigned',
        source: 'RDAP (rdap.org)',
        // Legacy compat
        registrar:  registrarName,
        owner:      registrantName,
        email:      registrantEmail,
        country:    registrantCountry,
      };
    }
  } catch(_) {}

  try {
    const r = await fetch(`https://rdap.iana.org/domain/${encodeURIComponent(domain)}`,
      { signal: AbortSignal.timeout(8000) });
    if (r.ok) {
      const d = await r.json();
      return {
        domain:   d.ldhName || domain,
        registrarName: 'See registrar RDAP',
        registrar:'See registrar RDAP',
        created:  (d.events||[]).find(e=>e.eventAction==='registration')?.eventDate || '—',
        expires:  (d.events||[]).find(e=>e.eventAction==='expiration')?.eventDate   || '—',
        updated:  '—',
        registrantName:'—', registrantOrg:'—', registrantEmail:'—',
        registrantPhone:'—', registrantAddress:'—', registrantCountry:'—',
        nameservers:(d.nameservers||[]).map(n=>n.ldhName).filter(Boolean).join('\n')||'—',
        status:   Array.isArray(d.status)?d.status.join(', '):(d.status||'—'),
        dnssec:   d.secureDNS?.delegationSigned ? 'Signed' : 'Unsigned',
        source:   'RDAP (IANA)'
      };
    }
  } catch(_) {}

  throw new Error(`WHOIS lookup failed for "${domain}". Try again in 30 seconds.`);
}

// ═══════════════════════════════════════════════════════════
// API: DNS
// ═══════════════════════════════════════════════════════════
async function fetchDNS(domain, type = 'A') {
  const res = await fetch(
    `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${encodeURIComponent(type)}`,
    { headers: { Accept: 'application/dns-json' }, signal: AbortSignal.timeout(8000) }
  );
  if (!res.ok) throw new Error(`DNS query failed (HTTP ${res.status})`);
  return res.json();
}

// ═══════════════════════════════════════════════════════════
// API: IP GEOLOCATION
// ═══════════════════════════════════════════════════════════
async function fetchGeo(ip) {
  try {
    const r = await fetch(`https://ipapi.co/${encodeURIComponent(ip)}/json/`,
      { signal: AbortSignal.timeout(8000) });
    if (r.ok) {
      const d = await r.json();
      if (!d.error && d.latitude) {
        return {
          status: 'success', query: d.ip || ip,
          country: d.country_name || '—', countryCode: d.country_code || '',
          regionName: d.region || '—', city: d.city || '—',
          lat: d.latitude, lon: d.longitude,
          isp: d.org || '—', org: d.org || '—', as: d.asn || '—',
          proxy: false, hosting: false
        };
      }
    }
  } catch(_) {}

  try {
    const r = await fetch(`https://freeipapi.com/api/json/${encodeURIComponent(ip)}`,
      { signal: AbortSignal.timeout(8000) });
    if (r.ok) {
      const d = await r.json();
      if (d.latitude) {
        return {
          status: 'success', query: d.ipAddress || ip,
          country: d.countryName || '—', countryCode: d.countryCode || '',
          regionName: d.regionName || '—', city: d.cityName || '—',
          lat: d.latitude, lon: d.longitude,
          isp: d.isp || '—', org: d.isp || '—', as: '—',
          proxy: false, hosting: false
        };
      }
    }
  } catch(_) {}

  throw new Error(`Could not geolocate IP "${ip}". The IP may be private or the service is rate-limited.`);
}

// ═══════════════════════════════════════════════════════════
// API: SSL LABS
// ═══════════════════════════════════════════════════════════
async function fetchSSLStart(domain) {
  const cleanDomain = domain.replace(/^https?:\/\//i, '').split('/')[0];
  const r = await fetch(
    `https://api.ssllabs.com/api/v3/analyze?host=${encodeURIComponent(cleanDomain)}&startNew=on&all=done`,
    { signal: AbortSignal.timeout(15000) }
  );
  if (!r.ok) throw new Error(`SSL Labs error (HTTP ${r.status}) — try again in a few minutes`);
  return r.json();
}

async function fetchSSLPoll(domain) {
  const cleanDomain = domain.replace(/^https?:\/\//i, '').split('/')[0];
  const r = await fetch(
    `https://api.ssllabs.com/api/v3/analyze?host=${encodeURIComponent(cleanDomain)}&all=done`,
    { signal: AbortSignal.timeout(15000) }
  );
  if (!r.ok) throw new Error(`SSL Labs poll error (HTTP ${r.status})`);
  return r.json();
}

// ═══════════════════════════════════════════════════════════
// API: VIRUSTOTAL (hardcoded key)
// ═══════════════════════════════════════════════════════════
async function fetchVirusTotal(urlOrDomain) {
  const apiKey = CONFIG.VT_API_KEY;
  const normalized = normalizeURL(urlOrDomain);
  const id = btoa(normalized)
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

  const getRes = await fetch(
    `https://www.virustotal.com/api/v3/urls/${id}`,
    { headers: { 'x-apikey': apiKey }, signal: AbortSignal.timeout(15000) }
  );
  if (getRes.ok) return getRes.json();
  if (getRes.status === 401) throw new Error('VirusTotal API key is invalid.');
  if (getRes.status === 429) throw new Error('VirusTotal rate limit reached. Wait 60 seconds.');

  const form = new FormData();
  form.append('url', normalized);
  const subRes = await fetch('https://sweet-brook-a95f.boodymahmody200.workers.dev/.dev/api/virustotal' ,{
// (مع وضع مسار الطلب الصحيح حسب ما برمجت الـ Worker), {
    method: 'POST', headers: { 'x-apikey': apiKey }, body: form,
    signal: AbortSignal.timeout(15000)
  });
  if (!subRes.ok) {
    const err = await subRes.json().catch(() => ({}));
    throw new Error(err?.error?.message || `VirusTotal submission failed (HTTP ${subRes.status})`);
  }
  const subJson = await subRes.json();
  const analysisId = subJson?.data?.id;
  if (!analysisId) throw new Error('VirusTotal did not return an analysis ID.');

  for (let i = 0; i < 10; i++) {
    await sleep(4000);
    const anRes = await fetch(
      `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
      { headers: { 'x-apikey': apiKey }, signal: AbortSignal.timeout(10000) }
    );
    if (anRes.ok) {
      const anData = await anRes.json();
      if (anData?.data?.attributes?.status === 'completed') return anData;
    }
  }
  throw new Error('VirusTotal scan timed out. Try again.');
}

// ═══════════════════════════════════════════════════════════
// API: VIRUSTOTAL — IP Reputation
// ═══════════════════════════════════════════════════════════
async function fetchVTIP(ip) {
  const apiKey = CONFIG.VT_API_KEY;
  if (!ip || !/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) throw new Error('Invalid IP address');
  // Skip private/loopback IPs
  if (/^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.)/.test(ip)) throw new Error('Private IP — not checked');
  const res = await fetch(
    `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(ip)}`,
    { headers: { 'x-apikey': apiKey }, signal: AbortSignal.timeout(12000) }
  );
  if (!res.ok) {
    if (res.status === 401) throw new Error('VT API key invalid');
    if (res.status === 429) throw new Error('VT rate limit — wait 60s');
    throw new Error(`VT IP check failed (HTTP ${res.status})`);
  }
  return res.json();
}

// ═══════════════════════════════════════════════════════════
// API: SCREENSHOT (ScreenshotMachine with key)
// ═══════════════════════════════════════════════════════════
function getScreenshotUrls(url) {
  const encoded = encodeURIComponent(normalizeURL(url));
  return [
    `https://api.screenshotmachine.com/?${CONFIG.SCREENSHOT_KEY}&url=${encoded}&dimension=1280x800&format=png&cacheLimit=0`,
    `https://image.thum.io/get/width/1280/crop/800/noanimate/${normalizeURL(url)}`,
    `https://mini.s-shot.ru/1280x800/PNG/1280/Z100/?${normalizeURL(url)}`,
  ];
}

// ═══════════════════════════════════════════════════════════
// API: GEMINI AI ANALYSIS
// ═══════════════════════════════════════════════════════════
async function fetchAIAnalysis(type, content) {
  const labels = {
    email:   'email (including headers, sender, subject, and body)',
    url:     'URL or link',
    message: 'text message, SMS, or WhatsApp message'
  };

  const prompt = `You are a senior cybersecurity analyst specializing in phishing and social engineering detection.
Analyze this ${labels[type] || type} and return a structured assessment.

Content:
"""
${content}
"""

Reply ONLY with a single valid JSON object. No markdown, no backticks, no explanation outside JSON:
{
  "verdict": "SAFE",
  "confidence": "high",
  "risk_score": 10,
  "summary": "One clear sentence verdict written for a non-technical user",
  "flags": [
    {"level": "safe", "text": "Specific finding in plain language"}
  ],
  "indicators": {
    "urgency_language": false,
    "suspicious_links": false,
    "spoofed_sender": false,
    "credential_request": false,
    "grammar_errors": false,
    "reward_bait": false
  },
  "advice": "One actionable recommendation in plain language"
}

Rules:
- verdict: exactly SAFE, SUSPICIOUS, or MALICIOUS
- risk_score: integer 0–100
- flags: 2–5 items, level must be danger/warning/safe/info
- Write for a non-technical audience — no jargon
- Be specific to the actual content provided`;

  const res = await fetch(
    `https://generativelanguage.googleapis.com/v1beta/models/${CONFIG.GEMINI_MODEL}:generateContent?key=${CONFIG.GEMINI_API_KEY}`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: { maxOutputTokens: 1024, temperature: 0.2 }
      }),
      signal: AbortSignal.timeout(30000)
    }
  );

  if (!res.ok) {
    // Gemini failed — fall back to Anthropic API silently
    return await fetchAIAnalysisFallback(prompt);
  }

  const data = await res.json();
  const raw = data?.candidates?.[0]?.content?.parts?.[0]?.text || '';
  const clean = raw.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/i, '').trim();

  try {
    return JSON.parse(clean);
  } catch (_) {
    const m = clean.match(/\{[\s\S]*\}/);
    if (m) {
      try { return JSON.parse(m[0]); } catch(_) {}
    }
    throw new Error('AI returned an unexpected response. Please try again.');
  }
}

// Fallback to Anthropic API if Gemini fails
async function fetchAIAnalysisFallback(prompt) {
  const res = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 1024,
      messages: [{ role: 'user', content: prompt }]
    }),
    signal: AbortSignal.timeout(30000)
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err?.error?.message || `AI API error (HTTP ${res.status})`);
  }

  const data  = await res.json();
  const raw   = (data.content || []).map(b => b.text || '').join('').trim();
  const clean = raw.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/i, '').trim();

  try {
    return JSON.parse(clean);
  } catch (_) {
    const m = clean.match(/\{[\s\S]*\}/);
    if (m) {
      try { return JSON.parse(m[0]); } catch(_) {}
    }
    throw new Error('AI returned an unexpected response. Please try again.');
  }
}

// ═══════════════════════════════════════════════════════════
// MAP RENDERER
// ═══════════════════════════════════════════════════════════
function renderLeafletMap(elId, lat, lon, label, ip) {
  const el = document.getElementById(elId);
  if (!el || typeof L === 'undefined') return;
  try {
    const map = L.map(elId, { zoomControl: true }).setView([lat, lon], 8);
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
      attribution: '© OpenStreetMap © CARTO', maxZoom: 18
    }).addTo(map);
    const icon = L.divIcon({
      html: `<div style="background:#f75a5a;width:14px;height:14px;border-radius:50%;border:2px solid #fff;box-shadow:0 0 12px rgba(247,90,90,0.9)"></div>`,
      iconSize: [14,14], iconAnchor: [7,7], className: ''
    });
    L.marker([lat, lon], { icon }).addTo(map)
      .bindPopup(`<b style="color:#111">${ip}</b><br><span style="color:#444">${label}</span>`, { maxWidth: 200 })
      .openPopup();
  } catch(e) { console.warn('Map render error:', e); }
}
