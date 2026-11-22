// Whatnot -> ntfy :: background service worker.
// Receives normalized sale events from content scripts and POSTs them to the
// configured ntfy topic. Sends are serialized with a small delay so a burst
// of sales doesn't hammer ntfy.
'use strict';

const DEFAULTS = {
  enabled: true,
  server: 'https://ntfy.sh',
  topic: '',
  token: '',
  priority: '4',
  minPrice: 0,
  domDetect: true,
  netDetect: true
};

const queue = [];
let draining = false;
let sentCount = 0;

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (!msg || typeof msg !== 'object') return;
  if (msg.type === 'SALE' && msg.sale) {
    queue.push(msg.sale);
    drain();
  } else if (msg.type === 'TEST') {
    sendTest().then(sendResponse);
    return true; // async response
  } else if (msg.type === 'GET_STATUS') {
    chrome.storage.local.get(['lastResult', 'sentCount'], (r) => {
      sendResponse({ lastResult: r.lastResult || null, sentCount: r.sentCount || 0 });
    });
    return true;
  }
});

async function drain() {
  if (draining) return;
  draining = true;
  while (queue.length) {
    const sale = queue.shift();
    await sendSale(sale).catch((e) => recordResult(false, String(e)));
    await new Promise((r) => setTimeout(r, 400));
  }
  draining = false;
}

async function getSettings() {
  return { ...DEFAULTS, ...(await chrome.storage.sync.get(DEFAULTS)) };
}

// ntfy reads the Title header as latin-1, so encode non-ASCII per RFC 2047.
function headerSafe(s) {
  const str = String(s || '');
  if (/^[\x20-\x7E]*$/.test(str)) return str;
  const bytes = new TextEncoder().encode(str);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return '=?UTF-8?B?' + btoa(bin) + '?=';
}

function authHeader(token) {
  const t = String(token || '').trim();
  if (!t) return null;
  if (t.startsWith('tk_')) return `Bearer ${t}`;
  if (t.includes(':')) return `Basic ${btoa(t)}`; // user:pass
  return `Bearer ${t}`;
}

function buildRequest(sale, cfg) {
  const server = (cfg.server || 'https://ntfy.sh').replace(/\/+$/, '');
  const url = `${server}/${encodeURIComponent(cfg.topic.trim())}`;

  const lines = [];
  const put = (label, v) => { if (v !== undefined && v !== null && String(v).trim() !== '') lines.push(`${label}: ${v}`); };
  put('Item', sale.title);
  put('Price', sale.price);
  put('Buyer', sale.buyer);
  if (sale.qty && sale.qty > 1) put('Qty', sale.qty);
  const typeLabel = sale.saleType
    ? String(sale.saleType).replace(/^key:/, '').replace(/^dom-card$/, 'sold card').replace(/^dom/, 'page render')
    : undefined;
  put('Type', typeLabel);
  put('Ref', sale.id);
  put('When', sale.detectedAt ? new Date(sale.detectedAt).toLocaleString() : new Date().toLocaleString());
  put('Show', sale.showTitle);
  if (sale.url) lines.push('', sale.url);
  if (sale.sourceUrl && sale.sourceUrl !== sale.url) {
    // strip query - socket URLs carry the page's CSRF token
    const src = String(sale.sourceUrl).split('?')[0].slice(0, 120);
    lines.push('', `(via ${sale.via || 'net'}: ${src})`);
  }

  const shortTitle = sale.title ? ` — ${String(sale.title).slice(0, 60)}` : '';
  const headers = {
    'Title': headerSafe(`Whatnot sale${sale.price ? ` ${sale.price}` : ''}${shortTitle}`),
    'Priority': String(cfg.priority || '4'),
    'Tags': 'moneybag,dollar',
    'Content-Type': 'text/plain; charset=utf-8'
  };
  if (sale.url && /^https?:/.test(sale.url)) headers['Click'] = sale.url;
  if (sale.image && /^https?:/.test(sale.image)) {
    headers['Attach'] = sale.image;
    headers['Icon'] = sale.image;
  }
  const auth = authHeader(cfg.token);
  if (auth) headers['Authorization'] = auth;

  return { url, headers, body: lines.join('\n') };
}

async function recordResult(ok, detail) {
  const lastResult = { ok, detail, at: new Date().toISOString() };
  await chrome.storage.local.set({ lastResult });
}

async function sendSale(sale) {
  const cfg = await getSettings();
  if (!cfg.enabled) return;
  if (!cfg.topic || !String(cfg.topic).trim()) {
    await recordResult(false, 'No ntfy topic configured — open the extension popup.');
    return;
  }
  const { url, headers, body } = buildRequest(sale, cfg);
  try {
    const res = await fetch(url, { method: 'POST', headers, body });
    if (!res.ok) throw new Error(`ntfy ${res.status}: ${(await res.text()).slice(0, 200)}`);
    sentCount += 1;
    await chrome.storage.local.set({ sentCount });
    try {
      chrome.action.setBadgeBackgroundColor({ color: '#16a34a' });
      chrome.action.setBadgeText({ text: String(sentCount) });
    } catch (_) { /* badge is cosmetic */ }
    await recordResult(true, `${sale.price || 'sale'} — ${sale.title || 'item'} → ${url}`);
  } catch (e) {
    await recordResult(false, `POST ${url} failed: ${e.message || e}`);
  }
}

async function sendTest() {
  const cfg = await getSettings();
  if (!cfg.topic || !String(cfg.topic).trim()) {
    return { ok: false, detail: 'Set a topic first.' };
  }
  const { url, headers, body } = buildRequest({
    title: 'Test notification — extension is working',
    price: '$0',
    buyer: 'you',
    saleType: 'test',
    detectedAt: new Date().toISOString(),
    showTitle: '(test)',
    url: 'https://www.whatnot.com/'
  }, cfg);
  try {
    const res = await fetch(url, { method: 'POST', headers, body });
    const text = await res.text();
    if (!res.ok) throw new Error(`ntfy ${res.status}: ${text.slice(0, 200)}`);
    await recordResult(true, `test → ${url}`);
    return { ok: true, detail: `Delivered to ${url}` };
  } catch (e) {
    const detail = `POST ${url} failed: ${e.message || e}`;
    await recordResult(false, detail);
    return { ok: false, detail };
  }
}
