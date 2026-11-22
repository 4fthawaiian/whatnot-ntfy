'use strict';

const DEFAULTS = {
  enabled: true,
  server: 'https://ntfy.sh',
  topic: '',
  token: '',
  priority: '4',
  minPrice: 0,
  domDetect: true,
  netDetect: true,
  hud: true,
  debug: false
};

const $ = (id) => document.getElementById(id);
const statusEl = $('status');
const lastEl = $('last');

function say(msg, isErr) {
  statusEl.textContent = msg;
  statusEl.className = isErr ? 'err' : '';
  setTimeout(() => { if (statusEl.textContent === msg) statusEl.textContent = ''; }, 6000);
}

function load() {
  chrome.storage.sync.get(DEFAULTS, (s) => {
    $('enabled').checked = !!s.enabled;
    $('server').value = s.server || DEFAULTS.server;
    $('topic').value = s.topic || '';
    $('token').value = s.token || '';
    $('priority').value = String(s.priority || '4');
    $('minPrice').value = s.minPrice || 0;
    $('domDetect').checked = !!s.domDetect;
    $('netDetect').checked = !!s.netDetect;
    $('hud').checked = s.hud !== false;
    $('debug').checked = !!s.debug;
  });
  chrome.runtime.sendMessage({ type: 'GET_STATUS' }, (r) => {
    if (chrome.runtime.lastError || !r) return;
    const parts = [];
    if (r.sentCount) parts.push(`${r.sentCount} sent this session`);
    if (r.lastResult) {
      const when = new Date(r.lastResult.at).toLocaleTimeString();
      parts.push(`${r.lastResult.ok ? 'last OK' : 'last failed'} ${when}: ${r.lastResult.detail}`);
    }
    lastEl.textContent = parts.join(' · ');
  });
}

// Request host permission for a custom (non-ntfy.sh) server. Must be called
// from a user gesture.
async function ensureServerPermission(origin) {
  if (origin === 'https://ntfy.sh') return true;
  const pattern = `${origin}/*`;
  const has = await chrome.permissions.contains({ origins: [pattern] });
  if (has) return true;
  return chrome.permissions.request({ origins: [pattern] });
}

// the enabled toggle applies instantly - no Save needed (same flag the HUD
// pause button flips)
$('enabled').addEventListener('change', () => {
  chrome.storage.sync.set({ enabled: $('enabled').checked }, () => {
    say($('enabled').checked ? 'Monitoring on.' : 'Monitoring paused.');
  });
});

$('save').addEventListener('click', async () => {
  let server = $('server').value.trim() || DEFAULTS.server;
  try {
    const u = new URL(server);
    if (u.protocol !== 'https:' && u.protocol !== 'http:') throw new Error('bad scheme');
    server = u.origin;
  } catch (_) {
    say('Server must be an http(s) URL, e.g. https://ntfy.sh', true);
    return;
  }
  const cfg = {
    enabled: $('enabled').checked,
    server,
    topic: $('topic').value.trim(),
    token: $('token').value.trim(),
    priority: $('priority').value,
    minPrice: parseFloat($('minPrice').value) || 0,
    domDetect: $('domDetect').checked,
    netDetect: $('netDetect').checked,
    hud: $('hud').checked,
    debug: $('debug').checked
  };
  // persist first so a denied host permission can never swallow the save
  await chrome.storage.sync.set(cfg);
  const granted = await ensureServerPermission(server).catch(() => false);
  if (!granted) {
    say('Saved — but posting to that server needs a host permission that was not granted.', true);
  } else {
    say('Saved.');
  }
});

$('test').addEventListener('click', () => {
  say('Sending…');
  chrome.runtime.sendMessage({ type: 'TEST' }, (r) => {
    if (chrome.runtime.lastError) return say(chrome.runtime.lastError.message, true);
    say(r && r.detail ? r.detail : 'No response', !(r && r.ok));
    load();
  });
});

load();
