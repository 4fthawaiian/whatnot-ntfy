// Whatnot -> ntfy :: MAIN-world sniffer.
// Runs inside the page (before page scripts) and hooks fetch, XMLHttpRequest
// and WebSocket so the page's own live event feed can be inspected for sale
// events. Candidate payloads are forwarded to the isolated content script via
// window.postMessage. Nothing is sent anywhere else from here.
(() => {
  'use strict';

  const TAG = 'wn2ntfy-sniffer';
  const MAX_BYTES = 3 * 1024 * 1024;
  // Words that suggest a payload might describe a completed sale. Kept broad;
  // the content script applies the strict filtering.
  const HINT_RE = /sold|purchase|order|auction|checkout|buyer|winner|transaction|sale|listing/i;
  const URL_RE = /graphql|api|stream|socket|live|order|sale|feed/i;

  const emit = (kind, meta) => {
    try {
      window.postMessage({ source: TAG, kind, ...meta }, location.origin);
    } catch (_) { /* ignore */ }
  };

  const looksJson = (text) => {
    if (!text || typeof text !== 'string' || text.length > MAX_BYTES) return false;
    if (!HINT_RE.test(text)) return false;
    const t = text.trimStart();
    return t.startsWith('{') || t.startsWith('[');
  };

  const inspectText = (kind, meta, text) => {
    if (!looksJson(text)) return;
    try {
      emit(kind, { ...meta, payload: JSON.parse(text) });
    } catch (_) { /* not valid JSON after all */ }
  };

  // ---- fetch() ------------------------------------------------------------
  const origFetch = window.fetch;
  if (typeof origFetch === 'function') {
    window.fetch = function patchedFetch(...args) {
      return origFetch.apply(this, args).then((res) => {
        try {
          const input = args[0];
          const url = String(typeof input === 'string' ? input : (input && input.url) || '');
          if (URL_RE.test(url)) {
            res.clone().text()
              .then((t) => inspectText('http', { url, status: res.status }, t))
              .catch(() => {});
          }
        } catch (_) { /* never break the page's request */ }
        return res;
      });
    };
  }

  // ---- XMLHttpRequest -----------------------------------------------------
  const origOpen = XMLHttpRequest.prototype.open;
  const origSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function (method, url, ...rest) {
    this.__wn2ntfyUrl = String(url);
    return origOpen.call(this, method, url, ...rest);
  };
  XMLHttpRequest.prototype.send = function (...args) {
    const xhr = this;
    if (URL_RE.test(xhr.__wn2ntfyUrl || '')) {
      xhr.addEventListener('load', () => {
        try {
          const type = xhr.responseType;
          if (type === 'json') {
            inspectText('xhr', { url: xhr.__wn2ntfyUrl, status: xhr.status }, JSON.stringify(xhr.response));
          } else if (type === '' || type === 'text') {
            inspectText('xhr', { url: xhr.__wn2ntfyUrl, status: xhr.status }, xhr.responseText);
          }
        } catch (_) { /* ignore */ }
      });
    }
    return origSend.apply(this, args);
  };

  // ---- WebSocket ----------------------------------------------------------
  // Live sale/bid events almost certainly arrive over a socket. We attach a
  // passive listener - the page's own handlers are untouched.
  const OrigWS = window.WebSocket;
  if (typeof OrigWS === 'function') {
    const PatchedWS = function (url, protocols) {
      const ws = protocols === undefined ? new OrigWS(url) : new OrigWS(url, protocols);
      ws.addEventListener('message', (ev) => {
        try {
          const data = ev.data;
          if (typeof data === 'string') {
            inspectText('ws', { url: String(url) }, data);
          } else if (data instanceof Blob) {
            data.text()
              .then((t) => inspectText('ws', { url: String(url) }, t))
              .catch(() => {});
          } else if (data instanceof ArrayBuffer) {
            inspectText('ws', { url: String(url) }, new TextDecoder().decode(data));
          }
        } catch (_) { /* ignore */ }
      });
      return ws;
    };
    PatchedWS.prototype = OrigWS.prototype;
    for (const k of ['CONNECTING', 'OPEN', 'CLOSING', 'CLOSED']) {
      Object.defineProperty(PatchedWS, k, { value: OrigWS[k] });
    }
    window.WebSocket = PatchedWS;
  }
})();
