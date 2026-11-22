// Whatnot -> ntfy :: isolated content script.
// Two detection paths:
//   1) Network: receives sniffed payloads from injected.js (MAIN world) and
//      recursively searches them for objects that look like completed sales.
//   2) DOM: MutationObserver over the page for "sold" cards / feed items.
// Candidates are normalized, de-duplicated and sent to the background worker.
//
// Anti-spam measures:
//   - Strong vs weak sale markers; bids/auction-state updates are suppressed.
//   - Aggregate keys (soldCount, total_sales, sort_order, is_sold flags, ...)
//    never count as markers.
//   - A single payload containing many sale records = history backfill; the
//     records seed the dedupe map so DOM renders don't refire, but nothing
//     is posted.
//   - Sale objects whose newest timestamp is > 2 min old are treated as
//     history, not live events.
//   - DOM emits are burst-limited so mounting the Sold tab doesn't flood.
(() => {
  'use strict';

  const TAG = 'wn2ntfy-sniffer';

  const DEFAULTS = {
    enabled: true,
    domDetect: true,
    netDetect: true,
    minPrice: 0,
    hud: true,
    debug: false
  };
  // If the extension was reloaded while this tab was open, this content
  // script is orphaned: chrome.runtime calls throw and storage changes never
  // arrive. We detect it and switch the HUD to a "refresh me" state.
  let ctxStale = false;
  function ctxAlive() {
    try { return !!chrome.runtime.id; } catch (_) { return false; }
  }

  let settings = { ...DEFAULTS };
  try {
    chrome.storage.sync.get(DEFAULTS, (s) => { settings = { ...DEFAULTS, ...s }; });
    chrome.storage.onChanged.addListener((changes, area) => {
      if (area !== 'sync') return;
      try {
        for (const [k, v] of Object.entries(changes)) settings[k] = v.newValue;
        hudRender();
      } catch (_) { /* orphan */ }
    });
  } catch (_) { ctxStale = true; }

  const log = (...a) => { if (settings.debug) console.debug('[wn2ntfy]', ...a); };

  // ------------------------------------------------------------------ dedupe
  const seen = new Map();            // key -> last-seen timestamp
  const SEEN_TTL = 30 * 60 * 1000;   // forget signatures after 30 min
  const REFIRE_MS = 15 * 60 * 1000;  // same no-id signature may refire after 15m
  const seenNodes = new WeakSet();

  function saleKey(sale) {
    return sale.id
      ? `id:${sale.id}`
      : [sale.title, sale.price, sale.buyer, sale.qty]
          .map((x) => String(x || '').toLowerCase()).join('|');
  }

  // true  = duplicate, suppress. Seed marks a key seen without notifying.
  function isDup(key) {
    const now = Date.now();
    if (seen.size > 3000) {
      for (const [k, ts] of seen) if (now - ts > SEEN_TTL) seen.delete(k);
    }
    const prev = seen.get(key);
    const window = key.startsWith('id:') ? SEEN_TTL : REFIRE_MS;
    if (prev !== undefined && now - prev < window) return true;
    seen.set(key, now);
    return false;
  }
  const seed = (key) => { seen.set(key, Date.now()); };

  // -------------------------------------------------------------------- emit
  // raw sniffed candidates, kept so the HUD "log raw" button can dump them
  // when a field extraction needs tuning against real payloads.
  const lastRaw = [];
  function stashRaw(node) {
    try { lastRaw.push({ at: new Date().toISOString(), node: JSON.parse(JSON.stringify(node)) }); }
    catch (_) { lastRaw.push({ at: new Date().toISOString(), node: String(node).slice(0, 500) }); }
    if (lastRaw.length > 15) lastRaw.shift();
  }

  function emit(sale) {
    if (!settings.enabled) return;
    sale.url = sale.url || location.href;
    sale.showTitle = (document.title || '').replace(/\s*[·|]\s*Whatnot.*$/i, '').slice(0, 100);
    sale.detectedAt = new Date().toISOString();

    const priceNum = typeof sale.price === 'number'
      ? sale.price
      : parseFloat(String(sale.price || '').replace(/[^0-9.]/g, ''));
    if (settings.minPrice > 0 && Number.isFinite(priceNum) && priceNum > 0 && priceNum < settings.minPrice) {
      log('below minPrice, skipping', sale);
      return;
    }
    const key = saleKey(sale);
    if (isDup(key)) { log('dup', key, sale); return; }
    log('SALE', sale);
    hudAdd(sale);
    try { chrome.runtime.sendMessage({ type: 'SALE', sale }); } catch (_) { /* worker asleep */ }
  }

  function isLivePage() {
    return /(^|\/)live(s?)(\/|$)|dashboard\/live|livestream/i.test(location.pathname);
  }

  // ============================================================ NETWORK PATH
  // ---- key-name heuristics -------------------------------------------------
  const RE = {
    // Keys that strongly indicate a completed sale when they appear on an
    // object that also carries sale fields.
    strongKey: /sold|purchase|checkout|transaction|receipt|invoice|order|sale/i,
    // ...but never when the key describes an aggregate/flag/layout field.
    aggKey: /count|total_?(count|sales|sold)|num_?|number|revenue|stat|spent|lifetime|rating|rank|rate|quota|capacity|limit|whole_?sale|resale|_min$|_max$|average|avg/i,
    layoutKey: /sort|display|position|sequence|arrange|queue|ordering|sidebar|nav|index|offset/i,
    boolFlagKey: /^(is|has|was|did|can)_/i,
    // Weak markers only count when a price is also present.
    weakKey: /winner|buyer|highest_?bidder|purchaser|top_?buyer/i,
    bidKey: /(^|_)bids?(_|$)|highest_?bid|current_?bid|latest_?bid|top_?bid|bid_?count|next_?bid|min_?bid/i,
    typeKey: /(^|_)(type|event|kind|status|action|state)(_type)?$|event(_?type)?$|__typename|message(_?type)?/i,
    markerValue: /sold|purchase|order_?(placed|created|confirmed|complete)|checkout|auction_?(end|complete|won|finish|close)|(^|_)won(_|$)|winner|transaction|sale_?(complete|confirmed)|receipt|invoice/i,
    bidValue: /bid|auction_?(live|running|open|active)/i,
    price: [
      /sold_?price|sale_?price|final_?price|hammer_?price|winning_?(bid|price)|purchase_?price|checkout_?(price|total)|order_?total/i,
      /total_?(price|amount|cost)|grand_?total|subtotal/i,
      /^(unit_?)?(price|amount|cost|value)(_cents|_in_cents)?$|cents|centavos/i,
      /price|amount|total|cost/i
    ],
    priceSkip: /spent|revenue|earning|lifetime|count|average|avg|shipping|tax|fee/i,
    cents: /cents|centavos|minor(_?units)?/i,
    title: [
      /^(product|listing|item)?_?title$/i,
      /^(product|listing|item)_?name$/i,
      /^name$/i,
      /title|name/i,
      /^description$/i
    ],
    buyerScalar: [
      /buyer_?(user_?name|display_?name|first_?name|handle|name)/i,
      /^(sold_?to|won_?by|ordered_?by|purchased_?by|purchaser|customer_?(user_?name|name))$/i,
      /^winner_?(user_?name|name|handle|first_?name)$/i,
      /^winner$/i
    ],
    buyerObj: /^buyer$|winner|purchaser|customer|recipient|user|member|account|sold_?to/i,
    username: [
      /^(user_?name|handle|login|display_?name|screen_?name|first_?name|name)$/i
    ],
    // keys that hold client/device metadata, never a person
    badBuyerKey: /agent|device|client|platform|version|sdk|locale|_os$|^os_|ip_?addr|lang|geo|carrier|app_?id|browser|session|fingerprint|telemetry/i,
    // values that are user-agent strings or otherwise not a username
    badBuyerVal: /CFNetwork|Darwin|okhttp|Dalvik|Mozilla|AppleWebKit|Gecko|Windows NT|\bAndroid\b|\biPhone\b|\biPad\b|Mac OS|\bLinux\b|Whatnot[\/\s]|\bv?\d+\.\d|\/|:|@|http|\s{2,}/i,
    qty: /^(quantity|qty|item_?count|num_?items|units)$/i,
    id: [
      /^(order|sale|purchase|transaction|payment|receipt|invoice|checkout)_?id$/i,
      /^(listing|product|item|auction|marketplace)_?id$/i,
      /^id$/i,
      /_id$/i
    ],
    currency: /^currency(_?code)?$|^(iso_?)?currency$/i,
    image: /(image|img|thumbnail|photo|picture|cover|media)/i,
    urlish: /url|uri|src|href|link/i,
    tsSale: /sold_?at|purchased_?at|ordered_?at|completed_?at|ended_?at|won_?at|sale_?(time|date)|transaction_?(time|date)/i,
    tsAny: /(_at|at)$|time(stamp)?|date|created|updated|inserted/i,
    tsSkip: /expires|expiry|start|begin|schedul|next|birth|login/i
  };

  function isScalar(v) {
    return typeof v === 'string' || typeof v === 'number';
  }

  function pickScalar(obj, res, depth = 0, skipRe) {
    for (const re of res) {
      for (const k of Object.keys(obj)) {
        const v = obj[k];
        if (re.test(k) && isScalar(v) && !(skipRe && skipRe.test(k))) return { key: k, value: v };
      }
    }
    if (depth >= 3) return null;
    for (const v of Object.values(obj)) {
      if (v && typeof v === 'object' && !Array.isArray(v)) {
        const r = pickScalar(v, res, depth + 1, skipRe);
        if (r) return r;
      }
    }
    return null;
  }

  // Buyer/username extraction. Two passes: scalar buyer-ish keys, then
  // username-ish fields inside nested buyer/user/winner objects. Values that
  // look like user-agent strings or client metadata are rejected - Whatnot's
  // socket frames carry the emitter's UA, not the person's handle.
  function collectScalars(node, depth, out) {
    if (!node || typeof node !== 'object' || depth > 3 || out.length > 80) return out;
    for (const [k, v] of Object.entries(node)) {
      if (isScalar(v)) out.push({ key: k, value: v });
      else if (v && typeof v === 'object' && !Array.isArray(v)) collectScalars(v, depth + 1, out);
    }
    return out;
  }

  function goodBuyerVal(v) {
    const s = String(v).trim();
    return s.length > 0 && s.length <= 60 && !RE.badBuyerVal.test(s) ? s : null;
  }

  function pickBuyer(node) {
    const fields = collectScalars(node, 0, []);
    for (const res of RE.buyerScalar) {
      for (const f of fields) {
        if (!res.test(f.key) || RE.badBuyerKey.test(f.key)) continue;
        const v = goodBuyerVal(f.value);
        if (v) return v;
      }
    }
    return pickBuyerNested(node, 0) || undefined;
  }

  function pickBuyerNested(node, depth) {
    if (depth > 3 || !node || typeof node !== 'object') return null;
    // username-ish scalars inside an object named like a person-container
    for (const [k, v] of Object.entries(node)) {
      if (v && typeof v === 'object' && !Array.isArray(v)
          && RE.buyerObj.test(k) && !RE.badBuyerKey.test(k)) {
        for (const res of RE.username) {
          for (const [ik, iv] of Object.entries(v)) {
            if (isScalar(iv) && res.test(ik) && !RE.badBuyerKey.test(ik)) {
              const val = goodBuyerVal(iv);
              if (val) return val;
            }
          }
        }
      }
    }
    for (const v of Object.values(node)) {
      if (v && typeof v === 'object' && !Array.isArray(v)) {
        const r = pickBuyerNested(v, depth + 1);
        if (r) return r;
      }
    }
    return null;
  }

  // Returns { strong, label } or null. A node is a sale candidate when it has
  // a strong completion marker, or a weak one (buyer/winner) that isn't part
  // of a bid/auction-state update.
  function markerInfo(obj) {
    let strong = null, weak = null, bidFlag = false;

    for (const [k, v] of Object.entries(obj)) {
      if (RE.typeKey.test(k) && typeof v === 'string') {
        if (RE.markerValue.test(v)) strong = strong || `${k}=${v}`;
        else if (RE.bidValue.test(v)) bidFlag = true;
      }
      if (isScalar(v)) {
        if (RE.bidKey.test(k)) bidFlag = true;
        // a bare numeric "order" is layout ordering, not a purchase
        if (/^order$/i.test(k) && typeof v === 'number') continue;
        if (RE.strongKey.test(k) && !RE.aggKey.test(k) && !RE.layoutKey.test(k)
            && !RE.boolFlagKey.test(k) && !Array.isArray(v)) {
          strong = strong || `key:${k}`;
        } else if (RE.weakKey.test(k) && !RE.aggKey.test(k)) {
          weak = weak || `key:${k}`;
        }
      } else if (v && typeof v === 'object' && !Array.isArray(v)) {
        // nested object under a sale-ish key (order:{...}, buyer:{...})
        if (RE.strongKey.test(k) && !RE.aggKey.test(k) && !RE.layoutKey.test(k)) {
          strong = strong || `key:${k}`;
        } else if (RE.weakKey.test(k) && !RE.aggKey.test(k)) {
          weak = weak || `key:${k}`;
        }
      }
      if (typeof v === 'string' && v.length <= 80) {
        if (/\bsold\b|order (placed|created|confirmed)|purchase complete|auction (ended|won|complete)|flash sale/i.test(v)) {
          strong = strong || `val:${v.slice(0, 40)}`;
        }
        if (RE.bidValue.test(v)) bidFlag = true;
      }
    }

    // auction/bid state updates never qualify unless a strong marker is present
    if (bidFlag && !strong) return null;
    if (strong) return { strong: true, label: strong };
    if (weak) return { strong: false, label: weak };
    return null;
  }

  // Newest timestamp anywhere in the node. Sale-ish keys win; scheduling keys
  // (expires/start/next) are ignored. Returns ms epoch or 0.
  function latestTimestamp(node, depth = 0, saleOnly = false) {
    let max = 0;
    if (depth > 4 || !node || typeof node !== 'object') return 0;
    for (const [k, v] of Object.entries(node)) {
      if (RE.tsSkip.test(k)) continue;
      const isSaleKey = RE.tsSale.test(k);
      const isAnyKey = RE.tsAny.test(k);
      if (isScalar(v) && (isSaleKey || (!saleOnly && isAnyKey))) {
        let t = 0;
        if (typeof v === 'number') t = v > 1e12 ? v : v > 1e9 ? v * 1000 : 0;
        else if (typeof v === 'string') t = Date.parse(v) || 0;
        if (t > max) max = t;
      } else if (v && typeof v === 'object' && !Array.isArray(v)) {
        const t = latestTimestamp(v, depth + 1, saleOnly);
        if (t > max) max = t;
      }
    }
    return max;
  }
  const HISTORY_MS = 2 * 60 * 1000;

  function fmtPrice(hit, currency) {
    if (!hit) return undefined;
    let v = hit.value;
    if (typeof v === 'number' && RE.cents.test(hit.key)) v = v / 100;
    if (typeof v === 'number') {
      const cur = currency ? String(currency) : '$';
      return cur === 'USD' || cur === '$' ? `$${v}` : `${cur} ${v}`;
    }
    const s = String(v).trim();
    if (!s || /^0(\.0+)?$/.test(s)) return undefined;
    return currency ? `${s} ${currency}` : s;
  }

  function findUrl(obj, depth = 0) {
    if (depth > 3) return null;
    for (const [k, v] of Object.entries(obj)) {
      if (typeof v === 'string' && /^https?:\/\//.test(v) && RE.image.test(k)) return v;
    }
    for (const [k, v] of Object.entries(obj)) {
      if (typeof v === 'string' && /^https?:\/\//.test(v) && RE.urlish.test(k)) return v;
      if (v && typeof v === 'object' && !Array.isArray(v) && RE.image.test(k)) {
        const r = findUrl(v, depth + 1);
        if (r) return r;
      }
    }
    return null;
  }

  // A node that only carries a weak marker AND looks like live auction state
  // (bid fields, auction sub-object, active-auction type) is the current
  // leader being updated on every bid - not a completed sale.
  function smellsAuction(node, depth = 0) {
    if (depth > 2 || !node || typeof node !== 'object') return false;
    for (const [k, v] of Object.entries(node)) {
      if (RE.bidKey.test(k) || /^auction(_?(live|current|active|state|status))?$|^bids$/i.test(k)) return true;
      if (RE.typeKey.test(k) && typeof v === 'string' && RE.bidValue.test(v) && !RE.markerValue.test(v)) return true;
      if (v && typeof v === 'object' && !Array.isArray(v) && smellsAuction(v, depth + 1)) return true;
    }
    return false;
  }

  function extractSale(node, via, sourceUrl, marker) {
    const currencyHit = pickScalar(node, [RE.currency]);
    const price = fmtPrice(pickScalar(node, RE.price, 0, RE.priceSkip), currencyHit && currencyHit.value);

    // weak markers (buyer/winner alone) require a price and no auction-state
    // smell - otherwise it's stats, a giveaway, or the current high bidder.
    if (!marker.strong && (!price || smellsAuction(node))) return null;

    let title;
    for (const re of RE.title) {
      const hit = pickScalar(node, [re], 0, /user_?name|buyer|seller|host|shop|account/i);
      if (hit && String(hit.value).trim()) { title = String(hit.value).trim().slice(0, 200); break; }
    }

    const buyer = pickBuyer(node);

    const qtyHit = pickScalar(node, [RE.qty]);
    const qty = qtyHit ? Number(qtyHit.value) : undefined;

    let id;
    for (const re of RE.id) {
      const hit = pickScalar(node, [re]);
      if (hit) { id = `${hit.key}:${hit.value}`; break; }
    }

    const image = findUrl(node) || undefined;

    if (!price && !title && !buyer) return null;

    return {
      title, price, buyer,
      qty: Number.isFinite(qty) && qty > 0 ? qty : undefined,
      id, image,
      saleType: marker.label,
      via, sourceUrl
    };
  }

  // Depth-first walk collecting nodes that look like sale records.
  function findSaleNodes(root, out = [], depth = 0, cap = 60) {
    if (!root || depth > 8 || out.length >= cap) return out;
    if (Array.isArray(root)) {
      for (const item of root) findSaleNodes(item, out, depth + 1, cap);
      return out;
    }
    if (typeof root !== 'object') return out;

    const marker = markerInfo(root);
    if (marker) {
      const sale = extractSale(root, null, null, marker);
      if (sale) out.push({ node: root, marker });
    }
    for (const v of Object.values(root)) {
      if (v && typeof v === 'object') findSaleNodes(v, out, depth + 1, cap);
    }
    return out;
  }

  // More than this many sale records in one payload = history/list, not a
  // live event.
  const BACKFILL_THRESHOLD = 5;

  function handleSniffed(kind, data) {
    const payload = data && data.payload;
    if (!payload) return;
    const hits = findSaleNodes(payload);
    if (!hits.length) return;

    const now = Date.now();
    const backfill = hits.length > BACKFILL_THRESHOLD;
    if (backfill) log(`backfill payload (${hits.length} records) — seeding, not notifying`);

    for (const hit of hits) {
      stashRaw(hit.node);
      const sale = extractSale(hit.node, kind, data.url, hit.marker);
      if (!sale) continue;

      // history check: newest sale-ish timestamp older than 2 min => old news
      let ts = latestTimestamp(hit.node, 0, true);
      if (!ts) ts = latestTimestamp(hit.node, 0, false);
      const stale = ts > 0 && now - ts > HISTORY_MS;

      if (backfill || stale) { seed(saleKey(sale)); continue; }
      emit(sale);
    }
  }

  window.addEventListener('message', (ev) => {
    if (ev.source !== window || !ev.data || ev.data.source !== TAG) return;
    if (!settings.enabled || !settings.netDetect) return;
    try { handleSniffed(ev.data.kind, ev.data); } catch (e) { log('sniff error', e); }
  });

  // ================================================================ DOM PATH
  const SALE_TEXT_RE = /\bsold\b|just sold|sold for|sold to|won it|auction ended|purchased|bought this|grabbed|snagged|flash sale/i;
  const PRICE_TEXT_RE = /[$£€]\s?\d[\d,]*(?:\.\d{1,2})?|\b\d[\d,]*(?:\.\d{1,2})?\s?(?:USD|GBP|EUR|CAD|AUD)\b/i;
  const BUYER_TEXT_RES = [
    /sold to\s+@?([A-Za-z0-9_.\-]+)/i,
    /won by\s+@?([A-Za-z0-9_.\-]+)/i,
    /congrats[,!\s]+@?([A-Za-z0-9_.\-]+)/i,
    /@?([A-Za-z0-9_.\-]+)\s+(?:just\s+)?(?:bought|purchased|won|grabbed|snagged|picked up|got)\b/i
  ];

  function extractFromText(text) {
    const clean = text.replace(/\s+/g, ' ').trim();
    const priceM = clean.match(PRICE_TEXT_RE);
    let buyer;
    for (const re of BUYER_TEXT_RES) {
      const m = clean.match(re);
      if (m) { buyer = m[1]; break; }
    }
    let title;
    const lines = text.split('\n').map((l) => l.trim()).filter(Boolean);
    for (const l of lines.sort((a, b) => b.length - a.length)) {
      if (/^(just\s+)?sold(\s+out)?[.\s!]*$/i.test(l)) continue;
      if (PRICE_TEXT_RE.test(l) && l.replace(PRICE_TEXT_RE, '').trim().length < 4) continue;
      if (buyer && l.includes(buyer) && l.length < 40) continue;
      if (l.length < 3) continue;
      title = l.slice(0, 140);
      break;
    }
    return { price: priceM && priceM[0], buyer, title };
  }

  // Burst guard: mounting the Sold tab renders history as dozens of added
  // nodes at once; a live sale arrives one at a time.
  const DOM_BURST_WINDOW = 2000;
  const DOM_BURST_MAX = 4;
  let domBurst = [];
  function domBurstOk() {
    const now = Date.now();
    domBurst = domBurst.filter((t) => now - t < DOM_BURST_WINDOW);
    if (domBurst.length >= DOM_BURST_MAX) return false;
    domBurst.push(now);
    return true;
  }

  function inspectDomNode(el) {
    if (!(el instanceof Element) || seenNodes.has(el)) return;
    const candidates = [el, ...el.querySelectorAll('*')].slice(0, 300);
    for (const c of candidates) {
      if (seenNodes.has(c)) continue;
      seenNodes.add(c);
      const text = c.textContent || '';
      if (text.length > 700 || !SALE_TEXT_RE.test(text) || !PRICE_TEXT_RE.test(text)) continue;
      const info = extractFromText(text);
      if (!info.price && !info.buyer && !info.title) continue;
      if (!isLivePage() && !info.buyer) continue; // marketplace "SOLD" badges
      const img = c.querySelector ? c.querySelector('img') : null;
      const sale = {
        title: info.title,
        price: info.price,
        buyer: info.buyer,
        image: img && img.src ? img.src : undefined,
        saleType: 'dom-card',
        via: 'dom'
      };
      if (domBurstOk()) emit(sale);
      else { seed(saleKey(sale)); log('dom burst — seeded', sale); }
    }
  }

  function domAllowed() {
    if (!settings.enabled || !settings.domDetect) return false;
    if (isLivePage()) return true;
    return !!document.querySelector('video');
  }

  const observer = new MutationObserver((mutations) => {
    if (!domAllowed()) return;
    let budget = 200;
    for (const m of mutations) {
      for (const node of m.addedNodes) {
        if (budget-- <= 0) return;
        try { inspectDomNode(node); } catch (e) { log('dom error', e); }
      }
    }
  });

  function startObserver() {
    if (document.body) {
      observer.observe(document.body, { childList: true, subtree: true });
      log('observer started');
    } else {
      setTimeout(startObserver, 500);
    }
  }
  startObserver();

  // ============================================================ HUD overlay
  // Shadow-DOM panel so Whatnot's styles can't touch it and our own
  // MutationObserver can't see it.
  const HUD_CSS = `
    .box { position: fixed; right: 12px; bottom: 12px; width: 250px; z-index: 2147483647;
      font: 12px/1.45 system-ui, -apple-system, sans-serif; color: #e7e7ea;
      background: rgba(14,14,20,.94); border: 1px solid #3a3a46; border-radius: 10px;
      box-shadow: 0 6px 24px rgba(0,0,0,.45); }
    .hd { display: flex; align-items: center; gap: 6px; padding: 7px 9px;
      border-bottom: 1px solid rgba(255,255,255,.07); }
    .dot { width: 8px; height: 8px; border-radius: 50%; background: #22c55e; flex: none; }
    .hd b { font-size: 11px; letter-spacing: .4px; }
    .st { flex: 1; color: #9a9aa8; font-size: 11px; white-space: nowrap;
      overflow: hidden; text-overflow: ellipsis; text-align: right; }
    .hd button { background: #26262f; border: 1px solid #3d3d4a; color: #e7e7ea;
      border-radius: 5px; padding: 2px 8px; cursor: pointer; font: inherit; font-size: 11px; }
    .hd button:hover { background: #32323e; }
    .list { max-height: 190px; overflow-y: auto; padding: 5px 9px 7px; }
    .item { padding: 3px 0; border-bottom: 1px solid rgba(255,255,255,.05);
      overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .item:last-child { border-bottom: 0; }
    .item b { color: #6ee7a0; }
    .item .b { color: #8fb4d9; }
    .empty { color: #6d6d7c; font-style: italic; }
    .ft { padding: 0 9px 7px; }
    .ft button { width: 100%; background: none; border: 1px solid #2c2c36; color: #777;
      font-size: 10px; border-radius: 5px; padding: 3px 0; cursor: pointer; }
    .ft button:hover { color: #aaa; }
  `;

  let hudHost = null;
  const hudEls = {};
  let hudHidden = false;
  let sentShown = 0;

  const escapeHtml = (s) => s.replace(/[&<>"']/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  function hudRender() {
    if (!hudEls.dot) return;
    if (ctxStale) {
      hudEls.dot.style.background = '#ef4444';
      hudEls.state.textContent = 'ext updated — refresh tab';
      hudEls.pause.textContent = 'Refresh';
      return;
    }
    hudEls.dot.style.background = settings.enabled ? '#22c55e' : '#f59e0b';
    hudEls.state.textContent = settings.enabled
      ? `watching${sentShown ? ` · ${sentShown} sent` : ''}` : 'paused';
    hudEls.pause.textContent = settings.enabled ? 'Pause' : 'Resume';
  }

  function hudAdd(sale) {
    if (!hudEls.list) return;
    const empty = hudEls.list.querySelector('.empty');
    if (empty) empty.remove();
    const div = document.createElement('div');
    div.className = 'item';
    const parts = [];
    if (sale.price) parts.push(`<b>${escapeHtml(String(sale.price))}</b>`);
    parts.push(escapeHtml(String(sale.title || 'item').slice(0, 60)));
    if (sale.buyer) parts.push(`<span class="b">→ ${escapeHtml(String(sale.buyer))}</span>`);
    div.innerHTML = parts.join(' ');
    hudEls.list.prepend(div);
    while (hudEls.list.children.length > 8) hudEls.list.lastChild.remove();
    sentShown += 1;
    hudRender();
  }

  function ensureHud() {
    if (hudHost && hudHost.isConnected) return;
    if (!document.body) return;
    hudHost = document.createElement('div');
    hudHost.setAttribute('data-wn2ntfy', 'hud');
    const shadow = hudHost.attachShadow({ mode: 'open' });
    shadow.innerHTML = `<style>${HUD_CSS}</style>
      <div class="box">
        <div class="hd">
          <span class="dot"></span><b>WN → NTFY</b>
          <span class="st"></span>
          <button class="pause">Pause</button>
          <button class="x" title="Hide until reload">×</button>
        </div>
        <div class="list"><div class="empty">no sales detected yet</div></div>
        <div class="ft"><button class="dump">log raw payloads to console</button></div>
      </div>`;
    hudEls.dot = shadow.querySelector('.dot');
    hudEls.state = shadow.querySelector('.st');
    hudEls.list = shadow.querySelector('.list');
    hudEls.pause = shadow.querySelector('.pause');
    hudEls.pause.onclick = () => {
      if (ctxStale) { location.reload(); return; }
      try {
        const p = chrome.storage.sync.set({ enabled: !settings.enabled });
        if (p && p.catch) p.catch(() => { ctxStale = true; hudRender(); });
      } catch (_) { ctxStale = true; hudRender(); }
    };
    shadow.querySelector('.x').onclick = () => { hudHidden = true; hudHost.style.display = 'none'; };
    shadow.querySelector('.dump').onclick = () => {
      console.log('[wn2ntfy] last raw sale candidates:', lastRaw);
      hudEls.state.textContent = `${lastRaw.length} dumped → console`;
    };
    document.body.appendChild(hudHost);
    hudRender();
  }

  setInterval(() => {
    if (!ctxStale && !ctxAlive()) ctxStale = true;
    // HUD shows on live pages, and everywhere while paused or stale so there
    // is always a visible way to turn monitoring back on.
    const show = settings.hud && !hudHidden && (isLivePage() || !settings.enabled || ctxStale);
    if (show) ensureHud();
    if (hudHost) {
      if (hudHost.isConnected) hudHost.style.display = show ? 'block' : 'none';
      else hudHost = null; // page removed it; allow rebuild
    }
    hudRender();
  }, 2000);
})();
