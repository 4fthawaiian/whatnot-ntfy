# Whatnot Sale → ntfy Notifier

A Manifest V3 Chrome extension that detects sales on a Whatnot live show while
you watch it, and posts the details to an [ntfy](https://ntfy.sh) topic — so
your phone or desktop buzzes on every sale with as much detail as the page
exposes.

Built for viewers who want a second-screen sales feed without staring at the
show.

## Features

- **Two detection paths.** A main-world sniffer hooks `WebSocket`, `fetch` and
  `XMLHttpRequest` before Whatnot's scripts run and pulls sale records out of
  the page's own live event feed (the rich path). A `MutationObserver` watches
  the on-screen sold feed as a DOM-level fallback.
- **Rich notifications.** Item title, price (cents/currency aware), buyer
  username, quantity, listing/order id, item thumbnail attached to the push,
  timestamp, show title and a click-through link to the show.
- **On-page HUD.** A small Shadow-DOM overlay on live pages shows watching /
  paused state, a rolling list of the last detected sales, a **Pause/Resume**
  button, and a raw-payload dump button for debugging.
- **Configurable.** Custom ntfy server, access token (`tk_...` or `user:pass`),
  priority, minimum price filter, per-path detection toggles, HUD on/off,
  debug logging.
- **Anti-spam by design.** Strong vs. weak event markers, bid/auction-state
  suppression, sold-history backfill detection, stale-timestamp filtering,
  DOM burst limiting and signature dedupe — so you get sales, not noise.

## Install

1. Clone or download this repo.
2. Open `chrome://extensions`, enable **Developer mode**.
3. **Load unpacked** → select the repo folder.
4. Click the extension icon and configure:
   - **ntfy server** — `https://ntfy.sh` or your self-hosted instance
     (a host permission is requested automatically for custom servers).
   - **Topic** — a long unguessable name; subscribe to the same topic in the
     ntfy app on your phone.
   - optional: access token, priority, min price.
5. **Send test** — you should get an ntfy message immediately.
6. Open any live Whatnot show (`whatnot.com/.../live/...`). The HUD appears
   bottom-right; sale notifications arrive as items sell.

## How it detects sales

| Path | Mechanism |
| --- | --- |
| Event feed | `injected.js` runs in the page's main world at `document_start`, wraps `WebSocket`/`fetch`/`XHR`, and forwards JSON payloads containing sale hints to the content script via `postMessage`. |
| Sold cards | `content.js` observes DOM mutations for elements containing a sold keyword + a price, and parses buyer/title/price out of the rendered text. |

Candidate JSON objects qualify as sales only with a **strong** completion
marker (`sold`, `SOLD` status, order/purchase/won typenames, order objects) or
a **weak** one (`buyer`/`winner`) that also has a price and no live-auction
smell. Then they pass through:

- **Backfill guard** — >5 sale records in one payload is the show's sold
  history, not a live event. Records seed the dedupe map instead of notifying.
- **Timestamp guard** — newest sale-ish timestamp older than 2 min = history.
- **Dedupe** — id-keyed events can never refire; composite signatures
  (title+price+buyer+qty) are suppressed for 15 min.
- **DOM burst guard** — >4 sold-card detections in 2 s is the Sold tab
  mounting, not a sale.
- **Rate limit** — posts are serialized with ~400 ms spacing.

User-agent strings and client/device metadata fields are explicitly excluded
from buyer extraction (Whatnot's socket frames carry the emitter's UA).

## Privacy

All processing happens locally in your browser. The only outbound requests
are to the ntfy server you configure. No analytics, no tracking, no third
parties. Your Whatnot session is never read — the extension only observes the
same traffic the page itself receives.

## Tuning / debugging

Whatnot's UI and wire format change without notice. If detection drifts:

- Enable **Debug** in the popup — candidates and skips are logged to the
  page console.
- Click **log raw payloads** in the HUD to dump the last 15 raw sale
  candidates, then adjust the heuristics in `content.js` (`markerInfo`, the
  `RE` key tables, `SALE_TEXT_RE`).
- After reloading the extension, refresh any Whatnot tabs that were open —
  content scripts can't re-inject into already-open pages (the HUD detects
  this state and offers a Refresh button).

## Files

| File | Role |
| --- | --- |
| `manifest.json` | MV3 manifest, content-script wiring |
| `injected.js` | MAIN-world network sniffer (WS/fetch/XHR) |
| `content.js` | normalization, anti-spam filters, DOM observer, HUD |
| `background.js` | service worker; formats and POSTs to ntfy |
| `popup.html` / `popup.js` | settings UI |

## License

MIT — see [LICENSE](LICENSE).
