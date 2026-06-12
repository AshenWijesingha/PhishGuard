# Browser compatibility notes

PhishGuard targets Chrome/Edge (Chromium ≥ 120) as the primary platform. This document lists
what changes for a Firefox build.

## Manifest V3 support in Firefox

Firefox supports MV3 from version 109, but with differences:

| Area | Chrome/Edge | Firefox | Impact on PhishGuard |
|---|---|---|---|
| Background | Service worker (`background.service_worker`) | **Event pages** — use `background.scripts` (Firefox does not run MV3 service workers) | Add `"background": { "scripts": ["background.js"] }` for the Firefox manifest; our worker code uses no SW-only APIs (`clients`, `skipWaiting`), so it runs unchanged as an event page |
| API namespace | `chrome.*` (callback + promise) | `browser.*` (promise-first); `chrome.*` alias exists | Code uses promise-style `chrome.*` throughout, which Firefox's `chrome` alias supports; alternatively add `webextension-polyfill` |
| `world: "MAIN"` content scripts | Supported (Chrome 111+) | Supported from Firefox 128 | The page hook works on current Firefox ESR+; on older versions, fall back to injecting a `<script>` tag from the isolated world |
| declarativeNetRequest | Full dynamic-rule support, 30k dynamic rules | Supported (FF 113+), **5,000 dynamic rules** and no `regexFilter` parity | We cap blocklist rules at 4,000 (`syncBlocklistRules`), within Firefox's limit; redirect-to-extension-page rules work in both |
| `chrome.action` badge | Per-tab badge text/color | Same API | No change |
| `options_page` | Supported | Prefers `options_ui` | Add `options_ui: { page: "dashboard.html", open_in_tab: true }` |
| CSP `extension_pages` | Supported | Supported | No change |
| `minimum_chrome_version` | Respected | Ignored; use `browser_specific_settings.gecko.strict_min_version` | Add gecko block |

## Firefox manifest delta

Create `public/manifest.firefox.json` at packaging time with these changes:

```jsonc
{
  "background": { "scripts": ["background.js"] },
  "options_ui": { "page": "dashboard.html", "open_in_tab": true },
  "browser_specific_settings": {
    "gecko": { "id": "phishguard@example.org", "strict_min_version": "128.0" }
  }
  // remove: minimum_chrome_version, options_page
}
```

A CI matrix producing both zips is planned alongside the Firefox target (N22):
`npm run build && node scripts/package.mjs --target=firefox`.

## Behavioral differences worth testing on Firefox

- **IndexedDB in event pages**: identical API; the hash-chained audit log is unaffected.
- **`requestSubmit()`** (used by the MAIN-world `form.submit` rewrite): supported since FF 75.
- **`requestIdleCallback`**: supported; the deferred page analysis path is unchanged.
- **Shadow DOM `mode: "closed"`** for warning UI: supported.
- **Safari**: not targeted; MV3 service workers and DNR exist but `world: "MAIN"` and dynamic
  DNR rules differ enough that a separate adaptation pass would be required.
