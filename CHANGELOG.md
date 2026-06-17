# Changelog

All notable changes to PhishGuard are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/), versioning: SemVer.

## [Unreleased]

### Changed
- **Learning site UI/UX overhaul.** Polished, branded redesign of `index.html` with a richer,
  more cohesive visual language and a full set of learning-platform features: sticky nav with
  scrollspy active-section highlighting and a top scroll-progress bar; animated stat counters;
  reveal-on-scroll; back-to-top; toasts; a saved **learning-path tracker** (5 modules, progress
  ring, localStorage); an interactive **"dissect a phishing email"** widget; an enhanced **URL
  Inspector** with a risk gauge and "what PhishGuard would do" guidance; an upgraded **quiz**
  with a best-score badge, persistence, and confetti on a perfect run; a **searchable glossary**;
  copy-to-clipboard install commands; a printable **cheat sheet**; keyboard theme toggle (D);
  and the user-supplied logo wired into the nav, footer, favicon, and social preview.
- Fixed a duplicate `id="glossary"` (section vs. results container) that would have let the
  glossary search wipe the whole section, and restored the Best Practices grid + cheat-sheet
  data that an earlier draft had dropped.

### Added
- **Learning site (`index.html`):** a single-file, HTML5 + vanilla JS + Tailwind (CDN) landing and
  education page. Covers what phishing is, attack types, red flags, best practices, the extension's
  features and install steps, and a glossary. Includes two interactive, fully on-device widgets — a
  **URL Inspector** that mirrors the extension's heuristics (homoglyph/typosquat/IP/userinfo/shortener
  detection) and a five-question **Spot-the-Phish quiz**. Dark mode, reduced-motion, and mobile menu
  supported.
- **GitHub Pages deployment** (`.github/workflows/pages.yml`): auto-deploys the learning site on every
  push to `main`, self-enabling Pages via `actions/configure-pages`.

## [1.2.0] — 2026-06-12

### Added
- **Dashboard charts:** hand-rolled, CSP-friendly SVG/CSS visualizations on the audit-log tab —
  stacked daily activity for the last 14 days (blocked / flagged / other), a verdict-breakdown
  donut, and a top-flagged-domains bar list. Charts react to the active search/type filters
  and adapt to dark mode.
- **Suspicious-destination confirmation:** the blocking pre-submit modal now also appears for
  *Suspicious* form destinations (configurable, on by default), with explicit
  "You are on X, but this form sends your information to Y" framing — the decisive
  intervention happens before any data leaves the page, not in a dismissible banner.

### Changed
- **Allow/blocklist mutual exclusivity:** a domain can only ever be on one list. Adding to the
  allowlist removes it from the blocklist (and resyncs the declarativeNetRequest rules), and
  vice versa; the dashboard announces when a domain is moved, and the audit log records it.
- **Notification anti-fatigue:** the non-blocking "suspicious page" banner now appears at most
  once per origin per 6-hour window within a browser session (chrome.storage.session), ending
  consecutive-banner spam. After a user explicitly overrides a warning for a destination, they
  are not re-prompted for the same destination on the same page load (every pass-through is
  still audit-logged).

## [1.1.0] — 2026-06-12

### Added — post-MVP protection batch (N1, N2, N5, N10, N14) + CI

- **Threat-intel adapters (N1):** PhishTank, OpenPhish, URLhaus, and a generic enterprise
  adapter (MISP export / custom REST URL lists, optional Bearer token) behind the existing
  pluggable interface. Feeds are opt-in, downloaded periodically, stored as truncated hashes,
  and matched entirely on-device; failed refreshes keep the previous cache.
- **Domain age (N2):** cached RDAP lookups (rdap.org) add a weighted "freshly registered
  domain" signal for pages and form destinations that already show suspicion; 30-day positive
  / 1-day negative caching; never consulted for signal-free browsing.
- **Webmail coverage (N5):** Yahoo Mail adapter and a generic Roundcube/Zimbra adapter that
  self-gates on recognizable webmail markup.
- **Password-reuse guard (N10):** warns when a submitted password was previously used on a
  different origin. Plaintext never leaves the page; storage holds salted hashes of both the
  password digest and the origin.
- **Micro-education (N14):** "How does this scam work?" cards for every detected technique in
  the blocking modal, plus a Learn library tab in the dashboard.
- **CI:** GitHub Actions workflow (typecheck → tests → build, uploads the load-unpacked
  bundle as an artifact).
- **Icons:** generated shield-with-checkmark artwork replaces the flat placeholder PNGs.
- 18 new tests (70 total): feed parsing/matching/offline behaviour, RDAP caching, reuse-guard
  semantics incl. storage opacity, education coverage.

## [1.0.0] — 2026-06-12

### Added — MVP (all must-have features M1–M17)

**Detection & analysis**
- Real-time URL analysis on navigation: homoglyph/punycode (IDN) detection with an RFC 3492
  decoder and confusable-character skeletons, typosquat Levenshtein distance against a bundled
  brand list, brand-in-subdomain nesting, excessive subdomain depth, IP-literal hosts
  (dotted/hex/decimal), userinfo-in-URL tricks, suspicious TLDs, URL-shortener flagging (M1).
- Sensitive-form detection via input types, `autocomplete` attributes, and name/label/placeholder
  heuristics (password, payment card, CVV, OTP, SSN, seed phrase), including dynamically
  injected forms through a debounced MutationObserver (M2).
- Capture-phase form-submission interception before any network request, covering native
  submits, `form.submit()` (rewritten to `requestSubmit()` in the MAIN world), and
  credential-shaped `fetch`/XHR POSTs held for a verdict (M3).
- Effective form-destination resolution (empty/relative actions, `formaction` overrides) with
  cross-origin mismatch, HTTPS→HTTP downgrade, action-to-IP, and action-to-shortener checks (M4).
- Google Safe Browsing Update API v4 adapter with local hash-prefix cache, k-anonymity
  full-hash lookups, positive-result TTL caching, and full offline tolerance (M5).
- Gmail and Outlook Web email inspection: display-name vs. address mismatch, reply-to
  divergence, link-text vs. href mismatch with in-message link highlighting, risky attachment
  names (metadata only) (M6).
- On-device content heuristics: urgency/pressure language, credential solicitation, payment
  lures, brand-keyword + off-brand-domain pairing (M7).
- Weighted risk-scoring engine with four verdict tiers and configurable weights/thresholds (M8).

**Protection & response**
- declarativeNetRequest dynamic rules redirect blocklisted navigations to a full-page
  interstitial before render; override requires a typed phrase and is logged (M9).
- Blocking pre-submit modal for High Risk submissions listing every triggered signal in plain
  language; cancel is the default focused action; Confirmed Malicious requires typed
  confirmation (M10).
- Local allowlist ("this is a false positive") and blocklist management from popup,
  banner, and dashboard (M11).

**Recording & visibility**
- Append-only audit log in IndexedDB covering detections, blocked submissions/navigations,
  overrides, TI hits, flagged visits, and reports (M12).
- SHA-256 hash-chained records for tamper evidence; chain verification in the dashboard;
  optional hashed-domain privacy mode; configurable retention (M13).
- Dashboard with search/filtering, weekly stats, integrity check, and CSV/JSON export (M14).
- Toolbar badge reflecting the current-page verdict; popup with verdict, signal breakdown,
  report/allowlist/blocklist actions (M15).

**Platform & quality**
- Manifest V3, TypeScript (strict), esbuild bundling, minimal permissions, strict CSP, no
  remote code, all analysis on-device, no telemetry (M16).
- 52 unit/integration tests: URL heuristics, scoring engine, hash-chain integrity
  (tamper/delete/forge), Safe Browsing canonicalization & caching, sensitive-form detection
  against benign and simulated-phishing HTML fixtures (M17).

### Planned (post-MVP)
- PhishTank / OpenPhish / URLhaus / enterprise REST threat-feed adapters (N1), RDAP domain age
  (N2), Yahoo Mail adapter (N5), password-reuse guard (N10), micro-education cards (N14),
  Firefox build target (N22). See README roadmap and BROWSER_COMPAT.md.
