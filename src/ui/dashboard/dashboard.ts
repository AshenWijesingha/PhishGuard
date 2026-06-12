/**
 * Options/dashboard page (M14): audit-log viewer with search, filtering,
 * stats, integrity verification, CSV/JSON export; allowlist/blocklist
 * management; sensitivity, threat-feed, and privacy settings.
 */
import { sendRequest, type Response } from '../../types/messages';
import type { AuditRecord } from '../../storage/audit-log';
import { toCsv } from '../../storage/audit-log';
import { EDUCATION } from '../../core/education';

function $(id: string): HTMLElement {
  return document.getElementById(id)!;
}

// ---------------------------------------------------------------------------
// Tabs

for (const tab of document.querySelectorAll<HTMLButtonElement>('[role="tab"]')) {
  tab.addEventListener('click', () => {
    for (const t of document.querySelectorAll<HTMLButtonElement>('[role="tab"]')) {
      t.setAttribute('aria-selected', String(t === tab));
    }
    for (const panel of document.querySelectorAll<HTMLElement>('[role="tabpanel"]')) {
      panel.hidden = panel.id !== `tab-${tab.dataset.tab}`;
    }
  });
}

// ---------------------------------------------------------------------------
// Audit log

let currentRecords: AuditRecord[] = [];

async function loadLog(): Promise<void> {
  const text = ($('log-search') as HTMLInputElement).value.trim();
  const eventType = ($('log-type') as HTMLSelectElement).value;
  const res = await sendRequest<Response>({
    kind: 'getAuditLog',
    filter: { text: text || undefined, eventType: eventType || undefined, limit: 500 },
  });
  if (res.kind !== 'auditLog') return;
  currentRecords = res.records;
  renderLog(res.records);
  renderStats(res.records);
  renderCharts(res.records);
}

function renderLog(records: AuditRecord[]): void {
  const tbody = document.querySelector('#log-table tbody')!;
  tbody.textContent = '';
  for (const r of records) {
    const tr = document.createElement('tr');
    const cells = [
      new Date(r.timestamp).toLocaleString(),
      r.type.replace(/_/g, ' '),
      r.domain,
      r.verdict ?? '—',
      r.score !== undefined ? String(r.score) : '—',
      r.userDecision ?? '—',
      r.signals.join(' • '),
    ];
    cells.forEach((text, i) => {
      const td = document.createElement('td');
      if (i === cells.length - 1) td.className = 'signals-cell';
      td.textContent = text;
      tr.appendChild(td);
    });
    tbody.appendChild(tr);
  }
}

function renderStats(records: AuditRecord[]): void {
  const weekAgo = Date.now() - 7 * 86400_000;
  const thisWeek = records.filter((r) => r.timestamp >= weekAgo);
  const blocks = thisWeek.filter((r) => r.type === 'blocked_submission' || r.type === 'blocked_navigation').length;
  const overrides = thisWeek.filter((r) => r.type === 'user_override').length;
  const domains = new Map<string, number>();
  for (const r of thisWeek) domains.set(r.domain, (domains.get(r.domain) ?? 0) + 1);
  const top = [...domains.entries()].sort((a, b) => b[1] - a[1])[0];

  const stats = $('stats');
  stats.textContent = '';
  const stat = (label: string, value: string) => {
    const div = document.createElement('div');
    div.className = 'stat';
    const b = document.createElement('b');
    b.textContent = value;
    div.append(b, document.createTextNode(label));
    stats.appendChild(div);
  };
  stat('events this week', String(thisWeek.length));
  stat('blocks this week', String(blocks));
  stat('overrides this week', String(overrides));
  stat('top flagged domain', top ? `${top[0]} (${top[1]})` : '—');
}

// ---------------------------------------------------------------------------
// Charts (hand-rolled SVG/CSS — no external libraries, CSP-friendly)

const SVG_NS = 'http://www.w3.org/2000/svg';

function svg<K extends keyof SVGElementTagNameMap>(tag: K, attrs: Record<string, string> = {}): SVGElementTagNameMap[K] {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
  return node;
}

function legend(id: string, items: { label: string; color: string }[]): void {
  const box = $(id);
  box.textContent = '';
  for (const item of items) {
    const span = document.createElement('span');
    const dot = document.createElement('span');
    dot.className = 'dot';
    dot.style.background = item.color;
    span.append(dot, document.createTextNode(item.label));
    box.appendChild(span);
  }
}

function emptyState(id: string): void {
  const box = $(id);
  box.textContent = '';
  const p = document.createElement('p');
  p.className = 'chart-empty';
  p.textContent = 'No events yet — PhishGuard is watching quietly.';
  box.appendChild(p);
}

const SEVERITY_COLORS = { blocked: '#e0341b', flagged: '#f5a623', other: '#1b5ea8' };
const BLOCK_TYPES = new Set(['blocked_submission', 'blocked_navigation', 'ti_hit']);
const FLAG_TYPES = new Set(['detection', 'flagged_visit']);

/** Stacked daily bars for the last 14 days. */
function renderActivityChart(records: AuditRecord[]): void {
  const box = $('chart-activity');
  box.textContent = '';
  const days = 14;
  const dayMs = 86400_000;
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const start = today.getTime() - (days - 1) * dayMs;

  const buckets = Array.from({ length: days }, () => ({ blocked: 0, flagged: 0, other: 0 }));
  for (const r of records) {
    if (r.timestamp < start) continue;
    const idx = Math.min(days - 1, Math.floor((r.timestamp - start) / dayMs));
    const bucket = buckets[idx]!;
    if (BLOCK_TYPES.has(r.type)) bucket.blocked++;
    else if (FLAG_TYPES.has(r.type)) bucket.flagged++;
    else bucket.other++;
  }
  const max = Math.max(1, ...buckets.map((b) => b.blocked + b.flagged + b.other));
  if (buckets.every((b) => b.blocked + b.flagged + b.other === 0)) {
    emptyState('chart-activity');
    legend('legend-activity', []);
    return;
  }

  const W = 560, H = 170, padB = 22, padL = 4;
  const chart = svg('svg', { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: 'xMidYMid meet' });
  const slot = (W - padL * 2) / days;
  const barW = Math.min(26, slot * 0.62);
  const plotH = H - padB - 8;

  for (let i = 0; i < days; i++) {
    const b = buckets[i]!;
    const x = padL + i * slot + (slot - barW) / 2;
    let yCursor = 8 + plotH;
    const total = b.blocked + b.flagged + b.other;
    for (const key of ['other', 'flagged', 'blocked'] as const) {
      const h = (b[key] / max) * plotH;
      if (h <= 0) continue;
      yCursor -= h;
      chart.appendChild(svg('rect', {
        x: String(x), y: String(yCursor), width: String(barW), height: String(h),
        rx: '3', fill: SEVERITY_COLORS[key],
      }));
    }
    if (total > 0) {
      const count = svg('text', {
        x: String(x + barW / 2), y: String(yCursor - 4), 'text-anchor': 'middle',
        'font-size': '10', fill: 'currentColor', opacity: '0.75',
      });
      count.textContent = String(total);
      chart.appendChild(count);
    }
    const d = new Date(start + i * dayMs);
    const label = svg('text', {
      x: String(x + barW / 2), y: String(H - 6), 'text-anchor': 'middle',
      'font-size': '9', fill: 'currentColor', opacity: '0.55',
    });
    label.textContent = `${d.getDate()}/${d.getMonth() + 1}`;
    chart.appendChild(label);
  }
  box.appendChild(chart);
  legend('legend-activity', [
    { label: 'Blocked', color: SEVERITY_COLORS.blocked },
    { label: 'Flagged', color: SEVERITY_COLORS.flagged },
    { label: 'Other events', color: SEVERITY_COLORS.other },
  ]);
}

/** Donut of events by verdict. */
function renderVerdictChart(records: AuditRecord[]): void {
  const box = $('chart-verdicts');
  box.textContent = '';
  const palette: Record<string, string> = {
    suspicious: '#f5a623', high_risk: '#e0341b', malicious: '#7a0c0c', other: '#7d8590',
  };
  const counts = new Map<string, number>();
  for (const r of records) {
    const key = r.verdict && palette[r.verdict] ? r.verdict : 'other';
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  const total = records.length;
  if (total === 0) {
    emptyState('chart-verdicts');
    legend('legend-verdicts', []);
    return;
  }

  const chart = svg('svg', { viewBox: '0 0 120 120' });
  let offset = 25; // start at 12 o'clock (pathLength 100, stroke starts at 3 o'clock)
  const order = ['malicious', 'high_risk', 'suspicious', 'other'];
  for (const key of order) {
    const n = counts.get(key) ?? 0;
    if (n === 0) continue;
    const pct = (n / total) * 100;
    chart.appendChild(svg('circle', {
      cx: '60', cy: '60', r: '44', fill: 'none',
      stroke: palette[key]!, 'stroke-width': '20', pathLength: '100',
      'stroke-dasharray': `${pct} ${100 - pct}`, 'stroke-dashoffset': String(offset),
    }));
    offset -= pct;
  }
  const totalText = svg('text', {
    x: '60', y: '58', 'text-anchor': 'middle', 'font-size': '17', 'font-weight': '700', fill: 'currentColor',
  });
  totalText.textContent = String(total);
  const sub = svg('text', {
    x: '60', y: '74', 'text-anchor': 'middle', 'font-size': '9', fill: 'currentColor', opacity: '0.6',
  });
  sub.textContent = 'events';
  chart.append(totalText, sub);
  box.appendChild(chart);

  const labels: Record<string, string> = {
    malicious: 'Confirmed malicious', high_risk: 'High risk', suspicious: 'Suspicious', other: 'Other',
  };
  legend(
    'legend-verdicts',
    order.filter((k) => (counts.get(k) ?? 0) > 0).map((k) => ({
      label: `${labels[k]} (${counts.get(k)})`,
      color: palette[k]!,
    })),
  );
}

/** Horizontal bars for the most-flagged domains. */
function renderDomainChart(records: AuditRecord[]): void {
  const box = $('chart-domains');
  box.textContent = '';
  const counts = new Map<string, number>();
  for (const r of records) {
    if (!r.domain) continue;
    counts.set(r.domain, (counts.get(r.domain) ?? 0) + 1);
  }
  const top = [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6);
  if (top.length === 0) {
    emptyState('chart-domains');
    return;
  }
  const max = top[0]![1];
  for (const [domain, count] of top) {
    const row = document.createElement('div');
    row.className = 'bar-row';
    const name = document.createElement('span');
    name.className = 'domain';
    name.textContent = domain;
    name.title = domain;
    const track = document.createElement('div');
    track.className = 'track';
    const fill = document.createElement('div');
    fill.className = 'fill';
    fill.style.width = `${Math.max(4, (count / max) * 100)}%`;
    track.appendChild(fill);
    const num = document.createElement('span');
    num.className = 'count';
    num.textContent = String(count);
    row.append(name, track, num);
    box.appendChild(row);
  }
}

function renderCharts(records: AuditRecord[]): void {
  renderActivityChart(records);
  renderVerdictChart(records);
  renderDomainChart(records);
}

$('log-search').addEventListener('input', () => void loadLog());
$('log-type').addEventListener('change', () => void loadLog());

$('btn-verify').addEventListener('click', async () => {
  const res = await sendRequest<Response>({ kind: 'verifyAuditLog' });
  const out = $('verify-result');
  if (res.kind === 'auditVerify' && res.ok) {
    out.className = 'ok';
    out.textContent = '✓ Hash chain intact — no tampering detected.';
  } else if (res.kind === 'auditVerify') {
    out.className = 'bad';
    out.textContent = `✗ Hash chain BROKEN at record #${res.brokenAt} — the log has been altered.`;
  }
});

function download(filename: string, mime: string, content: string): void {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([content], { type: mime }));
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}

$('btn-export-csv').addEventListener('click', () => {
  download(`phishguard-audit-${Date.now()}.csv`, 'text/csv', toCsv([...currentRecords].sort((a, b) => a.seq - b.seq)));
});
$('btn-export-json').addEventListener('click', () => {
  download(`phishguard-audit-${Date.now()}.json`, 'application/json', JSON.stringify(currentRecords, null, 2));
});

// ---------------------------------------------------------------------------
// Lists

async function loadLists(): Promise<void> {
  const res = await sendRequest<Response>({ kind: 'getLists' });
  if (res.kind !== 'lists') return;
  renderList('allow-list', res.allowlist, (d) => sendRequest({ kind: 'removeFromAllowlist', domain: d }));
  renderList('block-list', res.blocklist, (d) => sendRequest({ kind: 'removeFromBlocklist', domain: d }));
}

function renderList(id: string, items: string[], onRemove: (d: string) => Promise<unknown>): void {
  const ul = $(id);
  ul.textContent = '';
  for (const domain of items) {
    const li = document.createElement('li');
    const span = document.createElement('span');
    span.textContent = domain;
    const btn = document.createElement('button');
    btn.textContent = 'Remove';
    btn.addEventListener('click', async () => {
      await onRemove(domain);
      await loadLists();
    });
    li.append(span, btn);
    ul.appendChild(li);
  }
}

let noticeTimer: ReturnType<typeof setTimeout> | undefined;
function showListNotice(text: string): void {
  const box = $('list-notice');
  box.textContent = text;
  clearTimeout(noticeTimer);
  noticeTimer = setTimeout(() => (box.textContent = ''), 5000);
}

async function addToList(kind: 'addToAllowlist' | 'addToBlocklist', value: string): Promise<void> {
  const domain = value.trim();
  if (!domain) return;
  const res = await sendRequest<Response>({ kind, domain });
  if (res.kind === 'listAdded' && res.movedFromOtherList) {
    showListNotice(
      kind === 'addToAllowlist'
        ? `“${domain}” was on the blocklist — it has been moved to the allowlist.`
        : `“${domain}” was on the allowlist — it has been moved to the blocklist.`,
    );
  }
  await loadLists();
}

$('allow-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const input = $('allow-input') as HTMLInputElement;
  await addToList('addToAllowlist', input.value);
  input.value = '';
});
$('block-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const input = $('block-input') as HTMLInputElement;
  await addToList('addToBlocklist', input.value);
  input.value = '';
});

// ---------------------------------------------------------------------------
// Settings

async function loadSettings(): Promise<void> {
  const res = await sendRequest<Response>({ kind: 'getSettings' });
  if (res.kind !== 'settings') return;
  const s = res.settings;
  ($('th-suspicious') as HTMLInputElement).value = String(s.thresholds.suspicious);
  ($('th-high') as HTMLInputElement).value = String(s.thresholds.highRisk);
  ($('gsb-key') as HTMLInputElement).value = s.safeBrowsingApiKey;
  ($('feed-phishtank') as HTMLInputElement).checked = s.feeds.phishtank.enabled;
  ($('phishtank-key') as HTMLInputElement).value = s.feeds.phishtank.apiKey;
  ($('feed-openphish') as HTMLInputElement).checked = s.feeds.openphish.enabled;
  ($('feed-urlhaus') as HTMLInputElement).checked = s.feeds.urlhaus.enabled;
  ($('feed-custom') as HTMLInputElement).checked = s.feeds.custom.enabled;
  ($('custom-url') as HTMLInputElement).value = s.feeds.custom.url;
  ($('custom-key') as HTMLInputElement).value = s.feeds.custom.apiKey;
  ($('rdap-age') as HTMLInputElement).checked = s.rdapDomainAge;
  ($('pwd-guard') as HTMLInputElement).checked = s.passwordReuseGuard;
  ($('confirm-suspicious') as HTMLInputElement).checked = s.confirmSuspiciousSubmissions;
  ($('privacy-hash') as HTMLInputElement).checked = s.privacyHashDomains;
  ($('email-inspection') as HTMLInputElement).checked = s.emailInspection;
  ($('suspicious-banner') as HTMLInputElement).checked = s.suspiciousBanner;
  ($('retention') as HTMLInputElement).value = String(s.logRetentionDays);
}

$('btn-save-settings').addEventListener('click', async () => {
  await sendRequest({
    kind: 'updateSettings',
    settings: {
      thresholds: {
        suspicious: Number(($('th-suspicious') as HTMLInputElement).value) || 25,
        highRisk: Number(($('th-high') as HTMLInputElement).value) || 55,
        malicious: 1000,
      },
      safeBrowsingApiKey: ($('gsb-key') as HTMLInputElement).value.trim(),
      feeds: {
        phishtank: {
          enabled: ($('feed-phishtank') as HTMLInputElement).checked,
          apiKey: ($('phishtank-key') as HTMLInputElement).value.trim(),
          url: '',
        },
        openphish: { enabled: ($('feed-openphish') as HTMLInputElement).checked, apiKey: '', url: '' },
        urlhaus: { enabled: ($('feed-urlhaus') as HTMLInputElement).checked, apiKey: '', url: '' },
        custom: {
          enabled: ($('feed-custom') as HTMLInputElement).checked,
          apiKey: ($('custom-key') as HTMLInputElement).value.trim(),
          url: ($('custom-url') as HTMLInputElement).value.trim(),
        },
      },
      rdapDomainAge: ($('rdap-age') as HTMLInputElement).checked,
      passwordReuseGuard: ($('pwd-guard') as HTMLInputElement).checked,
      confirmSuspiciousSubmissions: ($('confirm-suspicious') as HTMLInputElement).checked,
      privacyHashDomains: ($('privacy-hash') as HTMLInputElement).checked,
      emailInspection: ($('email-inspection') as HTMLInputElement).checked,
      suspiciousBanner: ($('suspicious-banner') as HTMLInputElement).checked,
      logRetentionDays: Number(($('retention') as HTMLInputElement).value) || 0,
    },
  });
  $('settings-saved').textContent = '✓ Saved';
  setTimeout(() => ($('settings-saved').textContent = ''), 2500);
});

// ---------------------------------------------------------------------------
// Learn library (N14)

function renderLearnLibrary(): void {
  const box = $('learn-cards');
  for (const card of Object.values(EDUCATION)) {
    const div = document.createElement('div');
    div.className = 'edu-card';
    const h3 = document.createElement('h3');
    h3.textContent = card.title;
    const body = document.createElement('p');
    body.textContent = card.body;
    const tip = document.createElement('p');
    tip.className = 'edu-tip';
    tip.textContent = '✓ ' + card.tip;
    div.append(h3, body, tip);
    box.appendChild(div);
  }
}

void loadLog();
void loadLists();
void loadSettings();
renderLearnLibrary();
