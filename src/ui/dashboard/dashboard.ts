/**
 * Options/dashboard page (M14): audit-log viewer with search, filtering,
 * stats, integrity verification, CSV/JSON export; allowlist/blocklist
 * management; sensitivity, threat-feed, and privacy settings.
 */
import { sendRequest, type Response } from '../../types/messages';
import type { AuditRecord } from '../../storage/audit-log';
import { toCsv } from '../../storage/audit-log';

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

$('allow-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const input = $('allow-input') as HTMLInputElement;
  if (input.value.trim()) await sendRequest({ kind: 'addToAllowlist', domain: input.value });
  input.value = '';
  await loadLists();
});
$('block-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const input = $('block-input') as HTMLInputElement;
  if (input.value.trim()) await sendRequest({ kind: 'addToBlocklist', domain: input.value });
  input.value = '';
  await loadLists();
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
      privacyHashDomains: ($('privacy-hash') as HTMLInputElement).checked,
      emailInspection: ($('email-inspection') as HTMLInputElement).checked,
      suspiciousBanner: ($('suspicious-banner') as HTMLInputElement).checked,
      logRetentionDays: Number(($('retention') as HTMLInputElement).value) || 0,
    },
  });
  $('settings-saved').textContent = '✓ Saved';
  setTimeout(() => ($('settings-saved').textContent = ''), 2500);
});

void loadLog();
void loadLists();
void loadSettings();
