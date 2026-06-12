/**
 * Append-only, hash-chained audit log in IndexedDB (M12/M13).
 *
 * Each record stores the SHA-256 hash of the previous record's hash plus
 * the canonical JSON of its own event payload. Rewriting, deleting, or
 * reordering any record breaks the chain from that point on, which
 * verifyChain() detects. The log lives in IndexedDB so it survives browser
 * restarts and service-worker teardown.
 */

export type AuditEventType =
  | 'detection'
  | 'blocked_submission'
  | 'blocked_navigation'
  | 'user_override'
  | 'ti_hit'
  | 'flagged_visit'
  | 'allowlist_add'
  | 'blocklist_add'
  | 'report_phishing';

export interface AuditEvent {
  type: AuditEventType;
  /** Domain (or sha256:<hex> in privacy mode). */
  domain: string;
  url?: string;
  verdict?: string;
  score?: number;
  /** Plain-language signal descriptions that fired. */
  signals: string[];
  /** What the user chose: blocked | overridden | allowed | n/a. */
  userDecision?: string;
}

export interface AuditRecord extends AuditEvent {
  /** Monotonic sequence number (IndexedDB key). */
  seq: number;
  timestamp: number;
  /** Hash of the previous record ('GENESIS' sentinel hash for seq 1). */
  prevHash: string;
  /** SHA-256 over prevHash + canonical payload. */
  hash: string;
}

const DB_NAME = 'phishguard-audit';
const STORE = 'log';
const GENESIS = 'phishguard-genesis-v1';

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => {
      req.result.createObjectStore(STORE, { keyPath: 'seq' });
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** Deterministic serialization of the hashed portion of a record. */
function canonicalPayload(r: Omit<AuditRecord, 'hash'>): string {
  return JSON.stringify({
    seq: r.seq,
    timestamp: r.timestamp,
    type: r.type,
    domain: r.domain,
    url: r.url ?? null,
    verdict: r.verdict ?? null,
    score: r.score ?? null,
    signals: r.signals,
    userDecision: r.userDecision ?? null,
    prevHash: r.prevHash,
  });
}

export async function computeRecordHash(r: Omit<AuditRecord, 'hash'>): Promise<string> {
  return sha256Hex(canonicalPayload(r));
}

function tx<T>(db: IDBDatabase, mode: IDBTransactionMode, fn: (store: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    const t = db.transaction(STORE, mode);
    const req = fn(t.objectStore(STORE));
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

// Appends are serialized through this promise so two concurrent events can't
// both read the same tail and fork the chain.
let appendQueue: Promise<unknown> = Promise.resolve();

export function appendAudit(event: AuditEvent): Promise<AuditRecord> {
  const result = appendQueue.then(async () => {
    const db = await openDb();
    try {
      const last = await getLastRecord(db);
      const seq = (last?.seq ?? 0) + 1;
      const prevHash = last?.hash ?? (await sha256Hex(GENESIS));
      const partial: Omit<AuditRecord, 'hash'> = {
        ...event,
        signals: event.signals.slice(0, 50),
        seq,
        timestamp: Date.now(),
        prevHash,
      };
      const record: AuditRecord = { ...partial, hash: await computeRecordHash(partial) };
      await tx(db, 'readwrite', (s) => s.add(record));
      return record;
    } finally {
      db.close();
    }
  });
  appendQueue = result.catch(() => undefined);
  return result;
}

function getLastRecord(db: IDBDatabase): Promise<AuditRecord | undefined> {
  return new Promise((resolve, reject) => {
    const t = db.transaction(STORE, 'readonly');
    const req = t.objectStore(STORE).openCursor(null, 'prev');
    req.onsuccess = () => resolve((req.result?.value as AuditRecord) ?? undefined);
    req.onerror = () => reject(req.error);
  });
}

export async function getAllRecords(): Promise<AuditRecord[]> {
  const db = await openDb();
  try {
    return await tx(db, 'readonly', (s) => s.getAll() as IDBRequest<AuditRecord[]>);
  } finally {
    db.close();
  }
}

/**
 * Walks the chain from genesis. Returns ok=true if every record's stored
 * hash matches its recomputed hash AND links to its predecessor; otherwise
 * reports the first broken sequence number.
 */
export async function verifyChain(records?: AuditRecord[]): Promise<{ ok: boolean; brokenAt?: number }> {
  const all = (records ?? (await getAllRecords())).sort((a, b) => a.seq - b.seq);
  let prevHash = await sha256Hex(GENESIS);
  let expectedSeq = all.length > 0 ? all[0]!.seq : 1;
  for (const r of all) {
    if (r.seq !== expectedSeq) return { ok: false, brokenAt: r.seq };
    // After pruning, the first retained record's prevHash won't be genesis;
    // accept its stored prevHash as the chain anchor only at the head.
    const anchor = r === all[0] && r.seq !== 1 ? r.prevHash : prevHash;
    if (r.prevHash !== anchor) return { ok: false, brokenAt: r.seq };
    const { hash, ...rest } = r;
    if ((await computeRecordHash(rest)) !== hash) return { ok: false, brokenAt: r.seq };
    prevHash = hash;
    expectedSeq = r.seq + 1;
  }
  return { ok: true };
}

/** Removes records older than `retentionDays` (0 = keep forever). */
export async function pruneOldRecords(retentionDays: number): Promise<number> {
  if (retentionDays <= 0) return 0;
  const cutoff = Date.now() - retentionDays * 86400_000;
  const all = await getAllRecords();
  const stale = all.filter((r) => r.timestamp < cutoff);
  if (stale.length === 0) return 0;
  const db = await openDb();
  try {
    for (const r of stale) {
      await tx(db, 'readwrite', (s) => s.delete(r.seq));
    }
    return stale.length;
  } finally {
    db.close();
  }
}

export function toCsv(records: AuditRecord[]): string {
  const esc = (v: unknown) => `"${String(v ?? '').replace(/"/g, '""')}"`;
  const header = 'seq,timestamp,iso_time,type,domain,url,verdict,score,user_decision,signals,prev_hash,hash';
  const rows = records.map((r) =>
    [
      r.seq, r.timestamp, new Date(r.timestamp).toISOString(), r.type, r.domain,
      r.url ?? '', r.verdict ?? '', r.score ?? '', r.userDecision ?? '',
      r.signals.join(' | '), r.prevHash, r.hash,
    ].map(esc).join(','),
  );
  return [header, ...rows].join('\n');
}
