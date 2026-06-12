/**
 * Password-reuse guard (N10). Warns when a password the user is about to
 * submit was previously used on a *different* origin — the canonical
 * phishing moment ("typing your real password into a fake site").
 *
 * Privacy: plaintext passwords never reach this module. The content script
 * sends a SHA-256 digest of the password over internal extension
 * messaging; here it is salted with a random per-profile salt and hashed
 * again before storage. Origins are stored as salted hashes too, so the
 * store reveals neither passwords nor browsing history.
 */

const SALT_KEY = 'pg_pwd_salt';
const STORE_KEY = 'pg_pwd_reuse'; // { [saltedPwdHash]: string[] of salted origin hashes }
const MAX_PASSWORDS = 500;
const MAX_ORIGINS_PER_PASSWORD = 30;

type ReuseStore = Record<string, string[]>;

async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function getSalt(): Promise<string> {
  const existing = (await chrome.storage.local.get(SALT_KEY))[SALT_KEY] as string | undefined;
  if (existing) return existing;
  const salt = [...crypto.getRandomValues(new Uint8Array(32))].map((b) => b.toString(16).padStart(2, '0')).join('');
  await chrome.storage.local.set({ [SALT_KEY]: salt });
  return salt;
}

async function keys(pwdDigest: string, origin: string): Promise<{ pwdKey: string; originKey: string }> {
  const salt = await getSalt();
  return {
    pwdKey: await sha256Hex(`${salt}:pwd:${pwdDigest}`),
    originKey: await sha256Hex(`${salt}:origin:${origin.toLowerCase()}`),
  };
}

/**
 * True if this password digest has been recorded on at least one origin
 * other than `origin`.
 */
export async function isPasswordReused(pwdDigest: string, origin: string): Promise<boolean> {
  const { pwdKey, originKey } = await keys(pwdDigest, origin);
  const store = ((await chrome.storage.local.get(STORE_KEY))[STORE_KEY] as ReuseStore | undefined) ?? {};
  const origins = store[pwdKey];
  if (!origins || origins.length === 0) return false;
  return origins.some((o) => o !== originKey);
}

/** Records that this password digest was used on this origin. */
export async function recordPasswordUse(pwdDigest: string, origin: string): Promise<void> {
  const { pwdKey, originKey } = await keys(pwdDigest, origin);
  const store = ((await chrome.storage.local.get(STORE_KEY))[STORE_KEY] as ReuseStore | undefined) ?? {};
  const origins = store[pwdKey] ?? [];
  if (!origins.includes(originKey)) {
    origins.push(originKey);
    if (origins.length > MAX_ORIGINS_PER_PASSWORD) origins.shift();
    store[pwdKey] = origins;
    // Bound total tracked passwords (drop an arbitrary oldest key).
    const allKeys = Object.keys(store);
    if (allKeys.length > MAX_PASSWORDS) delete store[allKeys[0]!];
    await chrome.storage.local.set({ [STORE_KEY]: store });
  }
}
