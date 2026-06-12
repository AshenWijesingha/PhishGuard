import { describe, expect, it } from 'vitest';
import { DEFAULT_THRESHOLDS, DEFAULT_WEIGHTS, scoreSignals, type Signal } from '../src/core/scoring';

const sig = (id: Signal['id'], weight?: number): Signal => ({ id, reason: id, weight });

describe('scoring engine (M8)', () => {
  it('returns safe with no signals', () => {
    const r = scoreSignals([]);
    expect(r.verdict).toBe('safe');
    expect(r.score).toBe(0);
  });

  it('maps weights to verdict tiers', () => {
    expect(scoreSignals([sig('suspicious_tld')]).verdict).toBe('safe'); // 10 < 25
    expect(scoreSignals([sig('cross_origin_action')]).verdict).toBe('suspicious'); // 30
    expect(scoreSignals([sig('cross_origin_action'), sig('typosquat')]).verdict).toBe('high_risk'); // 70
    expect(scoreSignals([sig('threat_intel_hit')]).verdict).toBe('malicious');
    expect(scoreSignals([sig('local_blocklist_hit')]).verdict).toBe('malicious');
  });

  it('an allowlist hit pins the verdict to safe', () => {
    const r = scoreSignals([sig('threat_intel_hit'), sig('local_allowlist_hit')]);
    expect(r.verdict).toBe('safe');
  });

  it('respects per-signal weight overrides', () => {
    expect(scoreSignals([sig('suspicious_tld', 60)]).verdict).toBe('high_risk');
  });

  it('respects custom thresholds', () => {
    const strict = { suspicious: 5, highRisk: 9, malicious: 1000 };
    expect(scoreSignals([sig('suspicious_tld')], DEFAULT_WEIGHTS, strict).verdict).toBe('high_risk');
  });

  it('default thresholds are ordered', () => {
    expect(DEFAULT_THRESHOLDS.suspicious).toBeLessThan(DEFAULT_THRESHOLDS.highRisk);
    expect(DEFAULT_THRESHOLDS.highRisk).toBeLessThan(DEFAULT_THRESHOLDS.malicious);
  });
});
