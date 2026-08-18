// The finding model. One place that defines severity, scope, and shape.
export const SEVERITY = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
export const SEVERITY_RANK = Object.fromEntries(SEVERITY.map((s, i) => [s, i]));

// scope tells consumers whether a finding can be judged from one record alone.
//   'record' — syntax and self-consistency. Safe to run on a single record, so
//              `cf dns add` can pre-flight what you are about to publish.
//   'zone'   — needs the whole zone. Meaningless for one record: a lone MX
//              record always "has no SPF" because the SPF record is elsewhere.
export const SCOPES = ['record', 'zone'];

export function createCollector() {
  const findings = [];
  let seq = 0;

  function add(f) {
    if (!SEVERITY.includes(f.severity)) throw new Error(`bad severity: ${f.severity}`);
    if (!SCOPES.includes(f.scope)) throw new Error(`bad scope: ${f.scope} on ${f.code}`);
    findings.push({
      id: `F${String(++seq).padStart(3, '0')}`,
      severity: f.severity,
      scope: f.scope,
      code: f.code,
      title: f.title,
      where: f.where || [],
      detail: f.detail,
      remediation: f.remediation,
      fix: f.fix || null,
      refs: f.refs || [],
      evidence: f.evidence || {},
    });
  }

  function sorted() {
    return [...findings].sort((a, b) =>
      SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] || a.code.localeCompare(b.code));
  }

  function counts() {
    return findings.reduce((m, f) => ((m[f.severity] = (m[f.severity] || 0) + 1), m), {});
  }

  return { add, sorted, counts, get length() { return findings.length; } };
}
