// DNS resolution with a seeded cache.
//
// Names inside the zone under analysis resolve from the records we were handed,
// not from live DNS. Without that, analysing a snapshot or a proposed change
// would silently mix two sources of truth. Only external names hit the network.
import { Resolver } from 'node:dns/promises';

const TYPES = {
  TXT:   (r, n) => r.resolveTxt(n).then(a => a.map(x => x.join(''))),
  MX:    (r, n) => r.resolveMx(n),
  A:     (r, n) => r.resolve4(n),
  AAAA:  (r, n) => r.resolve6(n),
  CNAME: (r, n) => r.resolveCname(n),
  NS:    (r, n) => r.resolveNs(n),
};

const NOT_FOUND = ['ENOTFOUND', 'ENODATA', 'NXDOMAIN'];

export function createResolver({ offline = false, servers = ['1.1.1.1', '8.8.8.8', '9.9.9.9'] } = {}) {
  const cache = new Map();
  const resolver = new Resolver({ timeout: 4000, tries: 2 });
  try { resolver.setServers(servers); } catch { /* fall back to system */ }

  const key = (type, name) => `${type}:${name}`.toLowerCase();

  async function query(name, type) {
    if (offline) return { ok: false, offline: true, empty: true, data: [] };
    const k = key(type, name);
    if (cache.has(k)) return cache.get(k);
    let result;
    try {
      const fn = TYPES[type];
      const data = fn ? await fn(resolver, name) : [];
      result = { ok: true, data, empty: data.length === 0 };
    } catch (e) {
      const missing = NOT_FOUND.includes(e.code);
      result = { ok: false, code: e.code, nxdomain: missing, empty: true, data: [] };
    }
    cache.set(k, result);
    return result;
  }

  // Treat the supplied records as authoritative for their own names, including
  // authoritative negatives: a name present in the zone with no TXT genuinely
  // has no TXT.
  function seed(records) {
    if (offline) return;
    const byName = new Map();
    for (const r of records) {
      const n = r.name.toLowerCase();
      if (!byName.has(n)) byName.set(n, []);
      byName.get(n).push(r);
    }
    for (const [name, group] of byName) {
      for (const type of Object.keys(TYPES)) {
        const hit = group.filter(r => r.type === type);
        if (hit.length) {
          const data = type === 'MX'
            ? hit.map(r => ({ exchange: r.content, priority: r.priority ?? 0 }))
            : hit.map(r => r.content);
          cache.set(key(type, name), { ok: true, data, empty: false, seeded: true });
        } else if (type === 'TXT' || type === 'MX') {
          cache.set(key(type, name), { ok: true, data: [], empty: true, seeded: true });
        }
      }
    }
  }

  return { query, seed, get size() { return cache.size; } };
}
