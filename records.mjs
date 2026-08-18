// Record-list helpers shared by every check. Normalisation lives here only.
export const unquote = s =>
  String(s || '').replace(/^"|"$/g, '').replace(/"\s*"/g, '');

export function normalize(records) {
  return records.map(r => ({
    ...r,
    name: String(r.name || '').toLowerCase().replace(/\.$/, ''),
    type: String(r.type || '').toUpperCase(),
    content: unquote(r.content),
    proxied: r.proxied === true,
    tags: r.tags || [],
    priority: r.priority ?? null,
  }));
}

export function groupBy(list, keyFn) {
  return list.reduce((m, x) => {
    const k = keyFn(x);
    (m[k] = m[k] || []).push(x);
    return m;
  }, {});
}

// Duplicate groups on a key — the shape every "N records on one name" check needs.
export function duplicates(list, keyFn) {
  return Object.entries(groupBy(list, keyFn)).filter(([, g]) => g.length > 1);
}

export function relativeName(fqdn, zone) {
  if (fqdn === zone) return '@';
  return fqdn.endsWith('.' + zone) ? fqdn.slice(0, -(zone.length + 1)) : fqdn;
}
