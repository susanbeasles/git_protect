// Practical RFC 5322 validation — strict on what actually breaks report delivery.
export function isValidEmail(address) {
  if (!address || address.length > 254) return false;
  const at = address.lastIndexOf('@');
  if (at < 1 || at === address.length - 1) return false;
  const local = address.slice(0, at);
  const domain = address.slice(at + 1);
  if (local.length > 64) return false;
  if (/^\.|\.$|\.\./.test(local)) return false;
  if (!/^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+$/.test(local)) return false;
  return isValidHostname(domain);
}

export function isValidHostname(domain) {
  if (!domain || domain.length > 253 || !domain.includes('.')) return false;
  if (/^-|-$|^\.|\.$|\.\./.test(domain)) return false;
  return domain.split('.').every(l => l.length >= 1 && l.length <= 63 && /^[A-Za-z0-9-]+$/.test(l));
}

// Are two names in the same organisational domain? Approximated by suffix match,
// which is what DMARC relaxed alignment needs in practice.
export function sameOrgDomain(a, b) {
  a = String(a).toLowerCase(); b = String(b).toLowerCase();
  return a === b || a.endsWith('.' + b) || b.endsWith('.' + a);
}
