// Zone hygiene: takeover risk, origin exposure, structural DNS violations.
import { groupBy, duplicates } from '../records.mjs';
import { isSPF } from '../parse/spf.mjs';
import { isDMARC } from '../parse/dmarc.mjs';

export const checks = [
{
  code: 'CNAME_STRUCTURE', scope: 'zone',
  run(ctx) {
    const byName = groupBy(ctx.records, r => r.name);
    for (const rec of ctx.records.filter(r => r.type === 'CNAME')) {
      const others = (byName[rec.name] || []).filter(r => r.type !== 'CNAME');
      if (others.length) ctx.add({
        severity: 'HIGH', scope: 'zone', code: 'CNAME_COEXIST',
        title: 'CNAME coexists with other record types', where: [rec.name],
        detail: `RFC 1034 forbids a CNAME alongside other data at the same name. Also present: ${[...new Set(others.map(o => o.type))].join(', ')}.`,
        remediation: 'Remove the CNAME or the conflicting records.', refs: ['RFC 1034 §3.6.2'],
      });
      if (rec.name === ctx.zone) ctx.add({
        severity: 'MEDIUM', scope: 'zone', code: 'CNAME_APEX',
        title: 'CNAME at the zone apex', where: [rec.name],
        detail: 'Invalid in plain DNS. Cloudflare flattens it so it works here, but it breaks if the zone ever moves to another provider.',
        remediation: 'Prefer A/AAAA at the apex, or accept the provider lock-in knowingly.',
      });
    }
  },
},
{
  code: 'CNAME_DANGLING', scope: 'zone', needsNetwork: true,
  async run(ctx) {
    for (const rec of ctx.records.filter(r => r.type === 'CNAME')) {
      const target = rec.content.replace(/\.$/, '');
      const [a, cname, txt] = await Promise.all([
        ctx.query(target, 'A'), ctx.query(target, 'CNAME'), ctx.query(target, 'TXT'),
      ]);
      if (!(a.nxdomain && cname.nxdomain && txt.nxdomain)) continue;
      ctx.add({
        severity: 'HIGH', scope: 'zone', code: 'CNAME_DANGLING',
        title: 'dangling CNAME — subdomain takeover risk', where: [rec.name],
        detail: `${rec.name} points at ${target}, which does not resolve. If that target sits on a SaaS platform where anyone can claim an unused hostname, an attacker can serve content on your subdomain — and obtain a valid TLS certificate for it.`,
        remediation: 'Delete the record, or re-claim the resource at the provider.',
        evidence: { target },
      });
    }
  },
},
{
  code: 'ORIGIN_EXPOSURE', scope: 'record',
  run(ctx) {
    for (const rec of ctx.records.filter(r => r.type === 'A' || r.type === 'AAAA')) {
      if (rec.proxied) continue;
      ctx.add({
        severity: 'LOW', scope: 'record', code: 'ORIGIN_EXPOSED',
        title: 'unproxied address record exposes origin', where: [rec.name],
        detail: 'DNS only (grey cloud) publishes the origin address directly, so Cloudflare WAF, DDoS protection, and rate limiting can be bypassed by connecting to it.',
        remediation: 'Proxy it, or confirm the host is firewalled to Cloudflare ranges only. Mail hosts and some verification records legitimately cannot be proxied.',
      });
    }
  },
},
{
  code: 'ZONE_HYGIENE', scope: 'zone',
  run(ctx) {
    for (const [name, group] of duplicates(ctx.records, r => `${r.name}|${r.type}|${r.content}`)) {
      const rec = group[0];
      if (isSPF(rec.content) || isDMARC(rec.content)) continue;   // reported by their own checks
      ctx.add({
        severity: 'LOW', scope: 'zone', code: 'EXACT_DUPLICATE',
        title: 'exact duplicate records', where: [rec.name],
        detail: `${group.length} identical ${rec.type} records. Harmless but confusing, and a sign of drift.`,
        remediation: 'Delete the extras.',
      });
    }
    for (const rec of ctx.records) {
      if (rec.name.startsWith('*')) ctx.add({
        severity: 'MEDIUM', scope: 'record', code: 'WILDCARD',
        title: 'wildcard record present', where: [rec.name],
        detail: `A wildcard ${rec.type} answers for every undefined name, which defeats dangling-CNAME detection and can accidentally accept mail or traffic for names you never created.`,
        remediation: 'Prefer explicit records.',
      });
      if (rec.ttl > 1 && rec.ttl < 60) ctx.add({
        severity: 'LOW', scope: 'record', code: 'TTL_LOW',
        title: 'very low TTL', where: [rec.name],
        detail: `ttl=${rec.ttl}s increases query volume with little benefit outside a migration window.`,
        remediation: 'Use 300 while changing things, then raise to 3600+.',
      });
    }
  },
},
];
