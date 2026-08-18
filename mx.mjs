// MX record hygiene. RFC 2181 §10.3 and Cloudflare-specific traps.
import { groupBy } from '../records.mjs';

export const checks = [
{
  code: 'MX_CONFIG', scope: 'record',
  run(ctx) {
    for (const rec of ctx.records.filter(r => r.type === 'MX')) {
      if (rec.proxied) ctx.add({
        severity: 'CRITICAL', scope: 'record', code: 'MX_PROXIED',
        title: 'MX record is proxied through Cloudflare', where: [rec.name],
        detail: 'Cloudflare does not proxy SMTP. A proxied MX record breaks inbound mail entirely.',
        remediation: 'Set this record to DNS only (grey cloud).',
      });
      if (rec.priority === null) ctx.add({
        severity: 'MEDIUM', scope: 'record', code: 'MX_NO_PRIORITY',
        title: 'MX record has no priority', where: [rec.name],
        detail: 'An MX record without a preference value is invalid and may be rejected or defaulted unpredictably.',
        remediation: 'Set an explicit priority.',
      });
    }
  },
},
{
  code: 'MX_TARGETS', scope: 'zone', needsNetwork: true,
  async run(ctx) {
    for (const rec of ctx.records.filter(r => r.type === 'MX' && r.content)) {
      const target = rec.content.replace(/\.$/, '');
      const cname = await ctx.query(target, 'CNAME');
      if ((cname.data || []).length) ctx.add({
        severity: 'MEDIUM', scope: 'zone', code: 'MX_TO_CNAME',
        title: 'MX target is a CNAME', where: [rec.name],
        detail: `RFC 2181 §10.3 requires an MX target to be a hostname with an address record, not an alias. ${target} is a CNAME.`,
        remediation: 'Point the MX at a name with A/AAAA records.', refs: ['RFC 2181 §10.3'],
      });
      const a = await ctx.query(target, 'A');
      const aaaa = await ctx.query(target, 'AAAA');
      if (a.empty && aaaa.empty && !(cname.data || []).length) ctx.add({
        severity: 'HIGH', scope: 'zone', code: 'MX_UNRESOLVABLE',
        title: 'MX target does not resolve', where: [rec.name],
        detail: `${target} has no A or AAAA record. Mail to this domain cannot be delivered.`,
        remediation: 'Correct the hostname or remove the record.',
      });
    }
  },
},
{
  code: 'MX_PRIORITY_SPREAD', scope: 'zone',
  run(ctx) {
    const mx = ctx.records.filter(r => r.type === 'MX');
    for (const [name, group] of Object.entries(groupBy(mx, r => r.name))) {
      const prios = group.map(r => r.priority).filter(p => p !== null);
      if (group.length > 1 && prios.length > 1 && new Set(prios).size === 1) ctx.add({
        severity: 'INFO', scope: 'zone', code: 'MX_EQUAL_PRIORITY',
        title: 'all MX records share one priority', where: [name],
        detail: 'Equal preference means round-robin. Intentional for load spreading, a mistake if you meant primary and backup.',
        remediation: 'No action if deliberate.',
      });
    }
  },
},
];
