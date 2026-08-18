// DKIM checks. RFC 6376.
import { parseDKIM, isDKIMName } from '../parse/dkim.mjs';

const dkimRecords = ctx => ctx.records.filter(r => isDKIMName(r.name));

export const checks = [
{
  code: 'DKIM_SYNTAX', scope: 'record',
  run(ctx) {
    for (const rec of dkimRecords(ctx)) {
      if (rec.type === 'CNAME') continue;        // delegated; checked live below
      const parsed = parseDKIM(rec.content);
      for (const err of parsed.errors) {
        ctx.add({
          severity: err.includes('REVOKED') ? 'HIGH' : 'MEDIUM',
          scope: 'record', code: 'DKIM_SYNTAX',
          title: 'DKIM record problem', where: [rec.name], detail: err,
          remediation: 'Re-copy the public key from the sending platform.',
        });
      }
      if (parsed.bits !== null && parsed.bits < 1024) ctx.add({
        severity: 'HIGH', scope: 'record', code: 'DKIM_WEAK',
        title: `DKIM key looks like ~${parsed.bits} bits`, where: [rec.name],
        detail: 'Keys under 1024 bits are rejected outright by several major receivers.',
        remediation: 'Rotate to 2048-bit at the provider.',
      });
      else if (parsed.bits === 1024) ctx.add({
        severity: 'LOW', scope: 'record', code: 'DKIM_1024',
        title: 'DKIM key is 1024-bit', where: [rec.name],
        detail: 'Accepted everywhere but below current guidance.',
        remediation: 'Rotate to 2048-bit at the next opportunity.',
      });
    }
  },
},
{
  code: 'DKIM_LIVENESS', scope: 'zone', needsNetwork: true,
  async run(ctx) {
    for (const name of [...new Set(dkimRecords(ctx).map(r => r.name))]) {
      const txt = await ctx.query(name, 'TXT');
      const cname = await ctx.query(name, 'CNAME');
      const live = (txt.data || []).some(x => /(v=DKIM1|p=)/i.test(x))
                || (cname.data || []).length > 0;
      if (live) continue;
      ctx.add({
        severity: 'HIGH', scope: 'zone', code: 'DKIM_DEAD',
        title: 'DKIM selector does not resolve', where: [name],
        detail: 'The record is in the zone but public DNS returns nothing usable. Mail signed with this selector fails DKIM verification.',
        remediation: 'Check for a truncated or badly split key value, or a CNAME target that no longer exists.',
      });
    }
  },
},
];
