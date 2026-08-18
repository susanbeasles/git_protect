// Cross-record mail-stream coverage: does every sending name have SPF, DKIM, DMARC?
// These are inherently zone-scoped — a single MX record can never prove SPF is
// absent, because the SPF record is a different record.
import { isSPF } from '../parse/spf.mjs';
import { isDMARC } from '../parse/dmarc.mjs';
import { isDKIMName } from '../parse/dkim.mjs';
import { relativeName } from '../records.mjs';

export const checks = [
{
  code: 'MAIL_COVERAGE', scope: 'zone',
  run(ctx) {
    const mx = ctx.records.filter(r => r.type === 'MX');
    const spfNames = new Set(ctx.records.filter(r => r.type === 'TXT' && isSPF(r.content)).map(r => r.name));
    const dkim = ctx.records.filter(r => isDKIMName(r.name));
    const dmarc = ctx.records.filter(r => r.type === 'TXT' && isDMARC(r.content));

    for (const name of [...new Set(mx.map(r => r.name))]) {
      if (!spfNames.has(name)) ctx.add({
        severity: 'CRITICAL', scope: 'zone', code: 'MX_NO_SPF',
        title: 'mail-handling name has no SPF record', where: [name],
        detail: `${name} has MX records but publishes no SPF. If this name is used as an envelope-from (Return-Path) domain, SPF evaluates to "none" and the stream leans entirely on DKIM. Under an enforcing DMARC policy, any stream where DKIM also fails is quarantined or rejected.`,
        remediation: 'Publish SPF authorising the platform that sends for this name.',
        fix: `cf dns add --name ${relativeName(name, ctx.zone)} --type TXT --content "v=spf1 include:<platform> ~all" --ttl 300 --tags email,spf`,
      });
      if (!dkim.some(r => r.name.endsWith(`._domainkey.${name}`))) ctx.add({
        severity: 'HIGH', scope: 'zone', code: 'MX_NO_DKIM',
        title: 'mail-handling name has no DKIM selector', where: [name],
        detail: `No _domainkey record found under ${name}. DKIM is the only auth mechanism that survives forwarding — SPF breaks whenever a message is relayed, so a stream with SPF but no DKIM fails DMARC on any forwarded mail.`,
        remediation: 'Enable DKIM signing at the platform and publish the selector it gives you.',
      });
    }

    if (mx.length && !dmarc.length) ctx.add({
      severity: 'CRITICAL', scope: 'zone', code: 'NO_DMARC',
      title: 'zone handles mail but publishes no DMARC record', where: [ctx.zone],
      detail: 'Without DMARC, SPF and DKIM failures carry no policy and anyone can spoof the domain.',
      remediation: `Publish _dmarc.${ctx.zone}. Fix auth on every stream first, then go straight to p=quarantine.`,
    });
  },
},
];
