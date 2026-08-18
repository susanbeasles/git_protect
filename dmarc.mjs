// DMARC checks. RFC 7489.
import { parseDMARC, isDMARC, reportAddresses } from '../parse/dmarc.mjs';
import { duplicates } from '../records.mjs';

const dmarcRecords = ctx => ctx.records.filter(r => r.type === 'TXT' && isDMARC(r.content));

export const checks = [
{
  code: 'DMARC_DUPLICATE', scope: 'zone',
  run(ctx) {
    for (const [name, group] of duplicates(dmarcRecords(ctx), r => r.name)) {
      ctx.add({
        severity: 'CRITICAL', scope: 'zone', code: 'DMARC_DUPLICATE',
        title: `${group.length} DMARC records on one name`, where: [name],
        detail: 'RFC 7489 §6.6.3: when multiple DMARC records are found, receivers apply NO policy at all. Your published p= value has never been in effect, and you receive no aggregate reports — which is why the failure has been invisible.',
        remediation: 'Collapse to exactly one record. Fix SPF and DKIM on every sending stream FIRST — deleting the duplicate switches enforcement on for the whole org domain at once.',
        refs: ['RFC 7489 §6.6.3'], evidence: { count: group.length },
      });
    }
  },
},
{
  code: 'DMARC_SYNTAX', scope: 'record',
  run(ctx) {
    for (const rec of dmarcRecords(ctx)) {
      for (const err of parseDMARC(rec.content).errors) {
        ctx.add({
          severity: 'HIGH', scope: 'record', code: 'DMARC_SYNTAX',
          title: 'DMARC syntax error', where: [rec.name], detail: err,
          remediation: 'Malformed DMARC is treated as absent by many receivers.',
          refs: ['RFC 7489 §6.3'],
        });
      }
    }
  },
},
{
  code: 'DMARC_PLACEMENT', scope: 'record',
  run(ctx) {
    for (const rec of dmarcRecords(ctx)) {
      if (!rec.name.startsWith('_dmarc.') && rec.name !== `_dmarc.${ctx.zone}`) ctx.add({
        severity: 'HIGH', scope: 'record', code: 'DMARC_WRONG_NAME',
        title: 'DMARC record not published at _dmarc', where: [rec.name],
        detail: 'DMARC is only read from _dmarc.<domain>. Anywhere else it is inert.',
        remediation: `Move it to _dmarc.${ctx.zone}.`,
      });
    }
  },
},
{
  code: 'DMARC_POLICY', scope: 'zone',
  run(ctx) {
    for (const rec of dmarcRecords(ctx)) {
      const t = parseDMARC(rec.content).tags;
      const policy = (t.p || '').toLowerCase();
      const at = [rec.name];

      if (policy === 'none') ctx.add({
        severity: 'HIGH', scope: 'zone', code: 'DMARC_P_NONE',
        title: 'DMARC policy is p=none (monitoring only)', where: at,
        detail: 'Receivers take no action on failures. Anyone can spoof this domain and the mail is still accepted.',
        remediation: 'Move to p=quarantine, then p=reject, once every legitimate stream passes SPF or DKIM with alignment.',
      });
      if (!t.rua) ctx.add({
        severity: 'MEDIUM', scope: 'zone', code: 'DMARC_NO_RUA',
        title: 'no aggregate report address (rua=)', where: at,
        detail: 'Without rua you get no visibility into which senders are failing — you are enforcing blind.',
        remediation: 'Add rua=mailto:<your dmarc mailbox>.',
      });
      if (t.pct !== undefined && Number(t.pct) < 100 && policy !== 'none') ctx.add({
        severity: 'LOW', scope: 'zone', code: 'DMARC_PCT',
        title: `pct=${t.pct} — policy applies to a subset`, where: at,
        detail: 'Useful while ramping, but a permanent partial rollout is a permanent spoofing gap.',
        remediation: 'Raise to 100 once clean.',
      });
      if (!t.sp && policy) {
        const subs = [...new Set(ctx.records.map(r => r.name))]
          .filter(n => n !== ctx.zone && n.endsWith('.' + ctx.zone) && !n.startsWith('_'));
        ctx.add({
          severity: 'MEDIUM', scope: 'zone', code: 'DMARC_NO_SP',
          title: 'no explicit subdomain policy (sp=)', where: at,
          detail: `Without sp=, every subdomain inherits p=${policy}. This zone has ${subs.length} subdomain name(s), including active mail senders. Inheritance by omission means the next person cannot tell whether it was a decision.`,
          remediation: 'Set sp= explicitly, even if it matches p=.',
          evidence: { subdomainCount: subs.length },
        });
      }
      if ((t.adkim || 'r').toLowerCase() === 's' || (t.aspf || 'r').toLowerCase() === 's') ctx.add({
        severity: 'MEDIUM', scope: 'zone', code: 'DMARC_STRICT_ALIGN',
        title: 'strict alignment is enabled', where: at,
        detail: `Strict alignment requires an exact domain match, not an organisational-domain match. If the envelope-from is on a subdomain (bounces@mail.${ctx.zone}) while From: is @${ctx.zone}, strict SPF alignment fails every one of those messages.`,
        remediation: 'Use relaxed (adkim=r, aspf=r) unless From: and envelope domains match exactly.',
        refs: ['RFC 7489 §3.1'],
      });
    }
  },
},
{
  code: 'DMARC_RUF_PRIVACY', scope: 'zone',
  run(ctx) {
    for (const rec of dmarcRecords(ctx)) {
      const t = parseDMARC(rec.content).tags;
      if (!t.ruf) continue;
      ctx.add({
        severity: 'MEDIUM', scope: 'zone', code: 'DMARC_RUF_PRIVACY',
        title: 'forensic reports (ruf=) leak message content', where: [rec.name],
        detail: `ruf= failure reports can include message headers and subject lines. In a clinical or care-coordination context subject lines routinely carry patient names, appointment details, or record numbers — so this is a third-party disclosure of PHI to whoever operates the ruf destination${t.fo ? ` (fo=${t.fo} widens when reports fire)` : ''}.`,
        remediation: 'Confirm the ruf destination is covered by a BAA. If it is not, remove ruf= and fo= and keep rua= — aggregate reports carry counts and auth results, never message content.',
        refs: ['RFC 7489 §7.3'], evidence: { ruf: t.ruf, fo: t.fo || null },
      });
    }
  },
},
{
  code: 'DMARC_EXTERNAL_REPORTS', scope: 'zone', needsNetwork: true,
  async run(ctx) {
    for (const rec of dmarcRecords(ctx)) {
      const t = parseDMARC(rec.content).tags;
      const origin = rec.name.replace(/^_dmarc\./, '');
      for (const tag of ['rua', 'ruf']) {
        for (const dest of reportAddresses(t[tag])) {
          if (dest.error || !dest.domain) continue;
          if (dest.domain === origin || dest.domain.endsWith('.' + origin)) continue;
          const probe = `${origin}._report._dmarc.${dest.domain}`;
          const res = await ctx.query(probe, 'TXT');
          if ((res.data || []).some(s => /v=DMARC1/i.test(s))) continue;
          ctx.add({
            severity: 'HIGH', scope: 'zone', code: 'DMARC_EXTERNAL_UNAUTHORISED',
            title: `external ${tag} destination is not authorised`, where: [rec.name],
            detail: `Reports are addressed to ${dest.domain}, a different organisational domain. RFC 7489 §7.1 requires ${probe} to publish a DMARC record before receivers will send reports there. That record is missing or unreadable, so most receivers — Google and Microsoft included — silently drop your reports.`,
            remediation: `Ask the report provider to publish the authorisation record, or point ${tag}= at a mailbox on ${origin}.`,
            refs: ['RFC 7489 §7.1'], evidence: { probe, destination: dest.domain },
          });
        }
      }
    }
  },
},
];
