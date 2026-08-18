// SPF checks. RFC 7208.
import { parseSPF, isSPF, lookupTerms, LOOKUP_MECHANISMS } from '../parse/spf.mjs';
import { duplicates, relativeName } from '../records.mjs';

const spfRecords = ctx => ctx.records.filter(r => r.type === 'TXT' && isSPF(r.content));

// Recursive lookup cost. Separate from the checks so it can be tested alone.
export async function spfCost(query, domain, depth = 0, seen = new Set()) {
  const out = { lookups: 0, voids: 0, loop: false, unresolved: [] };
  if (depth > 10) { out.loop = true; return out; }
  const k = domain.toLowerCase();
  if (seen.has(k)) { out.loop = true; return out; }
  seen.add(k);

  const txt = await query(domain, 'TXT');
  const spf = (txt.data || []).filter(s => isSPF(s));
  if (!spf.length) { out.voids++; out.unresolved.push(domain); return out; }

  const parsed = parseSPF(spf[0]);
  if (!parsed.valid) return out;
  const { terms, redirect } = lookupTerms(parsed);

  for (const m of terms) {
    out.lookups++;
    if (m.name === 'include' && m.value) {
      const sub = await spfCost(query, m.value, depth + 1, seen);
      out.lookups += sub.lookups; out.voids += sub.voids;
      out.loop = out.loop || sub.loop;
      out.unresolved.push(...sub.unresolved);
    } else if (['a', 'mx', 'exists'].includes(m.name)) {
      const target = m.value || domain;
      const res = await query(target, m.name === 'mx' ? 'MX' : 'A');
      if (res.empty) { out.voids++; out.unresolved.push(target); }
    }
  }
  if (redirect) {
    out.lookups++;
    const sub = await spfCost(query, redirect, depth + 1, seen);
    out.lookups += sub.lookups; out.voids += sub.voids;
    out.loop = out.loop || sub.loop;
  }
  return out;
}

export const checks = [
{
  code: 'SPF_DUPLICATE', scope: 'zone',
  run(ctx) {
    for (const [name, group] of duplicates(spfRecords(ctx), r => r.name)) {
      ctx.add({
        severity: 'CRITICAL', scope: 'zone', code: 'SPF_DUPLICATE',
        title: `${group.length} SPF records on one name`, where: [name],
        detail: 'RFC 7208 §3.2 permits exactly one SPF record per name. More than one is an unconditional PermError — receivers treat SPF as unusable, and strict ones reject. Identical content does not exempt it.',
        remediation: 'Delete all but one. If they differ, merge the mechanisms into a single record first.',
        fix: `cf dns rm --name ${relativeName(name, ctx.zone)} --type TXT --content "v=spf1"`,
        refs: ['RFC 7208 §3.2'],
        evidence: { count: group.length, contents: group.map(r => r.content) },
      });
    }
  },
},
{
  code: 'SPF_SYNTAX', scope: 'record',
  run(ctx) {
    for (const rec of spfRecords(ctx)) {
      const parsed = parseSPF(rec.content);
      if (!parsed.valid) {
        ctx.add({
          severity: 'CRITICAL', scope: 'record', code: 'SPF_INVALID',
          title: 'SPF record is not valid', where: [rec.name],
          detail: parsed.reason,
          remediation: 'An SPF record must begin exactly with "v=spf1".',
          refs: ['RFC 7208 §4.5'],
        });
        continue;
      }
      for (const err of parsed.errors) {
        ctx.add({
          severity: 'HIGH', scope: 'record', code: 'SPF_SYNTAX',
          title: 'SPF syntax error', where: [rec.name], detail: err,
          remediation: 'Unrecognised terms cause a PermError on strict receivers. Remove or correct.',
          refs: ['RFC 7208 §4.6'],
        });
      }
    }
  },
},
{
  code: 'SPF_SEMANTICS', scope: 'record',
  run(ctx) {
    for (const rec of spfRecords(ctx)) {
      const p = parseSPF(rec.content);
      if (!p.valid) continue;
      const alls = p.mechanisms.filter(m => m.name === 'all');
      const idx = p.mechanisms.findIndex(m => m.name === 'all');
      const hasRedirect = p.modifiers.some(m => m.key === 'redirect');
      const at = [rec.name];

      if (alls.some(m => m.qualifier === '+')) ctx.add({
        severity: 'CRITICAL', scope: 'record', code: 'SPF_PLUS_ALL',
        title: '"+all" authorises the entire internet', where: at,
        detail: 'Any host on the internet passes SPF for this domain. This is worse than having no SPF record at all.',
        remediation: 'Change to -all immediately.',
      });
      if (!alls.length && !hasRedirect) ctx.add({
        severity: 'MEDIUM', scope: 'record', code: 'SPF_NO_ALL',
        title: 'SPF has no "all" mechanism', where: at,
        detail: 'Without a terminating all (or redirect=), the result for unlisted senders is Neutral — effectively no protection.',
        remediation: 'End the record with -all once every legitimate sender is listed, or ~all while validating.',
      });
      if (alls.length > 1) ctx.add({
        severity: 'HIGH', scope: 'record', code: 'SPF_MULTI_ALL',
        title: 'more than one "all" mechanism', where: at,
        detail: 'Only the first is evaluated; the rest are dead config that will mislead the next person.',
        remediation: 'Keep exactly one, as the final term.',
      });
      if (idx >= 0 && idx < p.mechanisms.length - 1) ctx.add({
        severity: 'MEDIUM', scope: 'record', code: 'SPF_TERMS_AFTER_ALL',
        title: 'mechanisms after "all" are unreachable', where: at,
        detail: `${p.mechanisms.length - 1 - idx} term(s) sit after "all" and will never be evaluated.`,
        remediation: 'Move "all" to the end.', refs: ['RFC 7208 §5.1'],
      });
      if (p.mechanisms.some(m => m.name === 'ptr')) ctx.add({
        severity: 'MEDIUM', scope: 'record', code: 'SPF_PTR',
        title: '"ptr" mechanism is deprecated', where: at,
        detail: 'RFC 7208 §5.5 says explicitly not to use ptr; it is slow and some receivers ignore or fail it.',
        remediation: 'Replace with ip4/ip6 or include.', refs: ['RFC 7208 §5.5'],
      });
      if (hasRedirect && alls.length) ctx.add({
        severity: 'MEDIUM', scope: 'record', code: 'SPF_REDIRECT_AND_ALL',
        title: 'redirect= is ignored when "all" is present', where: at,
        detail: 'When an all mechanism matches, the redirect modifier is never used.',
        remediation: 'Use one or the other.', refs: ['RFC 7208 §6.1'],
      });
      if (rec.content.length > 255) ctx.add({
        severity: 'LOW', scope: 'record', code: 'TXT_LONG',
        title: 'TXT value exceeds 255 characters', where: at,
        detail: `${rec.content.length} chars. A single DNS character-string caps at 255, so the record must be split into multiple strings. Cloudflare handles this, but hand-pasted values sometimes get truncated instead.`,
        remediation: 'Verify with dig that the full value comes back.',
      });
    }
  },
},
{
  code: 'SPF_LOOKUPS', scope: 'zone', needsNetwork: true,
  async run(ctx) {
    for (const rec of spfRecords(ctx)) {
      const cost = await spfCost(ctx.query, rec.name);
      const evidence = {
        lookups: cost.lookups, voidLookups: cost.voids,
        unresolved: [...new Set(cost.unresolved)],
      };
      const at = [rec.name];

      if (cost.loop) ctx.add({
        severity: 'CRITICAL', scope: 'zone', code: 'SPF_LOOP',
        title: 'SPF include loop or excessive nesting', where: at,
        detail: 'Recursive evaluation exceeded safe depth or revisited a domain — PermError.',
        remediation: 'Flatten or remove the offending include chain.', evidence,
      });
      if (cost.lookups > 10) ctx.add({
        severity: 'CRITICAL', scope: 'zone', code: 'SPF_LOOKUP_LIMIT',
        title: `SPF needs ${cost.lookups} DNS lookups (limit is 10)`, where: at,
        detail: 'RFC 7208 §4.6.4 caps SPF at 10 DNS-querying mechanisms. Over the cap is a PermError, which means the terminating "-all" is never reached and SPF provides no protection at all.',
        remediation: 'Remove unused includes; every retired vendor left in the record costs lookups. Do NOT flatten to raw IPs — that silently rots when vendors rotate address space.',
        refs: ['RFC 7208 §4.6.4'], evidence,
      });
      else if (cost.lookups >= 8) ctx.add({
        severity: 'MEDIUM', scope: 'zone', code: 'SPF_LOOKUP_NEAR_LIMIT',
        title: `SPF at ${cost.lookups}/10 DNS lookups`, where: at,
        detail: 'Little headroom. A vendor adding one nested include on their side breaks your SPF without you changing anything.',
        remediation: 'Retire unused includes now to buy margin.', evidence,
      });
      if (cost.voids > 2) ctx.add({
        severity: 'HIGH', scope: 'zone', code: 'SPF_VOID_LIMIT',
        title: `${cost.voids} void lookups (limit is 2)`, where: at,
        detail: 'RFC 7208 §4.6.4 caps void (empty or NXDOMAIN) lookups at 2. Exceeding it is a PermError.',
        remediation: `Remove includes that no longer resolve: ${evidence.unresolved.join(', ') || 'see evidence'}`,
        refs: ['RFC 7208 §4.6.4'], evidence,
      });
      else if (cost.voids > 0) ctx.add({
        severity: 'MEDIUM', scope: 'zone', code: 'SPF_VOID',
        title: `${cost.voids} include(s) do not resolve`, where: at,
        detail: `Dead includes waste lookups and count toward the void limit: ${evidence.unresolved.join(', ')}`,
        remediation: 'Remove them.', evidence,
      });
    }
  },
},
];
