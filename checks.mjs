#!/usr/bin/env node
// Unit tests for the pure parsers and the check registry.
// No DNS, no shell. Run: node test/checks.sh   (or bash test/checks.sh)
import { parseSPF, isSPF, lookupTerms } from '../lib/parse/spf.mjs';
import { parseDMARC, isDMARC, reportAddresses } from '../lib/parse/dmarc.mjs';
import { parseDKIM, estimateBits } from '../lib/parse/dkim.mjs';
import { isValidEmail, isValidHostname } from '../lib/parse/email.mjs';
import { normalize, duplicates, relativeName, groupBy } from '../lib/records.mjs';
import { createCollector, SEVERITY } from '../lib/findings.mjs';
import { ALL_CHECKS, selectChecks } from '../lib/checks/index.mjs';
import { spfCost } from '../lib/checks/spf.mjs';

let pass = 0, fail = 0;
const t = (name, cond, detail) => {
  if (cond) { pass++; }
  else { fail++; console.log(`  FAIL  ${name}${detail ? `\n        ${detail}` : ''}`); }
};
const eq = (name, got, want) =>
  t(name, JSON.stringify(got) === JSON.stringify(want),
    `want ${JSON.stringify(want)} got ${JSON.stringify(got)}`);

// ------------------------------------------------------------------ SPF parser
t('isSPF accepts a valid record', isSPF('v=spf1 -all'));
t('isSPF is case-insensitive', isSPF('V=SPF1 -all'));
t('isSPF rejects DMARC', !isSPF('v=DMARC1; p=none'));
t('isSPF rejects a lookalike prefix', !isSPF('v=spf10 -all'));
t('isSPF rejects empty', !isSPF(''));

eq('parseSPF: invalid without v=spf1', parseSPF('include:x -all').valid, false);
{
  const p = parseSPF('v=spf1 include:a.com ip4:1.2.3.4 -all');
  eq('parseSPF: mechanism count', p.mechanisms.length, 3);
  eq('parseSPF: include value', p.mechanisms[0].value, 'a.com');
  eq('parseSPF: default qualifier is +', p.mechanisms[0].qualifier, '+');
  eq('parseSPF: all qualifier read', p.mechanisms[2].qualifier, '-');
  eq('parseSPF: no errors on a clean record', p.errors, []);
}
{
  const p = parseSPF('v=spf1 redirect=_spf.a.com');
  eq('parseSPF: redirect is a modifier', p.modifiers[0], { key: 'redirect', value: '_spf.a.com' });
  eq('parseSPF: redirect is not a mechanism', p.mechanisms.length, 0);
}
{
  const p = parseSPF('v=spf1 bogus:x -all');
  t('parseSPF: unknown mechanism reported', p.errors.length === 1);
}
{
  const p = parseSPF('v=spf1 nonsense=1 -all');
  t('parseSPF: unknown modifier reported', p.errors.some(e => e.includes('modifier')));
}
{
  const p = parseSPF('v=spf1 exists:%{i}.a.com -all');
  eq('parseSPF: exists with a macro is a mechanism', p.mechanisms[0].name, 'exists');
}
{
  const { terms, redirect } = lookupTerms(parseSPF('v=spf1 include:a mx a ip4:1.1.1.1 redirect=b'));
  eq('lookupTerms: counts only DNS-querying mechanisms', terms.length, 3);
  eq('lookupTerms: surfaces redirect separately', redirect, 'b');
}

// ------------------------------------------------------------------ DMARC parser
t('isDMARC accepts a valid record', isDMARC('v=DMARC1; p=none'));
t('isDMARC rejects SPF', !isDMARC('v=spf1 -all'));
{
  const p = parseDMARC('v=DMARC1; p=quarantine; sp=reject; pct=50; adkim=s; aspf=r; rua=mailto:a@b.com');
  eq('parseDMARC: tags read', p.tags.p, 'quarantine');
  eq('parseDMARC: sp read', p.tags.sp, 'reject');
  eq('parseDMARC: no errors on a clean record', p.errors, []);
}
t('parseDMARC: invalid p reported', parseDMARC('v=DMARC1; p=maybe').errors.some(e => e.includes('p=')));
t('parseDMARC: pct out of range reported', parseDMARC('v=DMARC1; p=none; pct=250').errors.some(e => e.includes('pct')));
t('parseDMARC: pct non-integer reported', parseDMARC('v=DMARC1; p=none; pct=1.5').errors.some(e => e.includes('pct')));
t('parseDMARC: bad adkim reported', parseDMARC('v=DMARC1; p=none; adkim=x').errors.some(e => e.includes('adkim')));
t('parseDMARC: bad fo reported', parseDMARC('v=DMARC1; p=none; fo=9').errors.some(e => e.includes('fo')));
t('parseDMARC: valid fo combination accepted', parseDMARC('v=DMARC1; p=none; fo=1:d:s').errors.length === 0);
t('parseDMARC: v not first is reported', parseDMARC('p=none; v=DMARC1').errors.some(e => e.includes('first tag')));
t('parseDMARC: duplicate tag reported', parseDMARC('v=DMARC1; p=none; p=reject').errors.some(e => e.includes('duplicate')));
t('parseDMARC: unknown tag reported', parseDMARC('v=DMARC1; p=none; zz=1').errors.some(e => e.includes('unknown')));
t('parseDMARC: non-mailto rua reported', parseDMARC('v=DMARC1; p=none; rua=https://x').errors.some(e => e.includes('mailto')));
t('parseDMARC: malformed rua email reported', parseDMARC('v=DMARC1; p=none; rua=mailto:nope').errors.some(e => e.includes('invalid email')));

{
  const addrs = reportAddresses('mailto:a@x.com,mailto:b@y.com!10m');
  eq('reportAddresses: parses multiple', addrs.length, 2);
  eq('reportAddresses: extracts domain', addrs[0].domain, 'x.com');
  eq('reportAddresses: strips a size limit', addrs[1].address, 'b@y.com');
}

// ------------------------------------------------------------------ DKIM parser
{
  const p = parseDKIM('v=DKIM1; k=rsa; p=' + 'A'.repeat(392));
  eq('parseDKIM: 2048-bit estimate', p.bits, 2048);
  eq('parseDKIM: no errors', p.errors, []);
}
t('parseDKIM: empty p means revoked', parseDKIM('v=DKIM1; k=rsa; p=').errors.some(e => e.includes('REVOKED')));
t('parseDKIM: missing p reported', parseDKIM('v=DKIM1; k=rsa').errors.some(e => e.includes('no p=')));
t('parseDKIM: bad v reported', parseDKIM('v=DKIM2; p=AAAA').errors.some(e => e.includes('DKIM1')));
eq('estimateBits: ed25519 is 256', estimateBits('x'.repeat(44), 'ed25519'), 256);
eq('estimateBits: short key reads as 512', estimateBits('A'.repeat(100)), 512);
t('estimateBits: separates 1024 from 2048',
  estimateBits('A'.repeat(216)) === 1024 && estimateBits('A'.repeat(392)) === 2048);

// ------------------------------------------------------------------ email
t('email: plain address valid', isValidEmail('a@b.com'));
t('email: plus addressing valid', isValidEmail('rua+zone.com@dmarc.example.com'));
t('email: no domain dot invalid', !isValidEmail('a@localhost'));
t('email: leading dot in local invalid', !isValidEmail('.a@b.com'));
t('email: double dot invalid', !isValidEmail('a..b@c.com'));
t('email: no at invalid', !isValidEmail('ab.com'));
t('email: trailing at invalid', !isValidEmail('a@'));
t('email: overlong local invalid', !isValidEmail('x'.repeat(65) + '@b.com'));
t('hostname: valid', isValidHostname('mx1.example.com'));
t('hostname: leading hyphen invalid', !isValidHostname('-a.example.com'));
t('hostname: underscore label invalid for hostnames', !isValidHostname('_dmarc.example.com'));

// ------------------------------------------------------------------ records
{
  const n = normalize([{ name: 'WWW.Example.COM.', type: 'txt', content: '"a" "b"' }]);
  eq('normalize: lowercases the name', n[0].name, 'www.example.com');
  eq('normalize: strips the trailing dot', n[0].name.endsWith('.'), false);
  eq('normalize: upcases the type', n[0].type, 'TXT');
  eq('normalize: joins split TXT strings', n[0].content, 'ab');
  eq('normalize: defaults proxied to false', n[0].proxied, false);
  eq('normalize: defaults priority to null', n[0].priority, null);
}
{
  const recs = [{ name: 'a', v: 1 }, { name: 'a', v: 2 }, { name: 'b', v: 3 }];
  eq('duplicates: finds only repeated keys', duplicates(recs, r => r.name).length, 1);
  eq('groupBy: groups correctly', Object.keys(groupBy(recs, r => r.name)).sort(), ['a', 'b']);
}
eq('relativeName: apex', relativeName('example.com', 'example.com'), '@');
eq('relativeName: subdomain', relativeName('a.b.example.com', 'example.com'), 'a.b');

// ------------------------------------------------------------------ findings model
{
  const c = createCollector();
  c.add({ severity: 'HIGH', scope: 'zone', code: 'X', title: 't', detail: 'd', remediation: 'r' });
  c.add({ severity: 'CRITICAL', scope: 'record', code: 'A', title: 't', detail: 'd', remediation: 'r' });
  eq('collector: sorts by severity', c.sorted().map(f => f.code), ['A', 'X']);
  eq('collector: assigns ids', c.sorted()[0].id.startsWith('F'), true);
  eq('collector: counts by severity', c.counts(), { HIGH: 1, CRITICAL: 1 });
  let threw = false;
  try { c.add({ severity: 'NOPE', scope: 'zone', code: 'B' }); } catch { threw = true; }
  t('collector: rejects an invalid severity', threw);
  threw = false;
  try { c.add({ severity: 'HIGH', scope: 'nope', code: 'B' }); } catch { threw = true; }
  t('collector: rejects an invalid scope', threw);
}

// ------------------------------------------------------------------ registry
t('registry: every check declares a valid scope',
  ALL_CHECKS.every(c => ['record', 'zone'].includes(c.scope)));
t('registry: every check has a code and a run function',
  ALL_CHECKS.every(c => typeof c.code === 'string' && typeof c.run === 'function'));
t('registry: check codes are unique',
  new Set(ALL_CHECKS.map(c => c.code)).size === ALL_CHECKS.length);
t('registry: record-scope selection excludes zone checks',
  selectChecks({ scope: 'record' }).every(c => c.scope === 'record'));
t('registry: offline selection excludes network checks',
  selectChecks({ network: false }).every(c => !c.needsNetwork));
t('registry: record scope has no network checks (safe for pre-flight)',
  selectChecks({ scope: 'record', network: false }).length === selectChecks({ scope: 'record' }).length);
t('registry: there are both record and zone checks',
  selectChecks({ scope: 'record' }).length > 0 && selectChecks({ scope: 'zone' }).length > 0);

// ------------------------------------------------------------------ spfCost
{
  // A fake resolver: no network, fully deterministic.
  const zone = {
    'txt:a.com': ['v=spf1 include:b.com include:c.com -all'],
    'txt:b.com': ['v=spf1 ip4:1.1.1.1 -all'],
    'txt:c.com': ['v=spf1 include:d.com -all'],
    'txt:d.com': ['v=spf1 ip4:2.2.2.2 -all'],
    'txt:loop1.com': ['v=spf1 include:loop2.com -all'],
    'txt:loop2.com': ['v=spf1 include:loop1.com -all'],
    'txt:void.com': ['v=spf1 include:nothere.com include:alsogone.com -all'],
  };
  const q = async (name, type) => {
    const data = zone[`${type.toLowerCase()}:${name.toLowerCase()}`] || [];
    return { ok: data.length > 0, data, empty: data.length === 0, nxdomain: data.length === 0 };
  };
  const a = await spfCost(q, 'a.com');
  // a.com has 2 includes; c.com adds 1 more; b.com and d.com are ip4-only. = 3
  eq('spfCost: counts nested includes', a.lookups, 3);
  eq('spfCost: no voids on a clean chain', a.voids, 0);

  const l = await spfCost(q, 'loop1.com');
  t('spfCost: detects an include loop', l.loop === true);

  const v = await spfCost(q, 'void.com');
  eq('spfCost: counts void lookups', v.voids, 2);
  eq('spfCost: reports which names failed', v.unresolved.sort(), ['alsogone.com', 'nothere.com']);
}

console.log(`\n  ${pass} passed, ${fail} failed`);
if (fail) { console.log('CHECK TESTS FAILED'); process.exit(1); }
console.log('CHECK TESTS PASS');
