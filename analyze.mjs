#!/usr/bin/env node
// Zone analyzer. Orchestration only — every rule lives in lib/checks/.
//
//   stdin  {zone, records:[...]}
//   stdout {zone, generated, stats, findings:[...]}
//
//   --offline        no DNS queries; only checks that need no network
//   --scope record   only checks meaningful for a single record in isolation
import { readFileSync } from 'node:fs';
import { createResolver } from './resolve.mjs';
import { createCollector } from './findings.mjs';
import { normalize } from './records.mjs';
import { selectChecks } from './checks/index.mjs';

const argv = process.argv.slice(2);
const flag = n => argv.includes(n);
const opt = (n, d) => { const i = argv.indexOf(n); return i > -1 && argv[i + 1] ? argv[i + 1] : d; };

const offline = flag('--offline');
const scope = opt('--scope', null);

const input = JSON.parse(readFileSync(0, 'utf8'));
const zone = String(input.zone || '').toLowerCase().replace(/\.$/, '');
const records = normalize(Array.isArray(input) ? input : (input.records || []));

const resolver = createResolver({ offline });
resolver.seed(records);

const collector = createCollector();
const ctx = { zone, records, add: collector.add, query: resolver.query };

const checks = selectChecks({ scope, network: !offline });
const errors = [];
for (const check of checks) {
  try {
    await check.run(ctx);
  } catch (e) {
    // One broken check must not lose the other findings.
    errors.push({ check: check.code, error: String(e && e.message || e) });
  }
}

const mailNames = new Set(records.filter(r => r.type === 'MX').map(r => r.name));

process.stdout.write(JSON.stringify({
  zone,
  generated: new Date().toISOString(),
  offline,
  scope: scope || 'all',
  stats: {
    records: records.length,
    mx: records.filter(r => r.type === 'MX').length,
    spf: records.filter(r => r.type === 'TXT' && /^v=spf1/i.test(r.content)).length,
    dmarc: records.filter(r => r.type === 'TXT' && /^v=DMARC1/i.test(r.content)).length,
    dkim: records.filter(r => /_domainkey\./i.test(r.name)).length,
    mailNames: mailNames.size,
    checksRun: checks.length,
    dnsQueries: resolver.size,
    findings: collector.length,
    bySeverity: collector.counts(),
  },
  checkErrors: errors,
  findings: collector.sorted(),
}, null, 2));
