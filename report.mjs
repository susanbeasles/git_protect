#!/usr/bin/env node
// report.mjs — render analyzer findings; optionally redact for safe LLM upload.
//
//   --format text|md|json
//   --redact none|standard|strict
//   --keymap <path>   write the reversal map (0600, local only)
//
// Redaction philosophy: the analysis already ran locally with full data, so the
// report only needs findings plus enough structure to reason about. Anything that
// is useful to an attacker and not needed to discuss the findings gets removed.

import { readFileSync, writeFileSync } from 'node:fs';

const arg = (k, d) => {
  const i = process.argv.indexOf(k);
  return i > -1 && process.argv[i + 1] ? process.argv[i + 1] : d;
};
const FORMAT = arg('--format', 'text');
const REDACT = arg('--redact', 'none');
const KEYMAP = arg('--keymap', null);

const data = JSON.parse(readFileSync(0, 'utf8'));

// ------------------------------------------------------------------ redaction
const map = new Map();      // original -> placeholder
const counters = {};
function ph(kind, original) {
  const key = `${kind}:${original.toLowerCase()}`;
  if (map.has(key)) return map.get(key);
  counters[kind] = (counters[kind] || 0) + 1;
  const p = `${kind}${counters[kind]}`;
  map.set(key, p);
  return p;
}

const ZONE = (data.zone || '').toLowerCase();
const ZONE_ALIAS = 'example.com';

// Known verification-token prefixes. Each proves domain control to a third
// party, so leaking one is a real capability handed to an attacker.
const VERIFY_PREFIXES = [
  'google-site-verification', 'ms', 'facebook-domain-verification',
  'atlassian-domain-verification', 'apple-domain-verification', 'docusign',
  'adobe-idp-site-verification', 'stripe-verification', 'shopify',
  'zoom-domain-verification', 'miro-verification', 'slack-domain-verification',
  'workos-domain-verification', 'logmein-verification-code', 'citrix-verification-code',
  'globalsign-domain-verification', 'onetrust-domain-verification',
  'dropbox-domain-verification', 'mongodb-site-verification', 'notion-domain-verification',
  'openai-domain-verification', 'anthropic-domain-verification', 'canva-domain-verification',
  'brevo-code', 'mailru-verification', 'yandex-verification', 'detectify-verification',
  'have-i-been-pwned-verification', 'status-page-domain-verification',
];

const IPV4 = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
// Candidate-then-validate. A naive colon-group regex happily eats the time
// portion of an ISO-8601 timestamp (15:34:37), so every candidate is checked.
const IPV6_CAND = /\b[0-9A-Fa-f:]{6,45}\b/g;

function isIPv6(s) {
  if (!s.includes(':')) return false;
  if (/^\d{2}:\d{2}(:\d{2})?$/.test(s)) return false;      // clock time
  const dbl = s.split('::');
  if (dbl.length > 2) return false;
  const groups = s.split(':').filter(g => g !== '');
  if (groups.length < 2 || groups.length > 8) return false;
  if (dbl.length === 1 && s.split(':').length !== 8) return false;
  return groups.every(g => /^[0-9A-Fa-f]{1,4}$/.test(g))
      && groups.some(g => g.length === 4 || /[A-Fa-f]/.test(g));
}

function isPrivate4(ip) {
  const o = ip.split('.').map(Number);
  if (o.some(x => Number.isNaN(x) || x > 255)) return false;
  return o[0] === 10 || o[0] === 127 || (o[0] === 172 && o[1] >= 16 && o[1] <= 31)
      || (o[0] === 192 && o[1] === 168) || (o[0] === 169 && o[1] === 254);
}

function scrub(s, level) {
  if (typeof s !== 'string' || level === 'none') return s;
  let out = s;

  // DKIM public keys — keep the bit-length signal, drop the key
  out = out.replace(/\bp=([A-Za-z0-9+/]{40,}={0,2})/g, (m, k) => {
    const bits = Math.floor(k.length * 3 / 4) > 350 ? '3072+'
               : Math.floor(k.length * 3 / 4) > 250 ? '2048'
               : Math.floor(k.length * 3 / 4) > 120 ? '1024' : 'short';
    return `p=<DKIM-PUBKEY-${bits}bit-REDACTED>`;
  });

  // third-party domain-control proofs
  for (const pre of VERIFY_PREFIXES) {
    out = out.replace(new RegExp(`\\b${pre}\\s*=\\s*[^\\s";]+`, 'gi'),
      `${pre}=<VERIFICATION-TOKEN-REDACTED>`);
  }
  // bare high-entropy blobs in TXT values that we did not otherwise recognise
  out = out.replace(/(?<![:=/.\w-])[A-Za-z0-9+/_-]{32,}={0,2}(?![\w.-])/g, m => {
    if (/^(v=|include|spf|dmarc|dkim)/i.test(m)) return m;
    return '<OPAQUE-TOKEN-REDACTED>';
  });

  // public IPs (private ranges are not interesting to an outsider, but still go
  // at strict since they map internal topology)
  out = out.replace(IPV4, ip => (isPrivate4(ip) && level !== 'strict') ? ip : ph('IP', ip));
  out = out.replace(IPV6_CAND, m => isIPv6(m) ? ph('IP6', m) : m);

  // email local parts. Domain is kept at standard because the destination
  // organisation is material to the DMARC external-authorisation finding.
  out = out.replace(/\b([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})/g,
    (m, local, dom) => level === 'strict'
      ? `${ph('MAILBOX', local)}@${ph('MAILDOMAIN', dom)}`
      : `${ph('MAILBOX', local)}@${dom}`);

  // the zone itself
  if (ZONE) {
    out = out.split(new RegExp(ZONE.replace(/\./g, '\\.'), 'gi')).join(ZONE_ALIAS);
  }

  if (level === 'strict') {
    // pseudonymise remaining hostname labels, preserving depth.
    // Must match two-label domains (mailgun.org) as well as deeper ones — an
    // earlier version required 3+ labels and leaked every apex vendor domain.
    out = out.replace(/\b([a-z0-9][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)*\.[a-z]{2,})\b/gi, host => {
      const h = host.toLowerCase();
      if (h === ZONE_ALIAS || h.endsWith('.' + ZONE_ALIAS)) {
        const head = host.slice(0, -(ZONE_ALIAS.length + 1));
        if (!head) return host;
        const labels = head.split('.').map(l =>
          /^_/.test(l) ? l : ph('SUB', l));      // keep _dmarc, _domainkey structure
        return `${labels.join('.')}.${ZONE_ALIAS}`;
      }
      return ph('EXTDOMAIN', host);
    });
    // Fix commands carry bare labels (`--name mail`) that the hostname pass
    // cannot see because they have no dot. Substituting the label globally would
    // wreck prose ("mail-handling name"), so scope it to the flag itself and
    // reuse the SUB mapping already built from the `where` field.
    out = out.replace(/(--name\s+)(['"]?)([^\s'"]+)(\2)/g, (m, flag, q1, val, q2) => {
      if (val === '@' || val === ZONE_ALIAS) return m;
      const mapped = val.split('.').map(l => /^_/.test(l) ? l : ph('SUB', l)).join('.');
      return `${flag}${q1}${mapped}${q2}`;
    });
  }
  return out;
}

function walk(v, level) {
  if (typeof v === 'string') return scrub(v, level);
  if (Array.isArray(v)) return v.map(x => walk(x, level));
  if (v && typeof v === 'object') {
    const o = {};
    for (const [k, val] of Object.entries(v)) {
      if (['id', 'zone_id', 'zoneId', 'account_id'].includes(k) && typeof val === 'string'
          && /^[a-f0-9]{20,}$/i.test(val)) continue;   // drop CF object ids entirely
      o[k] = walk(val, level);
    }
    return o;
  }
  return v;
}

const view = REDACT === 'none' ? data : { ...walk(data, REDACT), zone: ZONE ? ZONE_ALIAS : data.zone };

// ------------------------------------------------------------------ renderers
const SEV_ICON = { CRITICAL: '[!!]', HIGH: '[!]', MEDIUM: '[~]', LOW: '[-]', INFO: '[i]' };
const C = { CRITICAL: '1;31', HIGH: '0;31', MEDIUM: '1;33', LOW: '0;36', INFO: '0;37' };
const tty = process.stdout.isTTY;
const col = (s, c) => tty ? `\x1b[${c}m${s}\x1b[0m` : s;

function renderText(d) {
  const L = [];
  L.push('');
  L.push(col(`DNS / email-auth analysis — ${d.zone}`, '1;37'));
  L.push(`generated ${d.generated}${d.offline ? '  (offline: syntax only)' : ''}`);
  const s = d.stats;
  L.push(`${s.records} records | ${s.mx} MX | ${s.spf} SPF | ${s.dmarc} DMARC | ${s.dkim} DKIM selectors`
        + (s.dnsQueries ? ` | ${s.dnsQueries} live DNS queries` : ''));
  L.push('');
  const bs = s.bySeverity || {};
  L.push(['CRITICAL','HIGH','MEDIUM','LOW','INFO']
    .map(k => col(`${k} ${bs[k] || 0}`, C[k])).join('   '));
  L.push('');
  if (!d.findings.length) { L.push(col('no findings', '0;32')); return L.join('\n'); }
  for (const f of d.findings) {
    L.push(col(`${SEV_ICON[f.severity]} ${f.severity}  ${f.code}  ${f.title}`, C[f.severity]));
    if (f.where?.length) L.push(`      at: ${f.where.join(', ')}`);
    L.push(...wrap(f.detail, 6));
    L.push(col(`      fix: `, '0;32') + wrap(f.remediation, 6).join('\n').trim());
    if (f.fix) L.push(col(`      $ ${f.fix}`, '0;36'));
    if (f.refs?.length) L.push(`      ref: ${f.refs.join('; ')}`);
    L.push('');
  }
  return L.join('\n');
}

function wrap(t, indent) {
  if (!t) return [];
  const w = 92 - indent, pad = ' '.repeat(indent), out = [];
  let line = '';
  for (const word of String(t).split(/\s+/)) {
    if ((line + ' ' + word).trim().length > w) { out.push(pad + line.trim()); line = word; }
    else line += ' ' + word;
  }
  if (line.trim()) out.push(pad + line.trim());
  return out;
}

function renderMd(d) {
  const L = [];
  L.push(`# DNS and email authentication analysis`);
  L.push('');
  L.push(`**Zone:** \`${d.zone}\`  `);
  L.push(`**Generated:** ${d.generated}  `);
  L.push(`**Mode:** ${d.offline ? 'offline (syntax only)' : 'live resolution'}  `);
  if (REDACT !== 'none') {
    L.push(`**Redaction:** \`${REDACT}\` — see "What was removed" below.`);
  }
  L.push('');
  const s = d.stats, bs = s.bySeverity || {};
  L.push('## Summary');
  L.push('');
  L.push('| Severity | Count |');
  L.push('|---|---|');
  for (const k of ['CRITICAL','HIGH','MEDIUM','LOW','INFO']) L.push(`| ${k} | ${bs[k] || 0} |`);
  L.push('');
  L.push(`Zone contains ${s.records} records: ${s.mx} MX, ${s.spf} SPF, ${s.dmarc} DMARC, ${s.dkim} DKIM selectors, across ${s.mailNames} mail-handling name(s).`);
  L.push('');

  if (REDACT !== 'none') {
    L.push('## What was removed');
    L.push('');
    L.push('This report was mechanically redacted before export. Removed or replaced:');
    L.push('');
    L.push('- DKIM public keys, replaced with a bit-length marker');
    L.push('- Third-party domain-verification tokens (each one proves domain control)');
    L.push('- High-entropy opaque TXT values');
    L.push('- Public IP addresses, replaced with stable `IPn` labels');
    L.push('- Email local-parts, replaced with stable `MAILBOXn` labels');
    L.push('- The real zone name, replaced with `example.com`');
    L.push('- Cloudflare internal object IDs');
    if (REDACT === 'strict') {
      L.push('- All subdomain labels, replaced with stable `SUBn` labels (hierarchy depth preserved)');
      L.push('- All external vendor domains, replaced with stable `EXTDOMAINn` labels');
      L.push('- Private-range IPs');
    }
    L.push('');
    L.push('Labels are consistent within this report, so structural relationships still hold. No DNS record in this zone contained message content, and DNS is not a PHI store — but subject-line and report-destination exposure is itself one of the findings below, so read that one before deciding what else to share.');
    L.push('');
  }

  L.push('## Findings');
  L.push('');
  for (const f of d.findings) {
    L.push(`### ${f.severity} — ${f.title}`);
    L.push('');
    L.push(`**Code:** \`${f.code}\` (${f.scope})  `);
    if (f.where?.length) L.push(`**Applies to:** ${f.where.map(w => `\`${w}\``).join(', ')}  `);
    if (f.refs?.length) L.push(`**Reference:** ${f.refs.join('; ')}  `);
    L.push('');
    L.push(f.detail);
    L.push('');
    L.push(`**Remediation.** ${f.remediation}`);
    if (f.fix) { L.push(''); L.push('```bash'); L.push(f.fix); L.push('```'); }
    if (f.evidence && Object.keys(f.evidence).length) {
      L.push('');
      L.push('<details><summary>Evidence</summary>');
      L.push('');
      L.push('```json');
      L.push(JSON.stringify(f.evidence, null, 2));
      L.push('```');
      L.push('');
      L.push('</details>');
    }
    L.push('');
  }
  L.push('## Suggested questions for review');
  L.push('');
  L.push('- Which findings must be fixed before DMARC enforcement is switched on, and in what order?');
  L.push('- Does the proposed remediation sequence ever leave a sending stream unauthenticated, even briefly?');
  L.push('- Which findings are false positives given that some records legitimately cannot be proxied or aligned?');
  L.push('');
  return L.join('\n');
}

// ------------------------------------------------------------------ emit
if (FORMAT === 'json') process.stdout.write(JSON.stringify(view, null, 2));
else if (FORMAT === 'md') process.stdout.write(renderMd(view));
else process.stdout.write(renderText(view));

if (KEYMAP && map.size) {
  const rev = {};
  for (const [k, v] of map) rev[v] = k.slice(k.indexOf(':') + 1);
  if (ZONE) rev[ZONE_ALIAS] = ZONE;
  writeFileSync(KEYMAP, JSON.stringify(rev, null, 2), { mode: 0o600 });
  process.stderr.write(`\nkeymap (${map.size + (ZONE ? 1 : 0)} entries) -> ${KEYMAP}\n`
    + `KEEP THIS LOCAL. It reverses the redaction; uploading it alongside the report defeats the point.\n`);
}
