// Check registry. Adding a category means adding one import line.
import { checks as spf }       from './spf.mjs';
import { checks as dmarc }     from './dmarc.mjs';
import { checks as dkim }      from './dkim.mjs';
import { checks as mail }      from './mail.mjs';
import { checks as mx }        from './mx.mjs';
import { checks as zone }      from './zone.mjs';
import { checks as transport } from './transport.mjs';

export const ALL_CHECKS = [...spf, ...dmarc, ...dkim, ...mail, ...mx, ...zone, ...transport];

// scope='record' keeps only checks that are meaningful for a single record in
// isolation. `cf dns add` uses this so it can pre-flight what you are about to
// publish without falsely reporting that the zone has no SPF.
export function selectChecks({ scope = null, network = true } = {}) {
  return ALL_CHECKS.filter(c =>
    (scope === null || c.scope === scope) &&
    (network || !c.needsNetwork));
}
