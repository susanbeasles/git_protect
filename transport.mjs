// Inbound mail transport security. Relevant where message content may carry PHI.
export const checks = [
{
  code: 'TRANSPORT_SECURITY', scope: 'zone', needsNetwork: true,
  async run(ctx) {
    if (!ctx.records.some(r => r.type === 'MX')) return;

    const sts = await ctx.query(`_mta-sts.${ctx.zone}`, 'TXT');
    if (!(sts.data || []).some(s => /v=STSv1/i.test(s))) ctx.add({
      severity: 'LOW', scope: 'zone', code: 'NO_MTA_STS',
      title: 'no MTA-STS policy', where: [ctx.zone],
      detail: 'MTA-STS lets you require TLS for inbound mail, closing the downgrade window that opportunistic STARTTLS leaves open.',
      remediation: 'Publish _mta-sts TXT plus an HTTPS policy file, starting in testing mode.',
      refs: ['RFC 8461'],
    });

    const tlsrpt = await ctx.query(`_smtp._tls.${ctx.zone}`, 'TXT');
    if (!(tlsrpt.data || []).some(s => /v=TLSRPTv1/i.test(s))) ctx.add({
      severity: 'INFO', scope: 'zone', code: 'NO_TLS_RPT',
      title: 'no TLS-RPT reporting', where: [ctx.zone],
      detail: 'TLS-RPT surfaces TLS negotiation failures for inbound mail. Reports carry no message content.',
      remediation: 'Publish _smtp._tls TXT with a rua= destination.', refs: ['RFC 8460'],
    });
  },
},
];
