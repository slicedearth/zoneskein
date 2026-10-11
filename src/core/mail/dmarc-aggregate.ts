import { SaxesParser } from 'saxes';

import { parseStrictIpAddress } from '../dns/ip';

const MAX_XML_CHARACTERS = 10 * 1024 * 1024;
const MAX_DEPTH = 32;
const MAX_TEXT_PER_ELEMENT = 65_536;
const MAX_RECORDS = 50_000;

export interface DmarcAggregateRow {
  readonly count: number;
  readonly disposition: string;
  readonly dkim: string;
  readonly envelopeFrom: string;
  readonly headerFrom: string;
  readonly sourceIp: string;
  readonly spf: string;
}

export interface DmarcAggregateReport {
  readonly begin: number | null;
  readonly domain: string;
  readonly end: number | null;
  readonly errors: readonly string[];
  readonly organisation: string;
  readonly policy: string;
  readonly records: readonly DmarcAggregateRow[];
  readonly reportId: string;
  readonly summary: {
    readonly aligned: number;
    readonly quarantined: number;
    readonly rejected: number;
    readonly total: number;
  };
}

function localName(value: string): string {
  return (value.includes(':') ? value.slice(value.lastIndexOf(':') + 1) : value).toLowerCase();
}

function wholeNumber(value: string, maximum = Number.MAX_SAFE_INTEGER): number | null {
  return /^\d+$/u.test(value) && Number(value) <= maximum ? Number(value) : null;
}

export function parseDmarcAggregateXml(source: string): DmarcAggregateReport {
  if (source.length === 0 || source.length > MAX_XML_CHARACTERS)
    throw new Error('The DMARC XML input is empty or exceeds the local safety limit.');
  if (/<!DOCTYPE/iu.test(source))
    throw new Error('DMARC XML with a document type declaration is not accepted.');
  const parser = new SaxesParser({ xmlns: false });
  const stack: string[] = [];
  let text = '';
  let organisation = '';
  let reportId = '';
  let begin: number | null = null;
  let end: number | null = null;
  let domain = '';
  let policy = '';
  let current: Partial<Record<keyof DmarcAggregateRow, string | number>> | null = null;
  const records: DmarcAggregateRow[] = [];
  const errors: string[] = [];

  parser.on('doctype', () => {
    throw new Error('DMARC XML with a document type declaration is not accepted.');
  });
  parser.on('opentag', (tag) => {
    stack.push(localName(tag.name));
    if (stack.length > MAX_DEPTH)
      throw new Error('DMARC XML exceeds the element-depth safety limit.');
    text = '';
    if (stack.at(-1) === 'record') current = {};
  });
  parser.on('text', (value) => {
    text += value;
    if (text.length > MAX_TEXT_PER_ELEMENT)
      throw new Error('DMARC XML contains an oversized text node.');
  });
  parser.on('cdata', (value) => {
    text += value;
    if (text.length > MAX_TEXT_PER_ELEMENT)
      throw new Error('DMARC XML contains an oversized text node.');
  });
  parser.on('closetag', (tag) => {
    const name = localName(tag.name);
    const path = stack.join('/');
    const value = text.trim();
    if (path.endsWith('report_metadata/org_name')) organisation = value;
    else if (path.endsWith('report_metadata/report_id')) reportId = value;
    else if (path.endsWith('date_range/begin')) begin = wholeNumber(value);
    else if (path.endsWith('date_range/end')) end = wholeNumber(value);
    else if (path.endsWith('policy_published/domain')) domain = value;
    else if (path.endsWith('policy_published/p')) policy = value;
    else if (current !== null) {
      if (path.endsWith('record/row/source_ip')) current.sourceIp = value;
      else if (path.endsWith('record/row/count'))
        current.count = wholeNumber(value, 0xffff_ffff) ?? -1;
      else if (path.endsWith('record/row/policy_evaluated/disposition'))
        current.disposition = value;
      else if (path.endsWith('record/row/policy_evaluated/dkim')) current.dkim = value;
      else if (path.endsWith('record/row/policy_evaluated/spf')) current.spf = value;
      else if (path.endsWith('record/identifiers/header_from')) current.headerFrom = value;
      else if (path.endsWith('record/identifiers/envelope_from')) current.envelopeFrom = value;
      if (name === 'record') {
        if (records.length >= MAX_RECORDS)
          throw new Error('DMARC report exceeds the record-count safety limit.');
        const count = typeof current.count === 'number' ? current.count : -1;
        if (
          typeof current.sourceIp !== 'string' ||
          parseStrictIpAddress(current.sourceIp) === null ||
          count < 0
        )
          errors.push(`Record ${String(records.length + 1)} has no valid source IP or count.`);
        else
          records.push({
            count,
            disposition:
              typeof current.disposition === 'string'
                ? current.disposition.toLowerCase()
                : 'unknown',
            dkim: typeof current.dkim === 'string' ? current.dkim.toLowerCase() : 'unknown',
            envelopeFrom: typeof current.envelopeFrom === 'string' ? current.envelopeFrom : '',
            headerFrom: typeof current.headerFrom === 'string' ? current.headerFrom : '',
            sourceIp: current.sourceIp,
            spf: typeof current.spf === 'string' ? current.spf.toLowerCase() : 'unknown',
          });
        current = null;
      }
    }
    stack.pop();
    text = '';
  });
  parser.on('error', (error) => {
    throw new Error(`DMARC XML is malformed near line ${String(parser.line)}.`, {
      cause: error,
    });
  });
  parser.write(source).close();
  if (reportId === '' || organisation === '')
    errors.push('Required report metadata is incomplete.');
  const summary = records.reduce(
    (value, row) => ({
      aligned: value.aligned + (row.dkim === 'pass' || row.spf === 'pass' ? row.count : 0),
      quarantined: value.quarantined + (row.disposition === 'quarantine' ? row.count : 0),
      rejected: value.rejected + (row.disposition === 'reject' ? row.count : 0),
      total: value.total + row.count,
    }),
    { aligned: 0, quarantined: 0, rejected: 0, total: 0 },
  );
  return { begin, domain, end, errors, organisation, policy, records, reportId, summary };
}
