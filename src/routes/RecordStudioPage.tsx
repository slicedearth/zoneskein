import { useMemo, useState } from 'react';

import { CopyButton } from '../components/CopyButton';
import { SnapshotButton } from '../components/SnapshotButton';
import { StatusBadge } from '../components/StatusBadge';
import { ToolIntro } from '../components/ToolIntro';
import {
  authorRecord,
  type AuthoringRecordType,
  type RecordAuthoringDiagnostic,
} from '../core/zone/authoring';
import { lintZoneSnippet } from '../core/zone/lint';
import type { ZoneDiagnostic, ZoneDocument, ZoneSeverity } from '../core/zone/types';

const MAX_WORKING_RECORDS = 256;
const MAX_WORKING_SET_CHARACTERS = 262_144;
const encoder = new TextEncoder();

const RECORD_TYPES = [
  'A',
  'AAAA',
  'CAA',
  'CNAME',
  'DNSKEY',
  'DS',
  'HTTPS',
  'MX',
  'NAPTR',
  'NS',
  'PTR',
  'SOA',
  'SRV',
  'SSHFP',
  'SVCB',
  'TLSA',
  'TXT',
  'URI',
] as const satisfies readonly AuthoringRecordType[];

interface FieldDefinition {
  readonly help?: string;
  readonly inputMode?: 'decimal' | 'numeric' | 'text' | 'url';
  readonly label: string;
  readonly maxLength?: number;
  readonly multiline?: boolean;
  readonly name: string;
  readonly placeholder?: string;
  readonly suggestions?: readonly string[];
}

interface WorkingRecord {
  readonly bind: string;
  readonly json: string;
  readonly type: AuthoringRecordType;
}

const FIELD_DEFINITIONS: Readonly<Record<AuthoringRecordType, readonly FieldDefinition[]>> = {
  A: [
    {
      inputMode: 'text',
      label: 'IPv4 address',
      name: 'address',
      placeholder: '192.0.2.10',
    },
  ],
  AAAA: [
    {
      inputMode: 'text',
      label: 'IPv6 address',
      name: 'address',
      placeholder: '2001:db8::10',
    },
  ],
  CAA: [
    {
      inputMode: 'numeric',
      label: 'Flags',
      name: 'flags',
      placeholder: '0',
      suggestions: ['0', '128'],
    },
    {
      help: 'Standard properties are issue, issuewild, issuemail, and iodef.',
      label: 'Property tag',
      name: 'tag',
      placeholder: 'issue',
      suggestions: ['issue', 'issuewild', 'issuemail', 'iodef'],
    },
    {
      help: 'Enter the complete property value, including any semicolon-separated parameters.',
      label: 'Property value',
      maxLength: 65_535,
      name: 'value',
      placeholder: 'ca.example; validationmethods=dns-01',
    },
  ],
  CNAME: [
    {
      label: 'Canonical target',
      name: 'target',
      placeholder: 'service.example.com.',
    },
  ],
  DNSKEY: [
    {
      help: 'Common values are 256 for a zone-signing key and 257 for a secure-entry-point key.',
      inputMode: 'numeric',
      label: 'Flags',
      name: 'flags',
      placeholder: '257',
      suggestions: ['256', '257'],
    },
    {
      help: 'DNSKEY protocol is required to be 3.',
      inputMode: 'numeric',
      label: 'Protocol',
      name: 'protocol',
      placeholder: '3',
      suggestions: ['3'],
    },
    {
      help: 'Use the IANA DNSSEC algorithm number published for the key.',
      inputMode: 'numeric',
      label: 'Algorithm',
      name: 'algorithm',
      placeholder: '13',
      suggestions: ['8', '13', '14', '15'],
    },
    {
      help: 'Paste Base64 key material only, without presentation-format whitespace.',
      label: 'Public key',
      maxLength: 65_535,
      multiline: true,
      name: 'publicKey',
      placeholder: 'Base64 public key data',
    },
  ],
  DS: [
    {
      inputMode: 'numeric',
      label: 'Key tag',
      name: 'keyTag',
      placeholder: '12345',
    },
    {
      inputMode: 'numeric',
      label: 'DNSSEC algorithm',
      name: 'algorithm',
      placeholder: '13',
      suggestions: ['8', '13', '14', '15'],
    },
    {
      help: '2 is SHA-256 and 4 is SHA-384. RFC 9905 prohibits creating new SHA-1 value 1 records.',
      inputMode: 'numeric',
      label: 'Digest type',
      name: 'digestType',
      placeholder: '2',
      suggestions: ['2', '4'],
    },
    {
      help: 'Hexadecimal digest without separators.',
      label: 'Digest',
      maxLength: 512,
      multiline: true,
      name: 'digest',
      placeholder: 'A1B2C3…',
    },
  ],
  HTTPS: [
    {
      help: 'Priority 0 selects AliasMode; other values select ServiceMode.',
      inputMode: 'numeric',
      label: 'SvcPriority',
      name: 'priority',
      placeholder: '1',
      suggestions: ['0', '1'],
    },
    {
      help: 'Use . to indicate that the owner name is the service target.',
      label: 'Target name',
      name: 'target',
      placeholder: '.',
    },
    {
      help: 'Enter one SvcParam per line, for example alpn=h2,h3 or port=443.',
      label: 'Service parameters',
      maxLength: 65_535,
      multiline: true,
      name: 'parameters',
      placeholder: 'alpn=h2,h3\nport=443',
    },
  ],
  MX: [
    {
      inputMode: 'numeric',
      label: 'Preference',
      name: 'preference',
      placeholder: '10',
    },
    {
      label: 'Mail exchanger',
      name: 'target',
      placeholder: 'mail.example.com.',
    },
  ],
  NAPTR: [
    { inputMode: 'numeric', label: 'Order', name: 'order', placeholder: '100' },
    {
      inputMode: 'numeric',
      label: 'Preference',
      name: 'preference',
      placeholder: '10',
    },
    {
      help: 'Application-defined NAPTR flags, such as s, a, u, or p.',
      label: 'Flags',
      name: 'flags',
      placeholder: 's',
    },
    {
      label: 'Service',
      name: 'service',
      placeholder: 'SIP+D2U',
    },
    {
      help: 'Leave empty when the replacement name is used directly.',
      label: 'Regular expression',
      maxLength: 4096,
      name: 'regexp',
      placeholder: '',
    },
    {
      help: 'Use . when the regular-expression field supplies the terminal result.',
      label: 'Replacement',
      name: 'replacement',
      placeholder: '_sip._udp.example.com.',
    },
  ],
  NS: [{ label: 'Name server', name: 'target', placeholder: 'ns1.example.com.' }],
  PTR: [{ label: 'Target name', name: 'target', placeholder: 'host.example.com.' }],
  SOA: [
    {
      label: 'Primary name server',
      name: 'primary',
      placeholder: 'ns1.example.com.',
    },
    {
      help: 'Represent the responsible mailbox with a dot in place of @.',
      label: 'Responsible contact',
      name: 'contact',
      placeholder: 'hostmaster.example.com.',
    },
    {
      help: 'Use a serial value that follows your zone’s established convention.',
      inputMode: 'numeric',
      label: 'Serial',
      name: 'serial',
      placeholder: '2026081301',
    },
    { label: 'Refresh', name: 'refresh', placeholder: '1h' },
    { label: 'Retry', name: 'retry', placeholder: '15m' },
    { label: 'Expire', name: 'expire', placeholder: '2w' },
    { label: 'Negative-cache minimum', name: 'minimum', placeholder: '5m' },
  ],
  SRV: [
    { inputMode: 'numeric', label: 'Priority', name: 'priority', placeholder: '10' },
    { inputMode: 'numeric', label: 'Weight', name: 'weight', placeholder: '5' },
    { inputMode: 'numeric', label: 'Port', name: 'port', placeholder: '443' },
    {
      help: 'Use . to state that the service is unavailable.',
      label: 'Target name',
      name: 'target',
      placeholder: 'service.example.com.',
    },
  ],
  SSHFP: [
    {
      inputMode: 'numeric',
      label: 'SSH public-key algorithm',
      name: 'algorithm',
      placeholder: '4',
      suggestions: ['1', '2', '3', '4', '6'],
    },
    {
      help: '1 is SHA-1 and 2 is SHA-256.',
      inputMode: 'numeric',
      label: 'Fingerprint type',
      name: 'fingerprintType',
      placeholder: '2',
      suggestions: ['2', '1'],
    },
    {
      help: 'Hexadecimal fingerprint without colons.',
      label: 'Fingerprint',
      maxLength: 512,
      multiline: true,
      name: 'fingerprint',
      placeholder: 'A1B2C3…',
    },
  ],
  SVCB: [
    {
      help: 'Priority 0 selects AliasMode; other values select ServiceMode.',
      inputMode: 'numeric',
      label: 'SvcPriority',
      name: 'priority',
      placeholder: '1',
      suggestions: ['0', '1'],
    },
    {
      help: 'Use . to indicate that the owner name is the service target.',
      label: 'Target name',
      name: 'target',
      placeholder: '.',
    },
    {
      help: 'Enter one SvcParam per line, for example mandatory=alpn and alpn=h2,h3.',
      label: 'Service parameters',
      maxLength: 65_535,
      multiline: true,
      name: 'parameters',
      placeholder: 'mandatory=alpn\nalpn=h2,h3',
    },
  ],
  TLSA: [
    {
      inputMode: 'numeric',
      label: 'Certificate usage',
      name: 'usage',
      placeholder: '3',
      suggestions: ['0', '1', '2', '3'],
    },
    {
      inputMode: 'numeric',
      label: 'Selector',
      name: 'selector',
      placeholder: '1',
      suggestions: ['0', '1'],
    },
    {
      help: '0 is exact data, 1 is SHA-256, and 2 is SHA-512.',
      inputMode: 'numeric',
      label: 'Matching type',
      name: 'matchingType',
      placeholder: '1',
      suggestions: ['0', '1', '2'],
    },
    {
      help: 'Hexadecimal certificate association data without separators.',
      label: 'Certificate association data',
      maxLength: 65_535,
      multiline: true,
      name: 'associationData',
      placeholder: 'A1B2C3…',
    },
  ],
  TXT: [
    {
      help: 'Long values are divided into DNS character-strings at UTF-8 boundaries.',
      label: 'Text value',
      maxLength: 65_535,
      multiline: true,
      name: 'value',
      placeholder: 'v=spf1 -all',
    },
  ],
  URI: [
    { inputMode: 'numeric', label: 'Priority', name: 'priority', placeholder: '10' },
    { inputMode: 'numeric', label: 'Weight', name: 'weight', placeholder: '1' },
    {
      help: 'Enter an absolute URI with a scheme.',
      inputMode: 'url',
      label: 'Target URI',
      maxLength: 4096,
      name: 'target',
      placeholder: 'https://example.com/service',
    },
  ],
};

const DEFAULT_FIELDS: Readonly<Record<AuthoringRecordType, Readonly<Record<string, string>>>> =
  {
    A: { address: '' },
    AAAA: { address: '' },
    CAA: { flags: '0', tag: 'issue', value: '' },
    CNAME: { target: '' },
    DNSKEY: { algorithm: '13', flags: '257', protocol: '3', publicKey: '' },
    DS: { algorithm: '13', digest: '', digestType: '2', keyTag: '' },
    HTTPS: { parameters: 'alpn=h2,h3', priority: '1', target: '.' },
    MX: { preference: '10', target: '' },
    NAPTR: {
      flags: 's',
      order: '100',
      preference: '10',
      regexp: '',
      replacement: '',
      service: '',
    },
    NS: { target: '' },
    PTR: { target: '' },
    SOA: {
      contact: '',
      expire: '2w',
      minimum: '5m',
      primary: '',
      refresh: '1h',
      retry: '15m',
      serial: '',
    },
    SRV: { port: '443', priority: '10', target: '', weight: '5' },
    SSHFP: { algorithm: '4', fingerprint: '', fingerprintType: '2' },
    SVCB: { parameters: 'alpn=h2,h3', priority: '1', target: '.' },
    TLSA: { associationData: '', matchingType: '1', selector: '1', usage: '3' },
    TXT: { value: '' },
    URI: { priority: '10', target: '', weight: '1' },
  };

function initialFields(): Record<AuthoringRecordType, Record<string, string>> {
  return Object.fromEntries(
    RECORD_TYPES.map((type) => [type, { ...DEFAULT_FIELDS[type] }]),
  ) as Record<AuthoringRecordType, Record<string, string>>;
}

function diagnosticTone(severity: RecordAuthoringDiagnostic['severity'] | ZoneSeverity) {
  return severity === 'error' ? 'error' : severity === 'warning' ? 'warning' : 'information';
}

function fieldDiagnostics(
  diagnostics: readonly RecordAuthoringDiagnostic[],
  field: string,
): readonly RecordAuthoringDiagnostic[] {
  return diagnostics.filter((item) => item.field === field);
}

function descriptionIds(
  id: string,
  help: string | undefined,
  diagnostics: readonly RecordAuthoringDiagnostic[],
): string | undefined {
  const ids = [
    help === undefined ? undefined : `${id}-help`,
    diagnostics.length ? `${id}-feedback` : undefined,
  ].filter((value): value is string => value !== undefined);
  return ids.length === 0 ? undefined : ids.join(' ');
}

function FieldNotes({
  diagnostics,
  help,
  id,
}: {
  readonly diagnostics: readonly RecordAuthoringDiagnostic[];
  readonly help?: string;
  readonly id: string;
}) {
  return (
    <>
      {help === undefined ? null : (
        <span className="field-help" id={`${id}-help`}>
          {help}
        </span>
      )}
      {diagnostics.length === 0 ? null : (
        <span
          className={
            diagnostics.some((item) => item.severity === 'error') ? 'form-error' : 'field-help'
          }
          id={`${id}-feedback`}
        >
          {diagnostics.map((item) => item.message).join(' ')}
        </span>
      )}
    </>
  );
}

function lintTone(document: ZoneDocument) {
  return document.diagnostics.some((item) => item.severity === 'error')
    ? 'error'
    : document.diagnostics.some((item) => item.severity === 'warning')
      ? 'warning'
      : 'pass';
}

function lintLabel(document: ZoneDocument): string {
  if (document.diagnostics.length === 0) return 'No diagnostics';
  return `${String(document.diagnostics.length)} diagnostic${document.diagnostics.length === 1 ? '' : 's'}`;
}

export function RecordStudioPage() {
  const [owner, setOwner] = useState('');
  const [ttl, setTtl] = useState('3600');
  const [type, setType] = useState<AuthoringRecordType>('A');
  const [fieldsByType, setFieldsByType] = useState(initialFields);
  const [workingRecords, setWorkingRecords] = useState<readonly WorkingRecord[]>([]);
  const [lintDocument, setLintDocument] = useState<ZoneDocument | null>(null);
  const [announcement, setAnnouncement] = useState('');

  const fields = fieldsByType[type];
  const result = useMemo(
    () => authorRecord({ fields, owner, ttl, type }),
    [fields, owner, ttl, type],
  );
  const bindWorkingSet = useMemo(
    () => workingRecords.map((record) => record.bind).join('\n'),
    [workingRecords],
  );
  const workingSetJson = useMemo(
    () =>
      JSON.stringify(
        {
          kind: 'zoneskein-record-working-set',
          records: workingRecords,
          schemaVersion: 1,
        },
        null,
        2,
      ),
    [workingRecords],
  );

  const draftTone = result.diagnostics.some((item) => item.severity === 'error')
    ? 'error'
    : result.diagnostics.some((item) => item.severity === 'warning')
      ? 'warning'
      : result.valid
        ? 'pass'
        : 'unknown';
  const draftLabel = !result.valid
    ? 'Needs changes'
    : result.diagnostics.some((item) => item.severity === 'warning')
      ? 'Valid with warnings'
      : 'Ready to add';

  function updateField(name: string, value: string) {
    setFieldsByType((current) => ({
      ...current,
      [type]: { ...current[type], [name]: value },
    }));
    setAnnouncement('');
  }

  function resetDraft() {
    setOwner('');
    setTtl('3600');
    setFieldsByType((current) => ({ ...current, [type]: { ...DEFAULT_FIELDS[type] } }));
    setAnnouncement(`${type} draft reset.`);
  }

  function addRecord(event: React.SyntheticEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!result.valid || result.bind === undefined) {
      setAnnouncement('Correct the draft errors before adding this record.');
      return;
    }
    const bind = result.bind;
    if (workingRecords.some((record) => record.bind === bind)) {
      setAnnouncement('That canonical BIND record is already in the working set.');
      return;
    }
    if (workingRecords.length >= MAX_WORKING_RECORDS) {
      setAnnouncement(
        `The local working set is limited to ${String(MAX_WORKING_RECORDS)} records.`,
      );
      return;
    }
    const nextCharacters =
      bindWorkingSet.length + (bindWorkingSet === '' ? 0 : 1) + bind.length;
    if (nextCharacters > MAX_WORKING_SET_CHARACTERS) {
      setAnnouncement(
        `The local working set is limited to ${MAX_WORKING_SET_CHARACTERS.toLocaleString()} characters.`,
      );
      return;
    }
    setWorkingRecords((current) => [...current, { bind, json: result.json, type }]);
    setLintDocument(null);
    setAnnouncement(`${type} record added to the local working set.`);
  }

  function removeRecord(bind: string) {
    setWorkingRecords((current) => current.filter((record) => record.bind !== bind));
    setLintDocument(null);
    setAnnouncement('Record removed from the local working set.');
  }

  function clearWorkingSet() {
    setWorkingRecords([]);
    setLintDocument(null);
    setAnnouncement('Local working set cleared.');
  }

  function lintWorkingSet() {
    if (bindWorkingSet === '') {
      setAnnouncement('Add at least one record before linting the working set.');
      return;
    }
    const document = lintZoneSnippet(bindWorkingSet, { maximumTtl: 86_400, minimumTtl: 300 });
    setLintDocument(document);
    setAnnouncement(
      `Local lint parsed ${String(document.records.length)} records and produced ${String(document.diagnostics.length)} diagnostics.`,
    );
  }

  const ownerDiagnostics = fieldDiagnostics(result.diagnostics, 'owner');
  const ttlDiagnostics = fieldDiagnostics(result.diagnostics, 'ttl');

  return (
    <div className="tool-page">
      <ToolIntro eyebrow="DNS Record Studio" title="Author records without publishing them.">
        Build standards-based record text locally, inspect exactly what would be copied, and
        lint a temporary working set before making any provider change. Nothing here sends DNS
        updates or contacts a nameserver.
      </ToolIntro>

      <aside className="conclusion-panel" aria-label="Publication boundary">
        <StatusBadge tone="information">Local only</StatusBadge>
        <p>
          The studio produces reviewable text, not a deployment. Confirm names, values, provider
          syntax, delegation context, and change controls before publishing elsewhere.
        </p>
      </aside>

      <form className="workbench-form record-studio-form" onSubmit={addRecord} noValidate>
        <div className="field-group">
          <label htmlFor="record-studio-owner">Owner name</label>
          <input
            id="record-studio-owner"
            value={owner}
            onChange={(event) => {
              setOwner(event.currentTarget.value);
              setAnnouncement('');
            }}
            aria-describedby={descriptionIds(
              'record-studio-owner',
              'Use @ for an apex placeholder, or enter an absolute name. Wildcard owners are supported.',
              ownerDiagnostics,
            )}
            aria-invalid={ownerDiagnostics.some((item) => item.severity === 'error')}
            autoComplete="off"
            maxLength={253}
            placeholder="service.example.com."
            spellCheck={false}
          />
          <FieldNotes
            diagnostics={ownerDiagnostics}
            help="Use @ for an apex placeholder, or enter an absolute name. Wildcard owners are supported."
            id="record-studio-owner"
          />
        </div>

        <div className="field-group">
          <label htmlFor="record-studio-ttl">TTL</label>
          <input
            id="record-studio-ttl"
            value={ttl}
            onChange={(event) => {
              setTtl(event.currentTarget.value);
              setAnnouncement('');
            }}
            aria-describedby={descriptionIds(
              'record-studio-ttl',
              'Enter seconds or a duration such as 5m, 1h, or 1d.',
              ttlDiagnostics,
            )}
            aria-invalid={ttlDiagnostics.some((item) => item.severity === 'error')}
            autoComplete="off"
            maxLength={32}
            placeholder="3600"
            spellCheck={false}
          />
          <FieldNotes
            diagnostics={ttlDiagnostics}
            help="Enter seconds or a duration such as 5m, 1h, or 1d."
            id="record-studio-ttl"
          />
        </div>

        <div className="field-group">
          <label htmlFor="record-studio-type">Record type</label>
          <select
            id="record-studio-type"
            value={type}
            onChange={(event) => {
              setType(event.currentTarget.value as AuthoringRecordType);
              setAnnouncement('');
            }}
          >
            {RECORD_TYPES.map((recordType) => (
              <option key={recordType} value={recordType}>
                {recordType}
              </option>
            ))}
          </select>
          <span className="field-help">
            Each type keeps its draft fields while you switch views.
          </span>
        </div>

        {FIELD_DEFINITIONS[type].map((definition) => {
          const id = `record-studio-${type.toLowerCase()}-${definition.name}`;
          const diagnostics = fieldDiagnostics(result.diagnostics, definition.name);
          const describedBy = descriptionIds(id, definition.help, diagnostics);
          const common = {
            'aria-describedby': describedBy,
            'aria-invalid': diagnostics.some((item) => item.severity === 'error'),
            autoComplete: 'off',
            id,
            maxLength: definition.maxLength ?? 4096,
            name: definition.name,
            onChange: (
              event:
                React.ChangeEvent<HTMLInputElement> | React.ChangeEvent<HTMLTextAreaElement>,
            ) => updateField(definition.name, event.currentTarget.value),
            placeholder: definition.placeholder,
            spellCheck: false,
            value: fields[definition.name] ?? '',
          };
          const suggestionsId =
            definition.suggestions === undefined ? undefined : `${id}-values`;
          return (
            <div
              className={`field-group${definition.multiline === true ? ' record-studio-wide' : ''}`}
              key={`${type}-${definition.name}`}
            >
              <label htmlFor={id}>{definition.label}</label>
              {definition.multiline === true ? (
                <textarea {...common} rows={5} />
              ) : (
                <input {...common} inputMode={definition.inputMode} list={suggestionsId} />
              )}
              {definition.suggestions === undefined ? null : (
                <datalist id={suggestionsId}>
                  {definition.suggestions.map((suggestion) => (
                    <option key={suggestion} value={suggestion} />
                  ))}
                </datalist>
              )}
              <FieldNotes
                diagnostics={diagnostics}
                id={id}
                {...(definition.help === undefined ? {} : { help: definition.help })}
              />
            </div>
          );
        })}

        <div className="form-actions">
          <button className="primary-button" type="submit" disabled={!result.valid}>
            Add valid record
          </button>
          <button className="quiet-button" type="button" onClick={resetDraft}>
            Reset draft
          </button>
          <StatusBadge tone={draftTone}>{draftLabel}</StatusBadge>
        </div>
      </form>

      <div className="run-status" aria-live="polite">
        {announcement}
      </div>

      <section className="results" aria-labelledby="record-preview-title">
        <div className="section-heading">
          <div>
            <p className="eyebrow">Live local preview</p>
            <h2 id="record-preview-title">Draft output</h2>
          </div>
          <StatusBadge tone={draftTone}>{draftLabel}</StatusBadge>
        </div>

        <div className="comparison-grid record-studio-output-grid">
          <article className="result-panel">
            <div className="result-heading">
              <h3>BIND presentation</h3>
              {result.bind === undefined ? null : (
                <CopyButton label="Copy BIND record" text={result.bind} />
              )}
            </div>
            {result.bind === undefined ? (
              <p className="empty-note">
                Complete the required fields to produce a BIND record.
              </p>
            ) : (
              <pre className="raw-output">
                <code>{result.bind}</code>
              </pre>
            )}
          </article>

          <article className="result-panel">
            <div className="result-heading">
              <h3>Structured JSON</h3>
              <CopyButton label="Copy JSON" text={result.json} />
            </div>
            <pre className="raw-output">
              <code>{result.json}</code>
            </pre>
          </article>
        </div>

        {result.txtChunks === undefined ? null : (
          <article className="result-panel" aria-labelledby="txt-chunks-title">
            <div className="result-heading">
              <h3 id="txt-chunks-title">TXT character-strings</h3>
              <StatusBadge tone="information">
                {result.txtChunks.length} chunk{result.txtChunks.length === 1 ? '' : 's'}
              </StatusBadge>
            </div>
            <div className="table-scroll">
              <table>
                <caption>TXT chunks split at UTF-8 octet boundaries</caption>
                <thead>
                  <tr>
                    <th>Chunk</th>
                    <th>UTF-8 octets</th>
                    <th>Value</th>
                  </tr>
                </thead>
                <tbody>
                  {result.txtChunks.map((chunk, index) => (
                    <tr key={`${String(index)}-${chunk}`}>
                      <td>{index + 1}</td>
                      <td>{encoder.encode(chunk).length}</td>
                      <td>
                        <code className="record-value">{chunk === '' ? '(empty)' : chunk}</code>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </article>
        )}

        <article className="result-panel" aria-labelledby="authoring-diagnostics-title">
          <div className="result-heading">
            <h3 id="authoring-diagnostics-title">Draft diagnostics</h3>
            <StatusBadge tone={draftTone}>
              {result.diagnostics.length === 0
                ? 'No diagnostics'
                : `${String(result.diagnostics.length)} diagnostic${result.diagnostics.length === 1 ? '' : 's'}`}
            </StatusBadge>
          </div>
          {result.diagnostics.length === 0 ? (
            <p className="empty-note">
              The draft passed every authoring rule available for this type.
            </p>
          ) : (
            <ul className="diagnostic-list">
              {result.diagnostics.map((diagnostic, index) => (
                <li key={`${diagnostic.code}-${diagnostic.field}-${String(index)}`}>
                  <StatusBadge tone={diagnosticTone(diagnostic.severity)}>
                    {diagnostic.severity}
                  </StatusBadge>
                  <span>
                    <code>{diagnostic.field}</code>: {diagnostic.message}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </article>
      </section>

      <section className="results" aria-labelledby="working-set-title">
        <div className="section-heading">
          <div>
            <p className="eyebrow">Temporary collection</p>
            <h2 id="working-set-title">Working set</h2>
          </div>
          <div className="export-actions">
            <StatusBadge tone={workingRecords.length === 0 ? 'unknown' : 'information'}>
              {workingRecords.length} / {MAX_WORKING_RECORDS} records
            </StatusBadge>
            {workingRecords.length === 0 ? null : (
              <>
                <CopyButton label="Copy all BIND records" text={bindWorkingSet} />
                <SnapshotButton
                  content={workingSetJson}
                  title="DNS Record Studio working set"
                  tool="other"
                />
              </>
            )}
          </div>
        </div>

        <article className="result-panel">
          <div className="result-heading">
            <h3>Reviewable records</h3>
            <div className="export-actions">
              <button
                className="primary-button"
                type="button"
                onClick={lintWorkingSet}
                disabled={workingRecords.length === 0}
              >
                Lint working set
              </button>
              <button
                className="quiet-button"
                type="button"
                onClick={clearWorkingSet}
                disabled={workingRecords.length === 0}
              >
                Clear all
              </button>
            </div>
          </div>
          {workingRecords.length === 0 ? (
            <p className="empty-note">
              Add a valid draft to build a local set. Canonically identical records are ignored.
            </p>
          ) : (
            <div className="table-scroll">
              <table>
                <caption>DNS records in the temporary local working set</caption>
                <thead>
                  <tr>
                    <th>Type</th>
                    <th>BIND record</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {workingRecords.map((record) => (
                    <tr key={record.bind}>
                      <td>{record.type}</td>
                      <td>
                        <code className="record-value">{record.bind}</code>
                      </td>
                      <td>
                        <div className="export-actions">
                          <CopyButton text={record.bind} />
                          <button
                            className="quiet-button"
                            type="button"
                            onClick={() => removeRecord(record.bind)}
                            aria-label={`Remove ${record.type} record from working set`}
                          >
                            Remove
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <p className="detail-note">
            The local lint pass uses a recommended TTL range of 300–86,400 seconds and applies
            cross-record checks such as duplicate data and CNAME conflicts.
          </p>
        </article>

        {lintDocument === null ? null : (
          <article className="result-panel" aria-labelledby="working-lint-title">
            <div className="result-heading">
              <h3 id="working-lint-title">Working-set lint</h3>
              <StatusBadge tone={lintTone(lintDocument)}>{lintLabel(lintDocument)}</StatusBadge>
            </div>
            {lintDocument.diagnostics.length === 0 ? (
              <p className="empty-note">
                No rule fired for the supported zone-snippet syntax and record set.
              </p>
            ) : (
              <div className="table-scroll">
                <table>
                  <caption>Local diagnostics for the DNS record working set</caption>
                  <thead>
                    <tr>
                      <th>Severity</th>
                      <th>Line</th>
                      <th>Rule</th>
                      <th>Explanation</th>
                    </tr>
                  </thead>
                  <tbody>
                    {lintDocument.diagnostics.map((diagnostic: ZoneDiagnostic, index) => (
                      <tr
                        key={`${diagnostic.rule}-${String(diagnostic.line)}-${String(index)}`}
                      >
                        <td>
                          <StatusBadge tone={diagnosticTone(diagnostic.severity)}>
                            {diagnostic.severity}
                          </StatusBadge>
                        </td>
                        <td>{diagnostic.line}</td>
                        <td>
                          <code>{diagnostic.rule}</code>
                        </td>
                        <td>{diagnostic.message}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </article>
        )}

        <details className="method-note">
          <summary>Validation and publishing limits</summary>
          <p>
            Record Studio validates and serialises the supported fields, then the working-set
            linter checks a practical zone-file subset. It does not know provider-specific
            extensions, account permissions, existing records, signing policy, or the intended
            zone cut. Treat the output as a change candidate that still needs authoritative
            review and staged deployment.
          </p>
        </details>
      </section>
    </div>
  );
}
