import { useEffect, useMemo, useRef, useState } from 'react';

import { CopyButton } from '../components/CopyButton';
import { RecordTable } from '../components/RecordTable';
import { StatusBadge } from '../components/StatusBadge';
import { ToolIntro } from '../components/ToolIntro';
import { IANA_DNS_PARAMETER_SNAPSHOT, knownIanaRecordType } from '../core/dns/iana-snapshot';
import { validateDnsName } from '../core/dns/names';
import { useDomainThread } from '../core/domain-thread';
import { parseGenericRecordType } from '../core/dns/record-types';
import { DnsQueryError, type DnsRecordType, type DnsResponse } from '../core/dns/types';
import { DnsQueryRun } from '../core/doh/query-run';
import { createDnsResolver } from '../core/doh/resolvers';
import { inspectResinfo, type ResinfoReport } from '../core/protocol/resinfo';
import { escapeTechnicalText, stringifyTechnicalEvidence } from '../core/technical-text';
import { RequestLifetime } from '../core/request-lifetime';
import { decodeEchConfigList, type EchConfigListReport } from '../core/zone/svcb';

type Mode = 'rrtype' | 'ech' | 'resinfo';
type DirectResolverId = 'cloudflare' | 'google';

function selectedType(
  value: string,
): { readonly code: number; readonly type: DnsRecordType } | { readonly error: string } {
  const known = knownIanaRecordType(value);
  if (known !== null) {
    const supportedNames = new Set<DnsRecordType>([
      'A',
      'AAAA',
      'CNAME',
      'MX',
      'NS',
      'TXT',
      'SOA',
      'CAA',
      'SRV',
      'DS',
      'DNSKEY',
      'RRSIG',
      'NSEC',
      'NSEC3',
      'TLSA',
      'ZONEMD',
      'HTTPS',
      'SVCB',
      'CDS',
      'CDNSKEY',
      'CSYNC',
      'DSYNC',
    ]);
    return {
      code: known.code,
      type: supportedNames.has(known.name as DnsRecordType)
        ? (known.name as DnsRecordType)
        : (`TYPE${String(known.code)}` as DnsRecordType),
    };
  }
  const generic = parseGenericRecordType(value);
  return generic.ok ? { code: generic.typeCode, type: generic.type } : { error: generic.error };
}

function rawHex(response: DnsResponse): string {
  return [...response.message.raw].map((byte) => byte.toString(16).padStart(2, '0')).join(' ');
}

function responseTone(response: DnsResponse): 'pass' | 'warning' | 'error' {
  if (response.message.responseCode === 'NOERROR') return 'pass';
  if (
    response.message.responseCode === 'SERVFAIL' ||
    response.message.responseCode === 'REFUSED'
  )
    return 'error';
  return 'warning';
}

export function ProtocolLabPage() {
  const domainThread = useDomainThread();
  const [mode, setMode] = useState<Mode>('rrtype');
  const [name, setName] = useState(() => domainThread.domain?.display ?? '');
  const [typeInput, setTypeInput] = useState('66');
  const [resolverId, setResolverId] = useState<DirectResolverId>('google');
  const [response, setResponse] = useState<DnsResponse | null>(null);
  const [resinfo, setResinfo] = useState<ResinfoReport | null>(null);
  const [echInput, setEchInput] = useState('');
  const [echReports, setEchReports] = useState<readonly EchConfigListReport[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const run = useRef<DnsQueryRun | null>(null);
  const lifetime = useRef(new RequestLifetime());
  const idn = useMemo(() => (name.trim() === '' ? null : validateDnsName(name)), [name]);

  useEffect(() => {
    const current = lifetime.current;
    current.enter();
    return () => {
      current.leave();
      run.current?.cancel();
      run.current = null;
    };
  }, []);

  function clear(): void {
    lifetime.current.invalidate();
    run.current?.cancel();
    run.current = null;
    setResponse(null);
    setResinfo(null);
    setEchReports([]);
    setBusy(false);
    setError('');
  }

  async function query(event: React.SyntheticEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    clear();
    const generation = lifetime.current.capture();
    const parsedName = validateDnsName(name);
    if (!parsedName.ok) {
      setError(parsedName.error.message);
      return;
    }
    domainThread.setDomain(parsedName.value);
    const recordType =
      mode === 'resinfo' ? { code: 261, type: 'TYPE261' as const } : selectedType(typeInput);
    if ('error' in recordType) {
      setError(recordType.error);
      return;
    }
    run.current?.cancel();
    const nextRun = new DnsQueryRun();
    run.current = nextRun;
    setResponse(null);
    setResinfo(null);
    setError('');
    setBusy(true);
    try {
      const result = await nextRun.query(
        createDnsResolver(resolverId),
        { name: parsedName.value, type: recordType.type },
        { checkingDisabled: false, dnssecOk: true, recursionDesired: mode !== 'resinfo' },
      );
      if (!lifetime.current.isCurrent(generation) || run.current !== nextRun) return;
      setResponse(result);
      if (mode === 'resinfo') setResinfo(inspectResinfo(result.message));
    } catch (cause) {
      if (!lifetime.current.isCurrent(generation)) return;
      if (nextRun.cancelled) setError('The protocol query was cancelled.');
      else
        setError(
          cause instanceof DnsQueryError || cause instanceof Error
            ? cause.message
            : 'The protocol query failed.',
        );
    } finally {
      if (lifetime.current.isCurrent(generation) && run.current === nextRun) {
        run.current = null;
        setBusy(false);
      }
    }
  }

  function decodeEch(event: React.SyntheticEvent<HTMLFormElement>): void {
    event.preventDefault();
    const values = echInput
      .split(/\r?\n/u)
      .map((line) => line.trim())
      .filter(Boolean);
    if (values.length === 0) {
      setError('Paste at least one Base64 ECHConfigList.');
      return;
    }
    if (values.length > 16) {
      setError('Compare no more than 16 ECHConfigList values at once.');
      return;
    }
    setError('');
    setEchReports(values.map(decodeEchConfigList));
  }

  const consistentEch =
    echReports.length > 1 &&
    new Set(
      echInput
        .split(/\r?\n/u)
        .map((line) => line.replaceAll(/\s+/gu, ''))
        .filter(Boolean),
    ).size === 1;

  return (
    <div className="tool-page">
      <ToolIntro eyebrow="Protocol lab" title="Keep pace with DNS as it evolves.">
        Inspect newly assigned or unknown data record types without waiting for a bespoke
        screen, decode ECH configuration lists, and ask resolvers for RFC 9606 self-published
        information.
      </ToolIntro>
      <div className="mode-tabs" role="group" aria-label="Protocol Lab mode">
        <button
          type="button"
          aria-pressed={mode === 'rrtype'}
          onClick={() => {
            clear();
            setMode('rrtype');
          }}
        >
          Data RR type
        </button>
        <button
          type="button"
          aria-pressed={mode === 'ech'}
          onClick={() => {
            clear();
            setMode('ech');
          }}
        >
          ECH decoder
        </button>
        <button
          type="button"
          aria-pressed={mode === 'resinfo'}
          onClick={() => {
            clear();
            setMode('resinfo');
            setName('resolver.arpa');
          }}
        >
          Resolver profile
        </button>
      </div>
      {mode === 'ech' ? (
        <form className="workbench-form zone-form" onSubmit={decodeEch}>
          <div className="field-group field-wide">
            <label htmlFor="ech-config-list">ECHConfigList values</label>
            <textarea
              id="ech-config-list"
              value={echInput}
              onChange={(event) => {
                clear();
                setEchInput(event.currentTarget.value);
              }}
              rows={10}
              maxLength={131_072}
              spellCheck={false}
              placeholder="One Base64 ECHConfigList per line"
            />
            <small>
              Values are decoded locally. Multiple lines reveal whether endpoints publish
              identical configuration bytes; equality alone does not prove downgrade resistance.
            </small>
          </div>
          {error === '' ? null : (
            <p className="form-error" role="alert">
              {error}
            </p>
          )}
          <div className="form-actions">
            <button className="primary-button" type="submit">
              Decode ECH
            </button>
          </div>
        </form>
      ) : (
        <form className="workbench-form" onSubmit={(event) => void query(event)}>
          <div className="field-group">
            <label htmlFor="protocol-name">
              {mode === 'resinfo' ? 'Resolver authentication domain name' : 'DNS name'}
            </label>
            <input
              id="protocol-name"
              value={name}
              onChange={(event) => {
                clear();
                setName(event.currentTarget.value);
              }}
              placeholder={mode === 'resinfo' ? 'resolver.arpa' : 'example.com'}
              spellCheck={false}
            />
            {idn?.ok && idn.value.unicode ? (
              <small>
                Unicode input maps to A-label <bdi dir="ltr">{idn.value.ascii}</bdi>.
              </small>
            ) : null}
          </div>
          {mode === 'rrtype' ? (
            <div className="field-group">
              <label htmlFor="protocol-type">Mnemonic or numeric RR type</label>
              <input
                id="protocol-type"
                value={typeInput}
                onChange={(event) => {
                  clear();
                  setTypeInput(event.currentTarget.value);
                }}
                placeholder="DSYNC or 66"
                spellCheck={false}
              />
              <small>
                Safe data types are sent directly to the selected DoH resolver. Pseudo,
                transfer, authentication, ANY and reserved query types are refused.
              </small>
            </div>
          ) : null}
          <div className="field-group">
            <label htmlFor="protocol-resolver">Direct resolver</label>
            <select
              id="protocol-resolver"
              value={resolverId}
              onChange={(event) => {
                clear();
                setResolverId(event.currentTarget.value as DirectResolverId);
              }}
            >
              <option value="google">Google Public DNS</option>
              <option value="cloudflare">Cloudflare 1.1.1.1</option>
            </select>
          </div>
          {mode === 'resinfo' ? (
            <p className="detail-note field-wide">
              ZoneSkein sets RD=0 and discards a response with AA=0, as RFC 9606 requires.
              Returned attributes are resolver claims—not independent proof of privacy,
              filtering or capability.
            </p>
          ) : (
            <p className="detail-note field-wide">
              IANA snapshot reviewed {IANA_DNS_PARAMETER_SNAPSHOT.reviewedAt}; registry last
              updated {IANA_DNS_PARAMETER_SNAPSHOT.registryLastUpdated}. Unknown RDATA remains
              visible in RFC 3597 hexadecimal form.
            </p>
          )}
          {error === '' ? null : (
            <p className="form-error" role="alert">
              {error}
            </p>
          )}
          <div className="form-actions">
            <button className="primary-button" type="submit" disabled={busy}>
              {busy
                ? 'Querying…'
                : mode === 'resinfo'
                  ? 'Inspect resolver profile'
                  : 'Query data type'}
            </button>
            {busy ? (
              <button
                className="quiet-button"
                type="button"
                onClick={() => {
                  clear();
                  setError('The protocol query was cancelled.');
                }}
              >
                Cancel
              </button>
            ) : null}
          </div>
        </form>
      )}
      <div className="run-status" aria-live="polite">
        {busy ? 'Waiting for one bounded direct DNS-over-HTTPS response.' : null}
      </div>
      {echReports.length === 0 ? null : (
        <section className="results" aria-labelledby="ech-results-title">
          <div className="section-heading">
            <div>
              <p className="eyebrow">Local decode</p>
              <h2 id="ech-results-title">ECH configurations</h2>
            </div>
            <StatusBadge
              tone={
                echReports.every((report) => report.status === 'valid') ? 'pass' : 'warning'
              }
            >
              {echReports.length > 1
                ? consistentEch
                  ? 'Byte-identical'
                  : 'Divergent'
                : echReports[0]?.status}
            </StatusBadge>
          </div>
          {echReports.map((report, reportIndex) => (
            <article className="result-panel" key={reportIndex}>
              <div className="result-heading">
                <h3>Value {reportIndex + 1}</h3>
                <StatusBadge
                  tone={
                    report.status === 'valid'
                      ? 'pass'
                      : report.status === 'unsupported'
                        ? 'unknown'
                        : 'error'
                  }
                >
                  {report.status}
                </StatusBadge>
              </div>
              {report.error === undefined ? null : <p>{report.error}</p>}
              <dl className="metadata-grid">
                <div>
                  <dt>Total bytes</dt>
                  <dd>{report.totalOctets}</dd>
                </div>
                <div>
                  <dt>Configurations</dt>
                  <dd>{report.configurations.length}</dd>
                </div>
              </dl>
              {report.configurations.map((config, index) => (
                <div
                  className="nested-result"
                  key={`${String(config.version)}-${String(index)}`}
                >
                  <h4>Version 0x{config.version.toString(16).padStart(4, '0')}</h4>
                  <dl className="metadata-grid">
                    <div>
                      <dt>Configuration ID</dt>
                      <dd>{config.configId ?? 'Unavailable'}</dd>
                    </div>
                    <div>
                      <dt>Known KEM encoding</dt>
                      <dd>{config.supportedKem ? 'Yes' : 'No'}</dd>
                    </div>
                    <div>
                      <dt>Supported decode</dt>
                      <dd>{config.supportedVersion ? 'Yes' : 'No'}</dd>
                    </div>
                    <div>
                      <dt>Public name</dt>
                      <dd>{config.publicName ?? 'Unavailable'}</dd>
                    </div>
                    <div>
                      <dt>KEM ID</dt>
                      <dd>{config.kemId ?? 'Unavailable'}</dd>
                    </div>
                    <div>
                      <dt>Public key</dt>
                      <dd>
                        {config.publicKeyOctets === null
                          ? 'Unavailable'
                          : `${String(config.publicKeyOctets)} bytes`}
                      </dd>
                    </div>
                    <div>
                      <dt>Maximum name</dt>
                      <dd>{config.maximumNameLength ?? 'Unavailable'}</dd>
                    </div>
                    <div>
                      <dt>Cipher suites</dt>
                      <dd>
                        {config.cipherSuites
                          .map(
                            (suite) =>
                              `KDF ${String(suite.kdfId)} / AEAD ${String(suite.aeadId)}`,
                          )
                          .join(', ') || 'Unavailable'}
                      </dd>
                    </div>
                  </dl>
                </div>
              ))}
            </article>
          ))}
          {echReports.length > 1 && !consistentEch ? (
            <article className="conclusion-panel partial-panel">
              <StatusBadge tone="warning">Endpoint divergence</StatusBadge>
              <p>
                The supplied ECHConfigList bytes differ. Confirm whether this is an intentional
                staged rollout, stale cache or unexpected endpoint inconsistency before
                enforcing a single expected value.
              </p>
            </article>
          ) : null}
        </section>
      )}
      {response === null ? null : (
        <section className="results" aria-labelledby="protocol-results-title">
          <div className="section-heading">
            <div>
              <p className="eyebrow">Wire response</p>
              <h2 id="protocol-results-title">{name}</h2>
            </div>
            <div className="export-actions">
              <StatusBadge tone={responseTone(response)}>
                {response.message.responseCode}
              </StatusBadge>
              <CopyButton
                label="Copy protocol evidence JSON"
                text={stringifyTechnicalEvidence(
                  {
                    flags: response.message.flags,
                    messageBytes: response.message.messageBytes,
                    records: [
                      ...response.message.answers,
                      ...response.message.authorities,
                      ...response.message.additionals,
                    ].map((record) => ({
                      owner: record.owner,
                      type: record.type,
                      typeCode: record.typeCode,
                      ttl: record.ttl,
                      rawRdata: [...record.rawRdata],
                    })),
                    receivedAt: response.receivedAt,
                    resolver: response.resolver,
                  },
                  2,
                )}
              />
            </div>
          </div>
          {resinfo === null ? null : (
            <article className="conclusion-panel">
              <StatusBadge
                tone={
                  resinfo.state === 'accepted'
                    ? 'pass'
                    : resinfo.state === 'discarded'
                      ? 'error'
                      : 'warning'
                }
              >
                {resinfo.state}
              </StatusBadge>
              <p>{resinfo.explanation}</p>
              {resinfo.attributes.length === 0 ? null : (
                <ul>
                  {resinfo.attributes.map((item, index) => (
                    <li key={`${item.key}-${String(index)}`}>
                      <code>
                        {item.key}
                        {item.value === null ? '' : `=${escapeTechnicalText(item.value)}`}
                      </code>{' '}
                      · {item.known ? 'registered' : 'unknown'} ·{' '}
                      {item.valid ? 'syntax valid' : 'invalid'}
                    </li>
                  ))}
                </ul>
              )}
            </article>
          )}
          <RecordTable
            compact
            label="Protocol answer records"
            records={response.message.answers}
          />
          <dl className="metadata-grid">
            <div>
              <dt>RD</dt>
              <dd>{response.message.flags.recursionDesired ? 'set' : 'clear'}</dd>
            </div>
            <div>
              <dt>AA</dt>
              <dd>{response.message.flags.authoritativeAnswer ? 'set' : 'clear'}</dd>
            </div>
            <div>
              <dt>AD</dt>
              <dd>{response.message.flags.authenticatedData ? 'set' : 'clear'}</dd>
            </div>
            <div>
              <dt>Message</dt>
              <dd>{response.message.messageBytes} bytes</dd>
            </div>
          </dl>
          <details className="protocol-details">
            <summary>Exact DNS wire bytes</summary>
            <pre className="raw-output">{rawHex(response)}</pre>
          </details>
        </section>
      )}
    </div>
  );
}
