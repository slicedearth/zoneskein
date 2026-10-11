import { dnskeyDigest, hex } from './digest';
import { canEstablishDsTrustPath, canValidateDsDigestType } from './algorithm-policy';
import { dnskeyKeyTag, dnssecAlgorithmName, digestTypeName } from './records';
import { canonicalMasterName, masterNameEquals } from '../zone/master-name';
import { parseZoneSnippet } from '../zone/parser';
import type { ZoneRecord } from '../zone/types';

const MAX_LIFECYCLE_KEYS = 256;
const MAX_LIFECYCLE_DS_RECORDS = 1_024;
const MAX_LIFECYCLE_FINDINGS = 200;

export type LifecycleFindingTone = 'information' | 'warning' | 'error' | 'pass';

export interface LifecycleFinding {
  readonly code: string;
  readonly message: string;
  readonly tone: LifecycleFindingTone;
}

export interface LifecycleKey {
  readonly algorithm: number;
  readonly flags: number;
  readonly keyTag: number;
  readonly owner: string;
  readonly role: 'KSK' | 'ZSK' | 'delete-signal' | 'revoked' | 'other';
  readonly sourceType: 'CDNSKEY' | 'DNSKEY';
}

export interface LifecycleDs {
  readonly algorithm: number;
  readonly digest: string;
  readonly digestType: number;
  readonly keyTag: number;
  readonly owner: string;
  readonly sourceType: 'CDS' | 'DS';
}

export interface LifecycleStage {
  readonly action: string;
  readonly earliestOffsetSeconds: number;
  readonly id: string;
  readonly title: string;
}

export interface DnssecLifecycleReport {
  readonly derivedDs: readonly LifecycleDs[];
  readonly dsRecords: readonly LifecycleDs[];
  readonly findings: readonly LifecycleFinding[];
  readonly keys: readonly LifecycleKey[];
  readonly parsedRecords: number;
  readonly stages: readonly LifecycleStage[];
  readonly status: 'complete' | 'partial' | 'unavailable';
}

function integer(value: string, maximum: number): number | null {
  return /^(?:0|[1-9]\d*)$/u.test(value) && Number(value) <= maximum ? Number(value) : null;
}

function base64(value: string): Uint8Array | null {
  if (!/^[A-Za-z0-9+/]+={0,2}$/u.test(value)) return null;
  try {
    return Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
  } catch {
    return null;
  }
}

function keyRecord(
  record: ZoneRecord,
): { readonly info: LifecycleKey; readonly rdata: Uint8Array } | null {
  if (record.type !== 'DNSKEY' && record.type !== 'CDNSKEY') return null;
  const [flagsText, protocolText, algorithmText, ...keyParts] = record.rdata.map(
    (token) => token.value,
  );
  if (flagsText === undefined || protocolText === undefined || algorithmText === undefined)
    return null;
  const flags = integer(flagsText, 0xffff);
  const protocol = integer(protocolText, 0xff);
  const algorithm = integer(algorithmText, 0xff);
  const key = base64(keyParts.join(''));
  if (flags === null || protocol !== 3 || algorithm === null || key === null) return null;
  const rdata = new Uint8Array(4 + key.length);
  rdata[0] = flags >>> 8;
  rdata[1] = flags & 0xff;
  rdata[2] = protocol;
  rdata[3] = algorithm;
  rdata.set(key, 4);
  return {
    info: {
      algorithm,
      flags,
      keyTag: dnskeyKeyTag(rdata),
      owner: record.owner,
      role:
        record.type === 'CDNSKEY' &&
        flags === 0 &&
        algorithm === 0 &&
        key.length === 1 &&
        key[0] === 0
          ? 'delete-signal'
          : flags & 0x0080
            ? 'revoked'
            : flags & 0x0100
              ? flags & 0x0001
                ? 'KSK'
                : 'ZSK'
              : 'other',
      sourceType: record.type,
    },
    rdata,
  };
}

function dsRecord(record: ZoneRecord): LifecycleDs | null {
  if (record.type !== 'DS' && record.type !== 'CDS') return null;
  const [tagText, algorithmText, digestTypeText, ...digestParts] = record.rdata.map(
    (token) => token.value,
  );
  if (tagText === undefined || algorithmText === undefined || digestTypeText === undefined)
    return null;
  const keyTag = integer(tagText, 0xffff);
  const algorithm = integer(algorithmText, 0xff);
  const digestType = integer(digestTypeText, 0xff);
  const digest = digestParts.join('').toUpperCase();
  const expectedDigestOctets =
    digestType === 1 ? 20 : digestType === 2 ? 32 : digestType === 4 ? 48 : null;
  const deletionSignal =
    record.type === 'CDS' &&
    keyTag === 0 &&
    algorithm === 0 &&
    digestType === 0 &&
    digest === '00';
  return keyTag === null ||
    algorithm === null ||
    digestType === null ||
    !/^[0-9A-F]+$/u.test(digest) ||
    digest.length % 2 !== 0 ||
    (!deletionSignal &&
      expectedDigestOctets !== null &&
      digest.length !== expectedDigestOctets * 2)
    ? null
    : { algorithm, digest, digestType, keyTag, owner: record.owner, sourceType: record.type };
}

function cdsDeleteSignal(record: LifecycleDs): boolean {
  return (
    record.sourceType === 'CDS' &&
    record.keyTag === 0 &&
    record.algorithm === 0 &&
    record.digestType === 0 &&
    record.digest === '00'
  );
}

function sameDs(left: LifecycleDs, right: LifecycleDs): boolean {
  return (
    sameOwner(left.owner, right.owner) &&
    left.keyTag === right.keyTag &&
    left.algorithm === right.algorithm &&
    left.digestType === right.digestType &&
    left.digest === right.digest
  );
}

function sameOwner(left: string, right: string): boolean {
  const a = canonicalMasterName(left);
  const b = canonicalMasterName(right);
  return a !== null && b !== null && masterNameEquals(a, b);
}

function csyncType(value: string): 'A' | 'AAAA' | 'NS' | null {
  const upper = value.toUpperCase();
  return upper === 'A' || upper === 'TYPE1'
    ? 'A'
    : upper === 'NS' || upper === 'TYPE2'
      ? 'NS'
      : upper === 'AAAA' || upper === 'TYPE28'
        ? 'AAAA'
        : null;
}

function delegationSignalFindings(
  records: readonly ZoneRecord[],
  origin: string | undefined,
): readonly LifecycleFinding[] {
  const findings: LifecycleFinding[] = [];
  const csync = records.filter((record) => record.type === 'CSYNC');
  if (csync.length > 1)
    findings.push({
      code: 'csync-multiple',
      message:
        'More than one CSYNC record was supplied. Parental agents must ignore a multiple-record CSYNC RRset.',
      tone: 'error',
    });
  for (const record of csync.length === 1 ? csync : []) {
    const [serialText, flagsText, ...typeTokens] = record.rdata.map((token) => token.value);
    const serial = serialText === undefined ? null : integer(serialText, 0xffff_ffff);
    const flags = flagsText === undefined ? null : integer(flagsText, 0xffff);
    const types = typeTokens.map(csyncType);
    if (
      serial === null ||
      flags === null ||
      typeTokens.length === 0 ||
      types.some((type) => type === null) ||
      new Set(types).size !== types.length
    ) {
      findings.push({
        code: 'csync-invalid',
        message: `Line ${String(record.line)}: CSYNC requires a 32-bit SOA serial, supported flags, and a unique NS, A, or AAAA type list.`,
        tone: 'error',
      });
      continue;
    }
    if (origin !== undefined && record.owner !== origin)
      findings.push({
        code: 'csync-not-apex',
        message: `Line ${String(record.line)}: CSYNC is outside the supplied child-zone apex.`,
        tone: 'error',
      });
    if ((flags & ~0x0003) !== 0) {
      findings.push({
        code: 'csync-flags-unknown',
        message: `Line ${String(record.line)}: CSYNC sets reserved flag bits that a parental agent must not process.`,
        tone: 'error',
      });
      continue;
    }
    findings.push({
      code: 'csync-signal',
      message: `CSYNC serial ${String(serial)} requests ${types.join(', ')} synchronisation${(flags & 0x0001) !== 0 ? ' with the immediate flag' : ''}${(flags & 0x0002) !== 0 ? ' using the SOA minimum gate' : ''}.`,
      tone: 'information',
    });
    findings.push({
      code: 'csync-consistency-unverified',
      message:
        'The supplied text cannot establish secure, consistent CSYNC and referenced RRsets across every delegated authoritative server.',
      tone: 'warning',
    });
  }

  const combinations = new Set<string>();
  for (const record of records.filter((item) => item.type === 'DSYNC')) {
    const [rrtypeText, schemeText, portText, targetText, ...extra] = record.rdata.map(
      (token) => token.value,
    );
    const rrtype = rrtypeText?.toUpperCase();
    const scheme =
      schemeText?.toUpperCase() === 'NOTIFY'
        ? 1
        : schemeText === undefined
          ? null
          : integer(schemeText, 0xff);
    const port = portText === undefined ? null : integer(portText, 0xffff);
    const targetOrigin = record.origin ?? origin;
    const target =
      targetText === undefined || targetOrigin === undefined
        ? null
        : (canonicalMasterName(targetText, targetOrigin)?.absolute ?? null);
    if (
      (rrtype !== 'CDS' && rrtype !== 'CSYNC') ||
      scheme === null ||
      port === null ||
      target === null ||
      extra.length > 0
    ) {
      findings.push({
        code: 'dsync-invalid',
        message: `Line ${String(record.line)}: DSYNC requires CDS or CSYNC, an 8-bit scheme, a 16-bit port, and one valid target name.`,
        tone: 'error',
      });
      continue;
    }
    const combination = `${rrtype}|${String(scheme)}`;
    if (combinations.has(combination))
      findings.push({
        code: 'dsync-duplicate',
        message: `Line ${String(record.line)}: DSYNC repeats the ${rrtype} scheme ${String(scheme)} combination.`,
        tone: 'error',
      });
    combinations.add(combination);
    if (scheme === 0 || port === 0)
      findings.push({
        code: 'dsync-ignored',
        message: `DSYNC ${rrtype} is a null-scheme or zero-port record that consumers ignore.`,
        tone: 'warning',
      });
    else if (scheme !== 1)
      findings.push({
        code: 'dsync-scheme-unsupported',
        message: `DSYNC ${rrtype} uses scheme ${String(scheme)}, which this workbench does not interpret.`,
        tone: 'warning',
      });
    else
      findings.push({
        code: 'dsync-endpoint',
        message: `DSYNC advertises a ${rrtype} notification endpoint at ${target}:${String(port)}. Reachability and receiver authority are not tested.`,
        tone: 'information',
      });
  }
  const signatures = records.filter((record) => record.type === 'RRSIG').length;
  if (signatures > 0)
    findings.push({
      code: 'rrsig-unverified',
      message: `${String(signatures)} RRSIG record${signatures === 1 ? ' was' : 's were'} retained as supplied context but not cryptographically verified by this lifecycle model.`,
      tone: 'information',
    });
  return findings;
}

export async function analyseDnssecLifecycle(
  source: string,
  origin?: string,
): Promise<DnssecLifecycleReport> {
  const document = parseZoneSnippet(
    source,
    origin === undefined || origin.trim() === '' ? {} : { origin },
  );
  const findings: LifecycleFinding[] = document.diagnostics
    .filter((diagnostic) => diagnostic.severity === 'error')
    .slice(0, 50)
    .map((diagnostic) => ({
      code: diagnostic.rule,
      message: `Line ${String(diagnostic.line)}: ${diagnostic.message}`,
      tone: 'error' as const,
    }));
  const keyRecords = document.records.filter(
    (record) => record.type === 'DNSKEY' || record.type === 'CDNSKEY',
  );
  if (keyRecords.length > MAX_LIFECYCLE_KEYS)
    findings.push({
      code: 'key-input-limit',
      message: `Only the first ${String(MAX_LIFECYCLE_KEYS)} DNSKEY and CDNSKEY records are analysed.`,
      tone: 'error',
    });
  const parsedKeys = keyRecords
    .slice(0, MAX_LIFECYCLE_KEYS)
    .map(keyRecord)
    .filter((value): value is NonNullable<typeof value> => value !== null);
  const keys = parsedKeys.map((value) => value.info);
  const suppliedDsRecords = document.records.filter(
    (record) => record.type === 'DS' || record.type === 'CDS',
  );
  if (suppliedDsRecords.length > MAX_LIFECYCLE_DS_RECORDS)
    findings.push({
      code: 'ds-input-limit',
      message: `Only the first ${String(MAX_LIFECYCLE_DS_RECORDS)} DS and CDS records are analysed.`,
      tone: 'error',
    });
  const dsRecords = suppliedDsRecords
    .slice(0, MAX_LIFECYCLE_DS_RECORDS)
    .map(dsRecord)
    .filter((value): value is LifecycleDs => value !== null);
  for (const record of [
    ...keyRecords.slice(0, MAX_LIFECYCLE_KEYS),
    ...suppliedDsRecords.slice(0, MAX_LIFECYCLE_DS_RECORDS),
  ]) {
    if ((record.type === 'DNSKEY' || record.type === 'CDNSKEY') && keyRecord(record) === null)
      findings.push({
        code: 'key-record-invalid',
        message: `Line ${String(record.line)}: ${record.type} fields are malformed or unsupported.`,
        tone: 'error',
      });
    if ((record.type === 'DS' || record.type === 'CDS') && dsRecord(record) === null)
      findings.push({
        code: 'ds-record-invalid',
        message: `Line ${String(record.line)}: ${record.type} fields or digest length are invalid.`,
        tone: 'error',
      });
  }
  findings.push(...delegationSignalFindings(document.records, document.origin));
  const comparableDs: LifecycleDs[] = [];
  for (const key of parsedKeys.filter((item) => item.info.sourceType === 'DNSKEY')) {
    for (const digestType of [1, 2, 4] as const) {
      comparableDs.push({
        algorithm: key.info.algorithm,
        digest: hex(await dnskeyDigest(key.info.owner, key.rdata, digestType)),
        digestType,
        keyTag: key.info.keyTag,
        owner: key.info.owner,
        sourceType: 'DS',
      });
    }
  }
  const derivableKeyTags = new Set(
    keys
      .filter(
        (key) =>
          key.sourceType === 'DNSKEY' &&
          (key.role === 'KSK' || key.role === 'ZSK') &&
          canEstablishDsTrustPath(key.algorithm),
      )
      .map((key) => `${key.owner}|${String(key.keyTag)}|${String(key.algorithm)}`),
  );
  const derivedDs = comparableDs.filter(
    (record) =>
      record.digestType !== 1 &&
      derivableKeyTags.has(
        `${record.owner}|${String(record.keyTag)}|${String(record.algorithm)}`,
      ),
  );
  if (keys.length === 0)
    findings.push({
      code: 'dnskey-missing',
      message: 'No parseable DNSKEY or CDNSKEY records were supplied.',
      tone: 'warning',
    });
  if (dsRecords.filter((record) => record.sourceType === 'DS').length === 0)
    findings.push({
      code: 'ds-missing',
      message:
        'No parent DS record was supplied, so the parent-child trust link is unavailable.',
      tone: 'warning',
    });
  for (const key of keys) {
    if (key.role === 'delete-signal') {
      findings.push({
        code: 'cdnskey-delete-signal',
        message:
          'The CDNSKEY deletion signal requests removal of the parent DS trust link. Confirm registrar support and maintain an authenticated rollback path before acting.',
        tone: 'warning',
      });
      continue;
    }
    if (key.role === 'other')
      findings.push({
        code: 'zone-bit-clear',
        message: `${key.sourceType} ${String(key.keyTag)} does not set the Zone Key flag.`,
        tone: 'error',
      });
    if (key.role === 'revoked')
      findings.push({
        code: 'revoked-key',
        message: `${key.sourceType} ${String(key.keyTag)} has the revoke flag set.`,
        tone: 'warning',
      });
    if ([5, 7].includes(key.algorithm))
      findings.push({
        code: 'legacy-algorithm',
        message: `${key.sourceType} ${String(key.keyTag)} uses legacy ${dnssecAlgorithmName(key.algorithm)}.`,
        tone: 'warning',
      });
    else if (!canEstablishDsTrustPath(key.algorithm))
      findings.push({
        code: 'unsupported-ds-algorithm',
        message: `${key.sourceType} ${String(key.keyTag)} uses ${dnssecAlgorithmName(key.algorithm)}, which this workbench does not offer for a new DS trust path.`,
        tone: 'error',
      });
  }
  for (const ds of dsRecords) {
    if (cdsDeleteSignal(ds)) {
      findings.push({
        code: 'cds-delete-signal',
        message:
          'The CDS deletion signal requests removal of the parent DS trust link. Confirm registrar support and maintain an authenticated rollback path before acting.',
        tone: 'warning',
      });
      continue;
    }
    if (ds.digestType === 1)
      findings.push({
        code: 'sha1-ds',
        message: `${ds.sourceType} ${String(ds.keyTag)} uses ${digestTypeName(ds.digestType)}. Prefer SHA-256 or SHA-384.`,
        tone: 'warning',
      });
    if (ds.sourceType === 'DS') {
      if (!canValidateDsDigestType(ds.digestType))
        findings.push({
          code: 'unsupported-ds-digest',
          message: `Parent DS ${String(ds.keyTag)} uses ${digestTypeName(ds.digestType)}, which cannot be compared locally.`,
          tone: 'warning',
        });
      else if (!comparableDs.some((derived) => sameDs(ds, derived)))
        findings.push({
          code: 'orphan-ds',
          message: `Parent DS ${String(ds.keyTag)} does not match a supplied DNSKEY at the same owner using the same algorithm and digest.`,
          tone: 'error',
        });
    }
  }
  const cds = dsRecords.filter(
    (record) => record.sourceType === 'CDS' && !cdsDeleteSignal(record),
  );
  const parentDs = dsRecords.filter((record) => record.sourceType === 'DS');
  if (
    cds.length > 0 &&
    !cds.every((record) => parentDs.some((parent) => sameDs(record, parent)))
  )
    findings.push({
      code: 'cds-parent-divergence',
      message: 'The supplied CDS set is not yet reflected in the supplied parent DS set.',
      tone: 'information',
    });
  const cdnskeys = parsedKeys.filter(
    (record) => record.info.sourceType === 'CDNSKEY' && record.info.role !== 'delete-signal',
  );
  if (
    cdnskeys.length > 0 &&
    !cdnskeys.every((record) =>
      parsedKeys.some(
        (dnskey) =>
          dnskey.info.sourceType === 'DNSKEY' &&
          sameOwner(dnskey.info.owner, record.info.owner) &&
          dnskey.rdata.length === record.rdata.length &&
          dnskey.rdata.every((byte, index) => byte === record.rdata[index]),
      ),
    )
  )
    findings.push({
      code: 'cdnskey-divergence',
      message:
        'A CDNSKEY does not have byte-identical DNSKEY material at the same owner in the supplied child set.',
      tone: 'error',
    });
  if (
    findings.every((finding) => finding.tone !== 'error') &&
    keys.length > 0 &&
    parentDs.length > 0 &&
    parentDs.every(
      (record) =>
        canValidateDsDigestType(record.digestType) &&
        comparableDs.some((derived) => sameDs(record, derived)),
    )
  )
    findings.push({
      code: 'supplied-link-consistent',
      message:
        'Every supplied parent DS matches supplied child key material for its digest type.',
      tone: 'pass',
    });

  const childTtlValues = document.records
    .filter((record) => ['DNSKEY', 'CDNSKEY', 'CDS'].includes(record.type))
    .flatMap((record) => (record.ttl === undefined ? [] : [record.ttl]));
  const parentTtlValues = document.records
    .filter((record) => record.type === 'DS')
    .flatMap((record) => (record.ttl === undefined ? [] : [record.ttl]));
  const childWait = childTtlValues.length === 0 ? 86_400 : Math.max(...childTtlValues);
  const parentWait = parentTtlValues.length === 0 ? 86_400 : Math.max(...parentTtlValues);
  const stages: readonly LifecycleStage[] = [
    {
      action:
        'Publish the new DNSKEY and, when used, matching CDS or CDNSKEY while retaining the old key material.',
      earliestOffsetSeconds: 0,
      id: 'prepublish',
      title: 'Pre-publish new key material',
    },
    {
      action:
        'Allow caches to learn the complete overlapping child key set before changing the parent.',
      earliestOffsetSeconds: childWait,
      id: 'child-wait',
      title: 'Wait through the child TTL',
    },
    {
      action:
        'Update the parent DS only after checking every reachable authoritative server returns the intended child signalling consistently.',
      earliestOffsetSeconds: childWait,
      id: 'parent',
      title: 'Change the parent trust link',
    },
    {
      action:
        'Retain both old and new validation paths until the prior parent DS can no longer remain cached.',
      earliestOffsetSeconds: childWait + parentWait,
      id: 'parent-wait',
      title: 'Wait through the parent TTL',
    },
    {
      action:
        'Remove superseded keys only after independent validation and a tested rollback checkpoint.',
      earliestOffsetSeconds: childWait + parentWait,
      id: 'retire',
      title: 'Retire old material',
    },
  ];
  const hasLifecycleRecords = document.records.some((record) =>
    ['DNSKEY', 'CDNSKEY', 'DS', 'CDS', 'CSYNC', 'DSYNC', 'RRSIG'].includes(record.type),
  );
  const status: DnssecLifecycleReport['status'] = !hasLifecycleRecords
    ? 'unavailable'
    : document.incomplete !== undefined ||
        findings.some((finding) => finding.tone === 'error' || finding.tone === 'warning')
      ? 'partial'
      : 'complete';
  const reportedFindings = findings.slice(0, MAX_LIFECYCLE_FINDINGS - 1);
  if (findings.length >= MAX_LIFECYCLE_FINDINGS)
    reportedFindings.push({
      code: 'finding-limit',
      message: `Only the first ${String(MAX_LIFECYCLE_FINDINGS - 1)} lifecycle findings are shown.`,
      tone: 'error',
    });
  return {
    derivedDs,
    dsRecords,
    findings: reportedFindings,
    keys,
    parsedRecords: document.records.length,
    stages,
    status,
  };
}
