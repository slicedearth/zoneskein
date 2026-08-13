import { validateDnsName } from '../dns/names';
import type { DnsRecord, DnsRecordType } from '../dns/types';
import { failure, success, type Result } from '../result';
import { boundCanonicalRdata } from './wire-evidence';

export const MAX_DNSSEC_ALIAS_TRANSITIONS = 64;

export type DnssecAliasErrorCode =
  | 'ambiguous-alias'
  | 'invalid-name'
  | 'invalid-owner'
  | 'invalid-rdata'
  | 'invalid-record'
  | 'invalid-synthesis'
  | 'loop'
  | 'transition-limit'
  | 'wrong-position';

export interface DnssecAliasError {
  readonly code: DnssecAliasErrorCode;
  readonly message: string;
}

export interface DnssecAliasPosition {
  readonly name: string;
  readonly transitions: number;
  readonly type: DnsRecordType;
}

export interface DnssecAliasTransition {
  readonly aliasOwner: string;
  readonly aliasType: 'CNAME' | 'DNAME' | 'HTTPS' | 'SVCB';
  readonly fromName: string;
  readonly fromType: DnsRecordType;
  readonly kind: 'alias';
  readonly targetName: string;
  readonly targetType: DnsRecordType;
}

export interface DnssecDnameTransition extends DnssecAliasTransition {
  readonly aliasType: 'DNAME';
  readonly synthesisedCnamePresent: boolean;
}

export interface ServiceBindingRecord {
  readonly effectiveTargetName: string;
  readonly priority: number;
  readonly record: DnsRecord;
  readonly targetName: string;
}

export type ServiceBindingClassification =
  | {
      readonly ignoredServiceRecords: number;
      readonly kind: 'alias';
      readonly records: readonly ServiceBindingRecord[];
      readonly transition: DnssecAliasTransition;
    }
  | {
      readonly ignoredServiceRecords: number;
      readonly kind: 'alias-choices';
      readonly records: readonly ServiceBindingRecord[];
      readonly targetNames: readonly string[];
    }
  | {
      readonly kind: 'service';
      readonly records: readonly ServiceBindingRecord[];
    }
  | {
      readonly kind: 'unavailable';
      readonly records: readonly ServiceBindingRecord[];
    };

interface ParsedWireName {
  readonly endOffset: number;
  readonly name: string;
}

function aliasFailure(
  code: DnssecAliasErrorCode,
  message: string,
): Result<never, DnssecAliasError> {
  return failure({ code, message });
}

function canonicalTextName(value: string): Result<string, DnssecAliasError> {
  if (value !== value.trim() || value.includes('://'))
    return aliasFailure('invalid-name', 'The alias name is not a canonical DNS name.');
  const parsed = validateDnsName(value);
  return parsed.ok
    ? success(parsed.value.absolute)
    : aliasFailure('invalid-name', `The alias name is invalid: ${parsed.error.message}`);
}

function parseWireName(
  bytes: Uint8Array,
  startOffset = 0,
): Result<ParsedWireName, DnssecAliasError> {
  const labels: string[] = [];
  let offset = startOffset;
  let wireLength = 1;
  for (;;) {
    const length = bytes[offset];
    if (length === undefined)
      return aliasFailure('invalid-rdata', 'The alias target name is truncated.');
    if (length > 63 || (length & 0xc0) !== 0)
      return aliasFailure(
        'invalid-rdata',
        'The alias target must be an uncompressed wire-format DNS name.',
      );
    offset += 1;
    if (length === 0) {
      const candidate = labels.length === 0 ? '.' : `${labels.join('.')}.`;
      const canonical = canonicalTextName(candidate);
      return canonical.ok ? success({ endOffset: offset, name: canonical.value }) : canonical;
    }
    if (offset + length > bytes.length)
      return aliasFailure('invalid-rdata', 'The alias target label is truncated.');
    wireLength += length + 1;
    if (wireLength > 255)
      return aliasFailure('invalid-rdata', 'The alias target exceeds the DNS wire-name limit.');
    let label = '';
    for (let index = offset; index < offset + length; index += 1) {
      const byte = bytes[index];
      if (byte === undefined || byte > 0x7f)
        return aliasFailure(
          'invalid-rdata',
          'The alias target contains an unsafe non-ASCII wire label.',
        );
      label += String.fromCharCode(byte);
    }
    labels.push(label);
    offset += length;
  }
}

function canonicalRecordOwner(record: DnsRecord): Result<string, DnssecAliasError> {
  const text = canonicalTextName(record.owner);
  if (!text.ok) return aliasFailure('invalid-owner', text.error.message);
  if (record.canonicalOwnerWire === undefined) return text;
  const wire = parseWireName(record.canonicalOwnerWire);
  if (!wire.ok || wire.value.endOffset !== record.canonicalOwnerWire.length)
    return aliasFailure('invalid-owner', 'The alias record owner has invalid wire evidence.');
  return wire.value.name === text.value
    ? text
    : aliasFailure(
        'invalid-owner',
        'The alias record owner does not match its canonical wire evidence.',
      );
}

function canonicalRecordRdata(record: DnsRecord): Uint8Array {
  return boundCanonicalRdata(record) ?? record.rawRdata;
}

function expectedTypeCode(type: 'CNAME' | 'DNAME' | 'HTTPS' | 'SVCB'): number {
  if (type === 'CNAME') return 5;
  if (type === 'DNAME') return 39;
  return type === 'SVCB' ? 64 : 65;
}

function validateRecord(
  record: DnsRecord,
  type: 'CNAME' | 'DNAME' | 'HTTPS' | 'SVCB',
): Result<string, DnssecAliasError> {
  if (
    record.class.toUpperCase() !== 'IN' ||
    record.type !== type ||
    record.typeCode !== expectedTypeCode(type)
  )
    return aliasFailure(
      'invalid-record',
      `The authenticated alias RRset contains a record that is not an IN ${type} record.`,
    );
  return canonicalRecordOwner(record);
}

function targetFromNameRdata(record: DnsRecord): Result<string, DnssecAliasError> {
  const rdata = canonicalRecordRdata(record);
  const parsed = parseWireName(rdata);
  return parsed.ok && parsed.value.endOffset === rdata.length
    ? success(parsed.value.name)
    : parsed.ok
      ? aliasFailure('invalid-rdata', 'The alias target has trailing wire-format data.')
      : parsed;
}

function uniqueValue(
  values: readonly string[],
  description: string,
): Result<string, DnssecAliasError> {
  if (values.length === 0)
    return aliasFailure('invalid-record', `The authenticated ${description} is empty.`);
  const unique = new Set(values);
  if (unique.size !== 1)
    return aliasFailure(
      'ambiguous-alias',
      `The authenticated ${description} contains divergent alias values.`,
    );
  const value = unique.values().next().value;
  return value === undefined
    ? aliasFailure('invalid-record', 'The alias value is absent.')
    : success(value);
}

function transition(
  aliasOwner: string,
  aliasType: DnssecAliasTransition['aliasType'],
  fromName: string,
  fromType: DnsRecordType,
  targetName: string,
  targetType = fromType,
): DnssecAliasTransition {
  return {
    aliasOwner,
    aliasType,
    fromName,
    fromType,
    kind: 'alias',
    targetName,
    targetType,
  };
}

export function exactCnameTransition(
  currentName: string,
  currentType: DnsRecordType,
  records: readonly DnsRecord[],
): Result<DnssecAliasTransition, DnssecAliasError> {
  const owner = canonicalTextName(currentName);
  if (!owner.ok) return owner;
  if (records.length === 0)
    return aliasFailure('invalid-record', 'The authenticated CNAME RRset is empty.');
  const targets: string[] = [];
  for (const record of records) {
    const recordOwner = validateRecord(record, 'CNAME');
    if (!recordOwner.ok) return recordOwner;
    if (recordOwner.value !== owner.value)
      return aliasFailure(
        'invalid-owner',
        'A CNAME transition must be owned by the current query name.',
      );
    const target = targetFromNameRdata(record);
    if (!target.ok) return target;
    targets.push(target.value);
  }
  const target = uniqueValue(targets, 'CNAME RRset');
  return target.ok
    ? success(transition(owner.value, 'CNAME', owner.value, currentType, target.value))
    : target;
}

function labels(name: string): readonly string[] {
  return name === '.' ? [] : name.slice(0, -1).split('.');
}

function isStrictAncestor(owner: string, name: string): boolean {
  const ownerLabels = labels(owner);
  const nameLabels = labels(name);
  return (
    ownerLabels.length < nameLabels.length &&
    ownerLabels.every(
      (label, index) => nameLabels[nameLabels.length - ownerLabels.length + index] === label,
    )
  );
}

function substituteDname(
  currentName: string,
  owner: string,
  target: string,
): Result<string, DnssecAliasError> {
  const currentLabels = labels(currentName);
  const prefixLength = currentLabels.length - labels(owner).length;
  const candidateLabels = [...currentLabels.slice(0, prefixLength), ...labels(target)];
  const candidate = candidateLabels.length === 0 ? '.' : `${candidateLabels.join('.')}.`;
  const parsed = canonicalTextName(candidate);
  return parsed.ok
    ? parsed
    : aliasFailure(
        'invalid-synthesis',
        'The DNAME substitution exceeds a DNS name bound or produces an invalid name.',
      );
}

export function ancestorDnameTransition(
  currentName: string,
  currentType: DnsRecordType,
  dnameRecords: readonly DnsRecord[],
  synthesisedCnames: readonly DnsRecord[] = [],
): Result<DnssecDnameTransition, DnssecAliasError> {
  const current = canonicalTextName(currentName);
  if (!current.ok) return current;
  if (dnameRecords.length === 0)
    return aliasFailure('invalid-record', 'The authenticated DNAME RRset is empty.');

  const owners: string[] = [];
  const targets: string[] = [];
  const ttls: number[] = [];
  for (const record of dnameRecords) {
    const owner = validateRecord(record, 'DNAME');
    if (!owner.ok) return owner;
    if (!isStrictAncestor(owner.value, current.value))
      return aliasFailure(
        'invalid-owner',
        'A DNAME transition must be owned by a strict ancestor of the current query name.',
      );
    const target = targetFromNameRdata(record);
    if (!target.ok) return target;
    owners.push(owner.value);
    targets.push(target.value);
    ttls.push(record.ttl);
  }
  const owner = uniqueValue(owners, 'DNAME RRset owners');
  if (!owner.ok) return owner;
  const target = uniqueValue(targets, 'DNAME RRset');
  if (!target.ok) return target;
  if (
    ttls.some((ttl) => !Number.isSafeInteger(ttl) || ttl < 0 || ttl > 0xffff_ffff) ||
    new Set(ttls).size !== 1
  )
    return aliasFailure(
      'ambiguous-alias',
      'The authenticated DNAME records have divergent TTLs.',
    );

  const substituted = substituteDname(current.value, owner.value, target.value);
  if (!substituted.ok) return substituted;
  const dnameTtl = ttls[0];
  if (dnameTtl === undefined)
    return aliasFailure('invalid-record', 'The authenticated DNAME RRset is empty.');
  for (const record of synthesisedCnames) {
    const cnameOwner = validateRecord(record, 'CNAME');
    if (!cnameOwner.ok) return cnameOwner;
    if (cnameOwner.value !== current.value)
      return aliasFailure(
        'invalid-synthesis',
        'The synthesised CNAME owner does not match the current query name.',
      );
    const cnameTarget = targetFromNameRdata(record);
    if (!cnameTarget.ok) return cnameTarget;
    if (cnameTarget.value !== substituted.value)
      return aliasFailure(
        'invalid-synthesis',
        'The synthesised CNAME does not match the authenticated DNAME substitution.',
      );
    if (record.ttl !== 0 && record.ttl !== dnameTtl)
      return aliasFailure(
        'invalid-synthesis',
        'A synthesised CNAME TTL must be zero or equal to the authenticated DNAME TTL.',
      );
  }
  return success({
    ...transition(owner.value, 'DNAME', current.value, currentType, substituted.value),
    aliasType: 'DNAME',
    synthesisedCnamePresent: synthesisedCnames.length > 0,
  });
}

function readUint16(bytes: Uint8Array, offset: number): number | null {
  const high = bytes[offset];
  const low = bytes[offset + 1];
  return high === undefined || low === undefined ? null : (high << 8) | low;
}

function validServiceParameters(bytes: Uint8Array, startOffset: number): boolean {
  let offset = startOffset;
  let previousKey = -1;
  while (offset < bytes.length) {
    const key = readUint16(bytes, offset);
    const length = readUint16(bytes, offset + 2);
    if (
      key === null ||
      length === null ||
      key <= previousKey ||
      offset + 4 + length > bytes.length
    )
      return false;
    previousKey = key;
    offset += 4 + length;
  }
  return offset === bytes.length;
}

function parseServiceBindingRecord(
  owner: string,
  type: 'HTTPS' | 'SVCB',
  record: DnsRecord,
): Result<ServiceBindingRecord, DnssecAliasError> {
  const recordOwner = validateRecord(record, type);
  if (!recordOwner.ok) return recordOwner;
  if (recordOwner.value !== owner)
    return aliasFailure(
      'invalid-owner',
      `A ${type} RRset must be owned by the current query name.`,
    );
  const rdata = canonicalRecordRdata(record);
  const priority = readUint16(rdata, 0);
  if (priority === null)
    return aliasFailure('invalid-rdata', `The ${type} SvcPriority field is truncated.`);
  const target = parseWireName(rdata, 2);
  if (!target.ok) return target;
  if (!validServiceParameters(rdata, target.value.endOffset))
    return aliasFailure(
      'invalid-rdata',
      `The ${type} SvcParams are truncated, duplicated, or out of numeric order.`,
    );
  return success({
    effectiveTargetName:
      priority !== 0 && target.value.name === '.' ? owner : target.value.name,
    priority,
    record,
    targetName: target.value.name,
  });
}

export function classifyServiceBindingRrset(
  currentName: string,
  type: 'HTTPS' | 'SVCB',
  records: readonly DnsRecord[],
): Result<ServiceBindingClassification, DnssecAliasError> {
  const owner = canonicalTextName(currentName);
  if (!owner.ok) return owner;
  if (records.length === 0)
    return aliasFailure('invalid-record', `The authenticated ${type} RRset is empty.`);
  const parsed: ServiceBindingRecord[] = [];
  for (const record of records) {
    const item = parseServiceBindingRecord(owner.value, type, record);
    if (!item.ok) return item;
    parsed.push(item.value);
  }
  const aliases = parsed.filter((item) => item.priority === 0);
  if (aliases.length === 0) return success({ kind: 'service', records: parsed });
  const targetNames = [...new Set(aliases.map((item) => item.targetName))].sort();
  if (targetNames.length > 1)
    return success({
      ignoredServiceRecords: parsed.length - aliases.length,
      kind: 'alias-choices',
      records: aliases,
      targetNames,
    });
  const target = targetNames[0];
  if (target === undefined)
    return aliasFailure(
      'invalid-record',
      `The authenticated ${type} AliasMode RRset is empty.`,
    );
  if (target === '.') return success({ kind: 'unavailable', records: aliases });
  return success({
    ignoredServiceRecords: parsed.length - aliases.length,
    kind: 'alias',
    records: aliases,
    transition: transition(owner.value, type, owner.value, type, target, type),
  });
}

function pathKey(name: string, type: DnsRecordType): string {
  return `${type}\u0000${name}`;
}

export class DnssecAliasPath {
  readonly #visited: Set<string>;
  #name: string;
  #transitions = 0;
  #type: DnsRecordType;

  private constructor(name: string, type: DnsRecordType) {
    this.#name = name;
    this.#type = type;
    this.#visited = new Set([pathKey(name, type)]);
  }

  static start(name: string, type: DnsRecordType): Result<DnssecAliasPath, DnssecAliasError> {
    const canonical = canonicalTextName(name);
    return canonical.ok ? success(new DnssecAliasPath(canonical.value, type)) : canonical;
  }

  get position(): DnssecAliasPosition {
    return { name: this.#name, transitions: this.#transitions, type: this.#type };
  }

  follow(next: DnssecAliasTransition): Result<DnssecAliasPosition, DnssecAliasError> {
    const from = canonicalTextName(next.fromName);
    const target = canonicalTextName(next.targetName);
    const aliasOwner = canonicalTextName(next.aliasOwner);
    if (!from.ok || !target.ok)
      return aliasFailure('invalid-name', 'The alias transition contains an invalid DNS name.');
    if (!aliasOwner.ok)
      return aliasFailure(
        'invalid-owner',
        'The alias transition contains an invalid owner name.',
      );
    if (from.value !== this.#name || next.fromType !== this.#type)
      return aliasFailure(
        'wrong-position',
        'The alias transition does not start at the current name and record type.',
      );
    if (next.targetType !== next.fromType)
      return aliasFailure(
        'invalid-record',
        'A CNAME, DNAME, SVCB, or HTTPS alias cannot change the query record type.',
      );
    if (
      (next.aliasType === 'CNAME' && aliasOwner.value !== from.value) ||
      (next.aliasType === 'DNAME' && !isStrictAncestor(aliasOwner.value, from.value)) ||
      ((next.aliasType === 'SVCB' || next.aliasType === 'HTTPS') &&
        (aliasOwner.value !== from.value || next.fromType !== next.aliasType))
    )
      return aliasFailure(
        'invalid-owner',
        'The alias transition owner or record type is not valid for this alias kind.',
      );
    if (this.#transitions >= MAX_DNSSEC_ALIAS_TRANSITIONS)
      return aliasFailure(
        'transition-limit',
        `The DNSSEC run exceeds the ${String(MAX_DNSSEC_ALIAS_TRANSITIONS)}-alias transition limit.`,
      );
    const key = pathKey(target.value, next.targetType);
    if (this.#visited.has(key))
      return aliasFailure('loop', 'The authenticated DNS alias path contains a loop.');
    this.#visited.add(key);
    this.#name = target.value;
    this.#type = next.targetType;
    this.#transitions += 1;
    return success(this.position);
  }
}
