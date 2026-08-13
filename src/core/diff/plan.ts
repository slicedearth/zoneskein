import { lintZoneSnippet } from '../zone/lint';
import { ZONE_ANALYSIS_LIMITS } from '../zone/parser';
import type { ZoneDocument, ZoneRecord } from '../zone/types';
import type {
  ChangeImpact,
  ChangePreflightFinding,
  ChangeRisk,
  DnsChange,
  DnsChangePlan,
  DiffReport,
  RolloutPhase,
} from './types';

export interface ChangePlanOptions {
  readonly incompleteTypes?: readonly string[];
  readonly now?: Date;
  readonly plannedAt?: Date;
}

const RISK_ORDER: Readonly<Record<ChangeRisk, number>> = {
  information: 0,
  low: 1,
  moderate: 2,
  high: 3,
  critical: 4,
};

class FindingCollector {
  readonly values: ChangePreflightFinding[] = [];
  incompleteReason: string | undefined;
  readonly #seen = new Set<string>();

  add(value: ChangePreflightFinding): boolean {
    const identity = JSON.stringify([value.code, value.message]);
    if (this.#seen.has(identity)) return true;
    if (this.values.length >= ZONE_ANALYSIS_LIMITS.findings) {
      this.incompleteReason = `Change planning exceeded the ${String(ZONE_ANALYSIS_LIMITS.findings)}-finding safety limit. No partial plan was retained.`;
      return false;
    }
    this.#seen.add(identity);
    this.values.push(value);
    return true;
  }
}

function incompletePlan(reasons: readonly string[]): DnsChangePlan {
  return {
    findings: [],
    impacts: [],
    incompleteReasons: [...new Set(reasons)],
    phases: [],
    risk: 'high',
    status: 'incomplete',
    timing: {},
  };
}

function greatestRisk(values: readonly ChangeRisk[]): ChangeRisk {
  return values.reduce<ChangeRisk>(
    (highest, value) => (RISK_ORDER[value] > RISK_ORDER[highest] ? value : highest),
    'information',
  );
}

function text(record: ZoneRecord | undefined): string {
  return (
    record?.rdata
      .map((token) => token.value)
      .join(' ')
      .trim() ?? ''
  );
}

function policyKind(record: ZoneRecord | undefined): string | null {
  if (record?.type !== 'TXT') return null;
  const value = text(record).toLowerCase();
  if (value.startsWith('v=spf1')) return 'SPF';
  if (value.startsWith('v=dmarc1')) return 'DMARC';
  if (value.startsWith('v=dkim1') || /(?:^|;)\s*p=/u.test(value)) return 'DKIM';
  if (value.startsWith('v=stsv1')) return 'MTA-STS';
  if (value.startsWith('v=tlsrptv1')) return 'TLS reporting';
  if (value.startsWith('v=bimi1')) return 'BIMI';
  return null;
}

function changeRisk(change: DnsChange): ChangeRisk {
  if (change.category === 'formatting-only') return 'information';
  if (change.category === 'ttl-only') return 'low';
  if (change.type === 'DS' || change.type === 'DNSKEY' || change.type === 'NS')
    return 'critical';
  if (
    change.type === 'MX' ||
    change.type === 'CNAME' ||
    change.type === 'TLSA' ||
    change.type === 'SOA'
  )
    return 'high';
  if (policyKind(change.after ?? change.before) !== null) return 'high';
  if (change.category === 'removed') return 'high';
  if (
    change.type === 'CAA' ||
    change.type === 'SRV' ||
    change.type === 'HTTPS' ||
    change.type === 'SVCB'
  )
    return 'moderate';
  return change.category === 'added' ? 'low' : 'moderate';
}

function impact(change: DnsChange, changeIndex: number): ChangeImpact {
  const risk = changeRisk(change);
  const reasons: string[] = [change.explanation];
  const policy = policyKind(change.after ?? change.before);
  if (change.type === 'NS')
    reasons.push(
      'Nameserver changes can affect the delegation and the authoritative zone independently.',
    );
  if (change.type === 'DS' || change.type === 'DNSKEY')
    reasons.push(
      'DNSSEC transitions can make the entire child zone bogus if parent and child states do not overlap safely.',
    );
  if (change.type === 'MX')
    reasons.push(
      'New deliveries may move immediately while old MX answers and connection routes remain cached.',
    );
  if (change.type === 'CNAME')
    reasons.push(
      'An unavailable target or incompatible coexisting data can break the alias owner.',
    );
  if (change.type === 'TLSA')
    reasons.push(
      'A stale or incorrect TLSA association can cause DANE-aware clients to reject the service.',
    );
  if (policy !== null)
    reasons.push(
      `${policy} policy changes can alter authentication, reporting, or receiver behaviour.`,
    );
  if (change.category === 'removed')
    reasons.push('The proposed snapshot removes a previously observed value.');
  const rollback =
    change.before === undefined
      ? `Remove the added ${change.type} value if verification fails, accounting for its published TTL.`
      : change.after === undefined
        ? `Restore the prior ${change.type} value exactly and retain the affected service until cached negative or old answers expire.`
        : `Restore the prior ${change.type} value and TTL from the before snapshot; keep both old and new dependencies available during the cache overlap.`;
  return { changeIndex, reasons, risk, rollback };
}

function absoluteTarget(value: string, origin: string | undefined): string | null {
  if (value === '' || value === '.') return null;
  if (value === '@') return origin ?? null;
  if (value.endsWith('.')) return value.toLowerCase();
  return origin === undefined ? null : `${value.toLowerCase()}.${origin}`.replace('..', '.');
}

function target(record: ZoneRecord, origin: string | undefined): string | null {
  const values = record.rdata.map((token) => token.value);
  if (record.type === 'CNAME' || record.type === 'NS')
    return absoluteTarget(values[0] ?? '', origin);
  if (record.type === 'MX') return absoluteTarget(values[1] ?? '', origin);
  if (record.type === 'SRV') return absoluteTarget(values[3] ?? '', origin);
  if (record.type === 'HTTPS' || record.type === 'SVCB')
    return absoluteTarget(values[1] ?? '', origin);
  return null;
}

function serial(document: ZoneDocument): number | null {
  const value = document.records.find((record) => record.type === 'SOA')?.rdata[2]?.value;
  if (value === undefined || !/^\d+$/u.test(value)) return null;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed >= 0 && parsed <= 0xffff_ffff ? parsed : null;
}

function serialAdvances(before: number, after: number): boolean {
  const difference = (after - before) >>> 0;
  return difference > 0 && difference < 0x8000_0000;
}

function preflight(
  before: ZoneDocument,
  after: ZoneDocument,
  findings: FindingCollector,
): string | null {
  const linted = lintZoneSnippet(
    after.source,
    after.origin === undefined ? {} : { origin: after.origin },
  );
  if (linted.incomplete !== undefined)
    return `Proposed snapshot linting is incomplete: ${linted.incomplete.message}`;
  for (const item of linted.diagnostics) {
    if (item.severity === 'information') continue;
    if (
      !findings.add({
        code: `zone-${item.rule}`,
        message: `Proposed line ${String(item.line)}:${String(item.column)} — ${item.message}`,
        risk: item.severity === 'error' ? 'high' : 'moderate',
      })
    )
      return findings.incompleteReason ?? 'Change planning exceeded its finding safety limit.';
  }
  const owners = new Set(after.records.map((record) => record.owner.toLowerCase()));
  for (const record of after.records) {
    const dependency = target(record, after.origin);
    if (
      dependency !== null &&
      after.origin !== undefined &&
      (dependency === after.origin || dependency.endsWith(`.${after.origin}`)) &&
      !owners.has(dependency)
    )
      if (
        !findings.add({
          code: 'internal-target-not-in-snapshot',
          message: `${record.owner} ${record.type} points to in-zone target ${dependency}, but the proposed snippet contains no record at that owner. Confirm it exists outside this partial snapshot before publishing.`,
          risk: record.type === 'CNAME' || record.type === 'MX' ? 'high' : 'moderate',
        })
      )
        return (
          findings.incompleteReason ?? 'Change planning exceeded its finding safety limit.'
        );
  }
  const beforeSerial = serial(before);
  const afterSerial = serial(after);
  if (
    beforeSerial !== null &&
    afterSerial !== null &&
    !serialAdvances(beforeSerial, afterSerial)
  )
    if (
      !findings.add({
        code: 'soa-serial-not-increased',
        message: `The proposed SOA serial ${String(afterSerial)} does not advance from ${String(beforeSerial)} under DNS serial-number arithmetic. Authoritative secondaries may not load the change.`,
        risk: 'high',
      })
    )
      return findings.incompleteReason ?? 'Change planning exceeded its finding safety limit.';
  return null;
}

function maximumPreviousTtl(report: DiffReport): number | undefined {
  let maximum: number | undefined;
  for (const change of report.changes) {
    const ttl = change.before?.ttl;
    if (changeRisk(change) === 'information' || ttl === undefined) continue;
    maximum = maximum === undefined ? ttl : Math.max(maximum, ttl);
  }
  return maximum;
}

function phases(report: DiffReport, previousTtl: number | undefined): readonly RolloutPhase[] {
  const hasRemovals = report.changes.some((change) => change.category === 'removed');
  const hasDnssec = report.changes.some(
    (change) => change.type === 'DS' || change.type === 'DNSKEY',
  );
  const hasNameservers = report.changes.some((change) => change.type === 'NS');
  return [
    {
      actions: [
        'Resolve every proposed-zone parser or lint error and confirm all in-zone targets exist.',
        ...(hasDnssec
          ? [
              'Choose a documented DNSSEC rollover method with an overlap in which the parent DS and child DNSKEY sets both validate.',
            ]
          : []),
        ...(hasNameservers
          ? [
              'Add and verify the new authoritative service before changing the parent delegation.',
            ]
          : []),
        previousTtl === undefined
          ? 'Recover the currently published TTLs before setting a change window; this snapshot does not establish them completely.'
          : `Lower affected TTLs in a separate publication if faster rollback is required; the largest observed prior TTL is ${String(previousTtl)} seconds.`,
      ],
      id: 'prepare',
      title: 'Prepare dependencies and rollback material',
    },
    {
      actions: [
        previousTtl === undefined
          ? 'Wait for the actual previous TTL horizon after any preparatory TTL reduction.'
          : `After publishing a lower TTL, wait at least the previous ${String(previousTtl)}-second TTL horizon before the semantic change.`,
        'Keep old targets healthy during this interval; lowering a TTL does not evict already cached answers.',
      ],
      id: 'wait',
      title: 'Wait out the previous cache horizon',
    },
    {
      actions: [
        'Publish additions and replacement targets before destructive removals wherever the protocol permits overlap.',
        ...(hasRemovals
          ? ['Remove old values only after the replacements are observable and functional.']
          : []),
        'Record the actual publication time and authoritative serial rather than assuming the planned time.',
      ],
      id: 'publish',
      title: 'Publish in dependency order',
    },
    {
      actions: [
        'Verify the authoritative source and then compare several recursive resolvers; treat disagreement as an observation, not a global percentage.',
        'Test the affected application path, not only the presence of its DNS record.',
        ...(hasDnssec
          ? ['Re-run independent DNSSEC validation before removing old key material.']
          : []),
      ],
      id: 'verify',
      title: 'Verify DNS and service behaviour',
    },
    {
      actions: [
        'Keep the prior values and configuration ready for the full old and new TTL overlap.',
        'If rollback is required, restore the prior values while retaining the failed new dependencies until their cached answers age out.',
      ],
      id: 'observe',
      title: 'Observe through the rollback window',
    },
    {
      actions: [
        'Restore normal TTLs only after the change is stable and the rollback decision window has closed.',
        'Save the verified final snapshot and note any intentional differences from the proposal.',
      ],
      id: 'restore',
      title: 'Restore steady-state TTLs',
    },
  ];
}

export function planDnsChanges(
  before: ZoneDocument,
  after: ZoneDocument,
  report: DiffReport,
  options: ChangePlanOptions = {},
): DnsChangePlan {
  if (report.status === 'incomplete') return incompletePlan(report.incompleteReasons);
  const inputReasons = [
    before.incomplete === undefined
      ? null
      : `Earlier snapshot is incomplete: ${before.incomplete.message}`,
    after.incomplete === undefined
      ? null
      : `Later snapshot is incomplete: ${after.incomplete.message}`,
  ].flatMap((reason) => (reason === null ? [] : [reason]));
  if (inputReasons.length > 0) return incompletePlan(inputReasons);
  if (report.changes.length > ZONE_ANALYSIS_LIMITS.changes)
    return incompletePlan([
      `Change planning received more than ${String(ZONE_ANALYSIS_LIMITS.changes)} classified changes.`,
    ]);

  const now = options.now ?? new Date();
  const plannedAt = options.plannedAt;
  const findings = new FindingCollector();
  if (options.incompleteTypes !== undefined && options.incompleteTypes.length > 0)
    if (
      !findings.add({
        code: 'current-observation-incomplete',
        message: `Current ${[...new Set(options.incompleteTypes)].join(', ')} data could not be observed. Changes for those record types were omitted instead of being guessed.`,
        risk: 'high',
      })
    )
      return incompletePlan([
        findings.incompleteReason ?? 'Change planning exceeded its finding safety limit.',
      ]);
  const preflightIncomplete = preflight(before, after, findings);
  if (preflightIncomplete !== null) return incompletePlan([preflightIncomplete]);
  const impacts = report.changes.map(impact);
  const previousTtlSeconds = maximumPreviousTtl(report);
  if (
    plannedAt !== undefined &&
    previousTtlSeconds !== undefined &&
    plannedAt.getTime() < now.getTime() + previousTtlSeconds * 1000
  )
    if (
      !findings.add({
        code: 'change-window-too-soon',
        message: `The planned change is sooner than the largest observed prior TTL horizon of ${String(previousTtlSeconds)} seconds. A TTL lowered now cannot make already cached answers expire by that time.`,
        risk: 'high',
      })
    )
      return incompletePlan([
        findings.incompleteReason ?? 'Change planning exceeded its finding safety limit.',
      ]);
  if (
    report.changes.some(
      (change) => changeRisk(change) === 'high' || changeRisk(change) === 'critical',
    ) &&
    previousTtlSeconds === undefined
  )
    if (
      !findings.add({
        code: 'previous-ttl-unknown',
        message:
          'At least one high-impact change lacks a prior TTL in the supplied snapshot. Recover that TTL before assigning a rollback horizon.',
        risk: 'high',
      })
    )
      return incompletePlan([
        findings.incompleteReason ?? 'Change planning exceeded its finding safety limit.',
      ]);
  const preparationDeadline =
    plannedAt === undefined || previousTtlSeconds === undefined
      ? undefined
      : new Date(plannedAt.getTime() - previousTtlSeconds * 1000).toISOString();
  const safeChangeAtIfLoweredNow =
    previousTtlSeconds === undefined
      ? undefined
      : new Date(now.getTime() + previousTtlSeconds * 1000).toISOString();
  let rollbackSeconds = previousTtlSeconds ?? 0;
  for (const change of report.changes)
    if (change.after?.ttl !== undefined)
      rollbackSeconds = Math.max(rollbackSeconds, change.after.ttl);
  const rollbackBase = plannedAt ?? now;
  const rollbackCacheHorizon =
    rollbackSeconds === 0
      ? undefined
      : new Date(rollbackBase.getTime() + rollbackSeconds * 1000).toISOString();
  return {
    findings: findings.values,
    impacts,
    incompleteReasons: [],
    phases: phases(report, previousTtlSeconds),
    risk: greatestRisk([
      ...impacts.map((item) => item.risk),
      ...findings.values.map((item) => item.risk),
    ]),
    status: 'complete',
    timing: {
      ...(plannedAt === undefined ? {} : { plannedAt: plannedAt.toISOString() }),
      ...(previousTtlSeconds === undefined ? {} : { previousTtlSeconds }),
      ...(preparationDeadline === undefined ? {} : { preparationDeadline }),
      ...(rollbackCacheHorizon === undefined ? {} : { rollbackCacheHorizon }),
      ...(safeChangeAtIfLoweredNow === undefined ? {} : { safeChangeAtIfLoweredNow }),
    },
  };
}
