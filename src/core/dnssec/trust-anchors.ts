import anchorData from './root-anchors.json';

import { dnskeyDigest } from './digest';
import type { DnskeyInfo } from './types';
import { DnssecWorkBudget } from './work-budget';

export interface RootTrustAnchor {
  readonly algorithm: number;
  readonly digest: Uint8Array;
  readonly digestHex: string;
  readonly digestType: 1 | 2 | 4;
  readonly id: string;
  readonly keyTag: number;
  readonly validFrom: string;
  readonly validUntil?: string;
}

export interface RootTrustAnchorMatch {
  readonly anchor: RootTrustAnchor;
  readonly key: DnskeyInfo;
}

export type RootTrustAnchorMaintenanceState =
  'current' | 'review-due' | 'overdue' | 'certificate-review-due';

export interface RootTrustAnchorMaintenance {
  readonly checkedAgeDays: number;
  readonly checkedAt: string;
  readonly nextReviewAt: string;
  readonly pinnedCertificateExpiresAt: string;
  readonly state: RootTrustAnchorMaintenanceState;
}

const ANCHOR_REVIEW_INTERVAL_DAYS = 45;
const ANCHOR_OVERDUE_DAYS = 90;
const CERTIFICATE_REVIEW_DAYS = 180;
const DAY_MILLISECONDS = 86_400_000;
export const ROOT_ANCHOR_CERTIFICATE_EXPIRES_AT = '2029-12-18T23:59:59.999Z';

function bytes(value: string): Uint8Array {
  if (!/^(?:[0-9a-f]{2})+$/iu.test(value))
    throw new Error('Malformed root trust-anchor digest.');
  return Uint8Array.from(value.match(/.{2}/gu) ?? [], (octet) => Number.parseInt(octet, 16));
}

function equal(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1)
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  return difference === 0;
}

export const ROOT_TRUST_ANCHOR_SOURCE = {
  retrievedAt: anchorData.retrievedAt,
  source: anchorData.source,
  sourceUpdated: anchorData.sourceUpdated,
} as const;

export function assessRootTrustAnchorMaintenance(now = Date.now()): RootTrustAnchorMaintenance {
  const checkedAt = Date.parse(`${ROOT_TRUST_ANCHOR_SOURCE.retrievedAt}T23:59:59.999Z`);
  const certificateExpiresAt = Date.parse(ROOT_ANCHOR_CERTIFICATE_EXPIRES_AT);
  if (!Number.isFinite(checkedAt) || !Number.isFinite(certificateExpiresAt))
    throw new Error('The bundled root trust-anchor maintenance dates are malformed.');
  const checkedAgeDays = Math.max(0, Math.floor((now - checkedAt) / DAY_MILLISECONDS));
  const certificateDaysRemaining = Math.floor((certificateExpiresAt - now) / DAY_MILLISECONDS);
  const state: RootTrustAnchorMaintenanceState =
    certificateDaysRemaining <= CERTIFICATE_REVIEW_DAYS
      ? 'certificate-review-due'
      : checkedAgeDays > ANCHOR_OVERDUE_DAYS
        ? 'overdue'
        : checkedAgeDays > ANCHOR_REVIEW_INTERVAL_DAYS
          ? 'review-due'
          : 'current';
  return {
    checkedAgeDays,
    checkedAt: new Date(checkedAt).toISOString(),
    nextReviewAt: new Date(
      checkedAt + ANCHOR_REVIEW_INTERVAL_DAYS * DAY_MILLISECONDS,
    ).toISOString(),
    pinnedCertificateExpiresAt: ROOT_ANCHOR_CERTIFICATE_EXPIRES_AT,
    state,
  };
}

export const ROOT_TRUST_ANCHORS: readonly RootTrustAnchor[] = anchorData.anchors.map(
  (anchor) => {
    if (anchor.digestType !== 1 && anchor.digestType !== 2 && anchor.digestType !== 4)
      throw new Error('The bundled root anchor uses an unsupported DS digest type.');
    return {
      algorithm: anchor.algorithm,
      digest: bytes(anchor.digest),
      digestHex: anchor.digest,
      digestType: anchor.digestType,
      id: anchor.id,
      keyTag: anchor.keyTag,
      validFrom: anchor.validFrom,
      ...('validUntil' in anchor && typeof anchor.validUntil === 'string'
        ? { validUntil: anchor.validUntil }
        : {}),
    };
  },
);

export async function matchRootTrustAnchors(
  keys: readonly DnskeyInfo[],
  now = Date.now(),
  budget = new DnssecWorkBudget(),
): Promise<readonly RootTrustAnchorMatch[]> {
  const matches: RootTrustAnchorMatch[] = [];
  for (const anchor of ROOT_TRUST_ANCHORS) {
    if (Date.parse(anchor.validFrom) > now) continue;
    if (anchor.validUntil !== undefined && Date.parse(anchor.validUntil) <= now) continue;
    for (const key of keys) {
      if (key.keyTag !== anchor.keyTag || key.algorithm !== anchor.algorithm) continue;
      if (!budget.consume('digestOperations')) return matches;
      const digest = await dnskeyDigest('.', key.record.rawRdata, anchor.digestType);
      if (budget.cancelled) return matches;
      if (equal(digest, anchor.digest)) matches.push({ anchor, key });
    }
  }
  return matches;
}
