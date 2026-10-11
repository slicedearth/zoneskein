import { parseStrictIpAddress } from '../dns/ip';
import { validateDnsName } from '../dns/names';
import {
  isDeprecatedDsDigestForAuthoring,
  isDeprecatedSha1DnssecAlgorithm,
} from '../dnssec/algorithm-policy';
import { parseTtl } from './parser';
import { verifyBindRecord } from './export-conformance';
import { canonicalSvcbKey, decodeBase64, isValidEchConfigList, svcbKeyNumber } from './svcb';

export type AuthoringRecordType =
  | 'A'
  | 'AAAA'
  | 'CAA'
  | 'CNAME'
  | 'DNSKEY'
  | 'DS'
  | 'HTTPS'
  | 'MX'
  | 'NAPTR'
  | 'NS'
  | 'PTR'
  | 'SOA'
  | 'SRV'
  | 'SSHFP'
  | 'SVCB'
  | 'TLSA'
  | 'TXT'
  | 'URI';

export interface RecordAuthoringDraft {
  readonly fields: Readonly<Record<string, string>>;
  readonly owner: string;
  readonly ttl: string;
  readonly type: AuthoringRecordType;
}

export interface RecordAuthoringDiagnostic {
  readonly code: string;
  readonly field: string;
  readonly message: string;
  readonly severity: 'information' | 'warning' | 'error';
}

export interface AuthoredRecord {
  readonly bind?: string;
  readonly diagnostics: readonly RecordAuthoringDiagnostic[];
  readonly json: string;
  readonly rdata?: string;
  readonly txtChunks?: readonly string[];
  readonly valid: boolean;
}

const encoder = new TextEncoder();

function diagnostic(
  code: string,
  field: string,
  message: string,
  severity: RecordAuthoringDiagnostic['severity'] = 'error',
): RecordAuthoringDiagnostic {
  return { code, field, message, severity };
}

function integer(value: string, minimum: number, maximum: number): number | null {
  if (!/^\d+$/u.test(value)) return null;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed >= minimum && parsed <= maximum ? parsed : null;
}

function zoneName(
  value: string,
  field: string,
  diagnostics: RecordAuthoringDiagnostic[],
  options: {
    readonly allowAt?: boolean;
    readonly allowRoot?: boolean;
    readonly wildcard?: boolean;
  } = {},
): string | null {
  const trimmed = value.trim();
  if (options.allowAt === true && trimmed === '@') return '@';
  if (options.allowRoot === true && trimmed === '.') return '.';
  const wildcard = options.wildcard === true && trimmed.startsWith('*.');
  const candidate = wildcard ? trimmed.slice(2) : trimmed;
  const parsed = validateDnsName(candidate);
  if (!parsed.ok) {
    diagnostics.push(diagnostic('name-invalid', field, parsed.error.message));
    return null;
  }
  return `${wildcard ? '*.' : ''}${parsed.value.absolute}`;
}

function address(
  value: string,
  family: 'ipv4' | 'ipv6',
  field: string,
  diagnostics: RecordAuthoringDiagnostic[],
): string | null {
  const parsed = parseStrictIpAddress(value);
  if (parsed?.kind() !== family) {
    diagnostics.push(
      diagnostic(
        'address-invalid',
        field,
        `Enter one valid ${family === 'ipv4' ? 'IPv4' : 'IPv6'} address.`,
      ),
    );
    return null;
  }
  return parsed.toNormalizedString();
}

function quote(value: string): string {
  let rendered = '';
  for (const character of value) {
    const codePoint = character.codePointAt(0) ?? 0;
    if (character === '\\') rendered += '\\\\';
    else if (character === '"') rendered += '\\"';
    else if (codePoint < 32 || codePoint === 127)
      rendered += `\\${String(codePoint).padStart(3, '0')}`;
    else rendered += character;
  }
  return `"${rendered}"`;
}

export function chunkTxtValue(value: string): readonly string[] {
  const chunks: string[] = [];
  let chunk = '';
  for (const character of value) {
    if (encoder.encode(character).length > 255)
      throw new Error('A TXT character cannot be represented inside one DNS character-string.');
    const next = `${chunk}${character}`;
    if (encoder.encode(next).length <= 255) chunk = next;
    else {
      chunks.push(chunk);
      chunk = character;
    }
  }
  if (chunk !== '' || value === '') chunks.push(chunk);
  return chunks;
}

function hex(
  value: string,
  field: string,
  diagnostics: RecordAuthoringDiagnostic[],
  expectedOctets?: readonly number[],
): string | null {
  const compact = value.replaceAll(/\s+/gu, '').toUpperCase();
  if (!/^(?:[0-9A-F]{2})+$/u.test(compact)) {
    diagnostics.push(
      diagnostic('hex-invalid', field, 'Enter an even-length hexadecimal value.'),
    );
    return null;
  }
  const octets = compact.length / 2;
  if (expectedOctets !== undefined && !expectedOctets.includes(octets)) {
    diagnostics.push(
      diagnostic(
        'hex-length',
        field,
        `This field must contain ${expectedOctets.map(String).join(' or ')} octets, not ${String(octets)}.`,
      ),
    );
    return null;
  }
  return compact;
}

function base64Value(
  value: string,
  field: string,
  diagnostics: RecordAuthoringDiagnostic[],
): string | null {
  const compact = value.replaceAll(/\s+/gu, '');
  if (decodeBase64(compact) === null) {
    diagnostics.push(diagnostic('base64-invalid', field, 'Enter valid Base64 data.'));
    return null;
  }
  return compact;
}

function splitParameterLines(value: string): readonly string[] {
  return value
    .split(/\r?\n/gu)
    .map((line) => line.trim())
    .filter(Boolean);
}

function svcbParameters(
  source: string,
  diagnostics: RecordAuthoringDiagnostic[],
): readonly string[] {
  const lines = splitParameterLines(source);
  const seen = new Set<string>();
  const values: {
    key: string;
    keyNumber: number | null;
    renderedValue?: string;
  }[] = [];
  for (const line of lines) {
    const equals = line.indexOf('=');
    const suppliedKey = (equals < 0 ? line : line.slice(0, equals)).toLowerCase();
    let value = equals < 0 ? undefined : line.slice(equals + 1);
    if (!/^(?:[a-z0-9][a-z0-9-]{0,62}|key(?:0|[1-9]\d{0,4}))$/u.test(suppliedKey)) {
      diagnostics.push(
        diagnostic(
          'svcb-key-invalid',
          'parameters',
          `SvcParam key ${suppliedKey} is malformed.`,
        ),
      );
      continue;
    }
    if (suppliedKey.startsWith('key') && integer(suppliedKey.slice(3), 0, 65_534) === null) {
      diagnostics.push(
        diagnostic(
          'svcb-key-range',
          'parameters',
          `Numeric SvcParam key ${suppliedKey} must be from key0 through key65534.`,
        ),
      );
      continue;
    }
    const keyNumber = svcbKeyNumber(suppliedKey);
    const key = canonicalSvcbKey(suppliedKey);
    const identity = keyNumber === null ? key : `key${String(keyNumber)}`;
    if (seen.has(identity)) {
      diagnostics.push(
        diagnostic('svcb-key-duplicate', 'parameters', `SvcParam ${key} is repeated.`),
      );
      continue;
    }
    seen.add(identity);
    if (keyNumber === null)
      diagnostics.push(
        diagnostic(
          'svcb-key-unregistered',
          'parameters',
          `SvcParam ${key} is not in the bundled registry view; confirm its current registration before publishing.`,
          'warning',
        ),
      );
    if (key === 'no-default-alpn' || key === 'ohttp') {
      if (value !== undefined && value !== '')
        diagnostics.push(
          diagnostic('svcb-empty-required', 'parameters', `${key} must have an empty value.`),
        );
      value = undefined;
    } else if (keyNumber !== null && value === undefined) {
      diagnostics.push(
        diagnostic('svcb-value-required', 'parameters', `${key} requires a value.`),
      );
    }
    if (key === 'port' && value !== undefined && integer(value, 1, 65_535) === null)
      diagnostics.push(
        diagnostic('svcb-port-invalid', 'parameters', 'port must be from 1 through 65535.'),
      );
    if (key === 'alpn' && value !== undefined) {
      const protocols = value.split(',');
      if (protocols.some((item) => item === '') || new Set(protocols).size !== protocols.length)
        diagnostics.push(
          diagnostic(
            'svcb-alpn-invalid',
            'parameters',
            'alpn requires unique, non-empty comma-separated protocol identifiers.',
          ),
        );
    }
    if (key === 'ech' && value !== undefined) {
      if (!isValidEchConfigList(value))
        diagnostics.push(
          diagnostic(
            'svcb-ech-invalid',
            'parameters',
            'ech must contain a structurally valid Base64-encoded ECHConfigList.',
          ),
        );
    }
    if ((key === 'ipv4hint' || key === 'ipv6hint') && value !== undefined) {
      const family = key === 'ipv4hint' ? 'ipv4' : 'ipv6';
      if (value.split(',').some((item) => parseStrictIpAddress(item)?.kind() !== family))
        diagnostics.push(
          diagnostic(
            'svcb-hint-invalid',
            'parameters',
            `${key} must contain comma-separated ${family === 'ipv4' ? 'IPv4' : 'IPv6'} addresses.`,
          ),
        );
    }
    values.push({
      key,
      keyNumber,
      ...(value === undefined ? {} : { renderedValue: value }),
    });
  }
  const mandatory = values.find((entry) => entry.key === 'mandatory');
  if (mandatory?.renderedValue !== undefined) {
    const supplied = mandatory.renderedValue
      .split(',')
      .map((item) => item.toLowerCase())
      .filter(Boolean);
    const identities = supplied.map((key) => {
      const number = svcbKeyNumber(key);
      return number === null ? key : `key${String(number)}`;
    });
    if (
      supplied.length === 0 ||
      new Set(identities).size !== identities.length ||
      identities.includes('key0') ||
      identities.some((key) => !seen.has(key))
    )
      diagnostics.push(
        diagnostic(
          'svcb-mandatory-inconsistent',
          'parameters',
          'mandatory must list only other keys that also appear in this record.',
        ),
      );
    mandatory.renderedValue = supplied
      .map(canonicalSvcbKey)
      .sort((left, right) => {
        const leftNumber = svcbKeyNumber(left);
        const rightNumber = svcbKeyNumber(right);
        if (leftNumber !== null && rightNumber !== null) return leftNumber - rightNumber;
        if (leftNumber !== null) return -1;
        if (rightNumber !== null) return 1;
        return left.localeCompare(right);
      })
      .join(',');
  }
  if (seen.has('key2') && !seen.has('key1'))
    diagnostics.push(
      diagnostic(
        'svcb-no-default-without-alpn',
        'parameters',
        'no-default-alpn requires an alpn parameter in the same record.',
      ),
    );
  return values
    .sort((left, right) => {
      if (left.keyNumber !== null && right.keyNumber !== null)
        return left.keyNumber - right.keyNumber;
      if (left.keyNumber !== null) return -1;
      if (right.keyNumber !== null) return 1;
      return left.key.localeCompare(right.key);
    })
    .map((entry) =>
      entry.renderedValue === undefined
        ? entry.key
        : `${entry.key}=${quote(entry.renderedValue)}`,
    );
}

function field(draft: RecordAuthoringDraft, name: string): string {
  return draft.fields[name]?.trim() ?? '';
}

function requiredInteger(
  draft: RecordAuthoringDraft,
  name: string,
  minimum: number,
  maximum: number,
  diagnostics: RecordAuthoringDiagnostic[],
): number | null {
  const parsed = integer(field(draft, name), minimum, maximum);
  if (parsed === null)
    diagnostics.push(
      diagnostic(
        'integer-invalid',
        name,
        `${name} must be a whole number from ${String(minimum)} through ${String(maximum)}.`,
      ),
    );
  return parsed;
}

function makeRdata(
  draft: RecordAuthoringDraft,
  diagnostics: RecordAuthoringDiagnostic[],
): { readonly rdata: string; readonly txtChunks?: readonly string[] } | null {
  const target = (name = 'target', options: { readonly allowRoot?: boolean } = {}) =>
    zoneName(field(draft, name), name, diagnostics, options);
  if (draft.type === 'A' || draft.type === 'AAAA') {
    const value = address(
      field(draft, 'address'),
      draft.type === 'A' ? 'ipv4' : 'ipv6',
      'address',
      diagnostics,
    );
    return value === null ? null : { rdata: value };
  }
  if (draft.type === 'CNAME' || draft.type === 'NS' || draft.type === 'PTR') {
    const value = target();
    return value === null ? null : { rdata: value };
  }
  if (draft.type === 'TXT') {
    const chunks = chunkTxtValue(draft.fields['value'] ?? '');
    return { rdata: chunks.map(quote).join(' '), txtChunks: chunks };
  }
  if (draft.type === 'MX') {
    const preference = requiredInteger(draft, 'preference', 0, 65_535, diagnostics);
    const value = target();
    return preference === null || value === null
      ? null
      : { rdata: `${String(preference)} ${value}` };
  }
  if (draft.type === 'SRV') {
    const priority = requiredInteger(draft, 'priority', 0, 65_535, diagnostics);
    const weight = requiredInteger(draft, 'weight', 0, 65_535, diagnostics);
    const port = requiredInteger(draft, 'port', 0, 65_535, diagnostics);
    const value = target('target', { allowRoot: true });
    return priority === null || weight === null || port === null || value === null
      ? null
      : { rdata: `${String(priority)} ${String(weight)} ${String(port)} ${value}` };
  }
  if (draft.type === 'CAA') {
    const flags = requiredInteger(draft, 'flags', 0, 255, diagnostics);
    const tag = field(draft, 'tag').toLowerCase();
    if (!/^[a-z0-9]{1,15}$/u.test(tag))
      diagnostics.push(
        diagnostic('caa-tag-invalid', 'tag', 'CAA tag must contain 1–15 letters or digits.'),
      );
    if (!['issue', 'issuewild', 'issuemail', 'iodef'].includes(tag))
      diagnostics.push(
        diagnostic(
          'caa-tag-unknown',
          'tag',
          'This CAA tag is not one of the standard properties bundled with ZoneSkein.',
          (flags ?? 0) & 0x80 ? 'error' : 'warning',
        ),
      );
    return flags === null || !/^[a-z0-9]{1,15}$/u.test(tag)
      ? null
      : { rdata: `${String(flags)} ${tag} ${quote(draft.fields['value'] ?? '')}` };
  }
  if (draft.type === 'SOA') {
    const primary = zoneName(field(draft, 'primary'), 'primary', diagnostics);
    const contact = zoneName(field(draft, 'contact'), 'contact', diagnostics);
    const serial = requiredInteger(draft, 'serial', 0, 0xffff_ffff, diagnostics);
    const timings = ['refresh', 'retry', 'expire', 'minimum'].map((name) => {
      const value = parseTtl(field(draft, name));
      if (value === null)
        diagnostics.push(
          diagnostic('ttl-field-invalid', name, `${name} must be a valid DNS TTL value.`),
        );
      return value;
    });
    if (primary === null || contact === null || serial === null || timings.includes(null))
      return null;
    return {
      rdata: `${primary} ${contact} ${String(serial)} ${timings.map(String).join(' ')}`,
    };
  }
  if (draft.type === 'TLSA') {
    const usage = requiredInteger(draft, 'usage', 0, 3, diagnostics);
    const selector = requiredInteger(draft, 'selector', 0, 1, diagnostics);
    const matching = requiredInteger(draft, 'matchingType', 0, 2, diagnostics);
    const association = hex(
      field(draft, 'associationData'),
      'associationData',
      diagnostics,
      matching === 1 ? [32] : matching === 2 ? [64] : undefined,
    );
    return usage === null || selector === null || matching === null || association === null
      ? null
      : { rdata: `${String(usage)} ${String(selector)} ${String(matching)} ${association}` };
  }
  if (draft.type === 'DS') {
    const keyTag = requiredInteger(draft, 'keyTag', 0, 65_535, diagnostics);
    const algorithm = requiredInteger(draft, 'algorithm', 0, 255, diagnostics);
    const digestType = requiredInteger(draft, 'digestType', 0, 255, diagnostics);
    const expected =
      digestType === 1 ? [20] : digestType === 2 ? [32] : digestType === 4 ? [48] : undefined;
    if (expected === undefined)
      diagnostics.push(
        diagnostic(
          'ds-digest-unsupported',
          'digestType',
          'This builder validates SHA-1, SHA-256, and SHA-384 DS digest lengths only.',
          'warning',
        ),
      );
    if (algorithm !== null && isDeprecatedSha1DnssecAlgorithm(algorithm))
      diagnostics.push(
        diagnostic(
          'ds-algorithm-deprecated',
          'algorithm',
          'RFC 9905 prohibits creating DS records with RSA/SHA-1 algorithms 5 or 7.',
        ),
      );
    if (digestType !== null && isDeprecatedDsDigestForAuthoring(digestType))
      diagnostics.push(
        diagnostic(
          'ds-digest-deprecated',
          'digestType',
          'RFC 9905 prohibits creating new DS records with SHA-1 digest type 1.',
        ),
      );
    const digest = hex(field(draft, 'digest'), 'digest', diagnostics, expected);
    return keyTag === null || algorithm === null || digestType === null || digest === null
      ? null
      : { rdata: `${String(keyTag)} ${String(algorithm)} ${String(digestType)} ${digest}` };
  }
  if (draft.type === 'DNSKEY') {
    const flags = requiredInteger(draft, 'flags', 0, 65_535, diagnostics);
    const protocol = requiredInteger(draft, 'protocol', 0, 255, diagnostics);
    const algorithm = requiredInteger(draft, 'algorithm', 0, 255, diagnostics);
    const publicKey = base64Value(field(draft, 'publicKey'), 'publicKey', diagnostics);
    if (protocol !== null && protocol !== 3)
      diagnostics.push(
        diagnostic('dnskey-protocol-invalid', 'protocol', 'DNSKEY protocol must be 3.'),
      );
    if (algorithm !== null && isDeprecatedSha1DnssecAlgorithm(algorithm))
      diagnostics.push(
        diagnostic(
          'dnskey-algorithm-deprecated',
          'algorithm',
          'RFC 9905 prohibits creating DNSKEY and RRSIG records with RSA/SHA-1 algorithms 5 or 7.',
        ),
      );
    return flags === null || protocol !== 3 || algorithm === null || publicKey === null
      ? null
      : { rdata: `${String(flags)} 3 ${String(algorithm)} ${publicKey}` };
  }
  if (draft.type === 'SSHFP') {
    const algorithm = requiredInteger(draft, 'algorithm', 1, 6, diagnostics);
    const fingerprintType = requiredInteger(draft, 'fingerprintType', 1, 2, diagnostics);
    const fingerprint = hex(
      field(draft, 'fingerprint'),
      'fingerprint',
      diagnostics,
      fingerprintType === 1 ? [20] : fingerprintType === 2 ? [32] : undefined,
    );
    return algorithm === null || fingerprintType === null || fingerprint === null
      ? null
      : { rdata: `${String(algorithm)} ${String(fingerprintType)} ${fingerprint}` };
  }
  if (draft.type === 'URI') {
    const priority = requiredInteger(draft, 'priority', 0, 65_535, diagnostics);
    const weight = requiredInteger(draft, 'weight', 0, 65_535, diagnostics);
    const uri = draft.fields['target']?.trim() ?? '';
    try {
      const parsed = new URL(uri);
      if (parsed.protocol === '') throw new Error('scheme');
    } catch {
      diagnostics.push(diagnostic('uri-invalid', 'target', 'Enter an absolute URI.'));
    }
    return priority === null ||
      weight === null ||
      diagnostics.some((item) => item.field === 'target' && item.severity === 'error')
      ? null
      : { rdata: `${String(priority)} ${String(weight)} ${quote(uri)}` };
  }
  if (draft.type === 'NAPTR') {
    const order = requiredInteger(draft, 'order', 0, 65_535, diagnostics);
    const preference = requiredInteger(draft, 'preference', 0, 65_535, diagnostics);
    const replacement = zoneName(field(draft, 'replacement'), 'replacement', diagnostics, {
      allowRoot: true,
    });
    return order === null || preference === null || replacement === null
      ? null
      : {
          rdata: `${String(order)} ${String(preference)} ${quote(draft.fields['flags'] ?? '')} ${quote(draft.fields['service'] ?? '')} ${quote(draft.fields['regexp'] ?? '')} ${replacement}`,
        };
  }
  const priority = requiredInteger(draft, 'priority', 0, 65_535, diagnostics);
  const value = target('target', { allowRoot: true });
  const parameters = svcbParameters(draft.fields['parameters'] ?? '', diagnostics);
  if (priority === 0 && parameters.length > 0)
    diagnostics.push(
      diagnostic(
        'svcb-alias-parameters',
        'parameters',
        'AliasMode priority 0 records must not contain SvcParams.',
      ),
    );
  if (priority === 0 && value === '.')
    diagnostics.push(
      diagnostic(
        'svcb-alias-root-target',
        'target',
        'AliasMode priority 0 requires a non-root target name.',
      ),
    );
  return priority === null || value === null
    ? null
    : {
        rdata: `${String(priority)} ${value}${parameters.length === 0 ? '' : ` ${parameters.join(' ')}`}`,
      };
}

export function authorRecord(draft: RecordAuthoringDraft): AuthoredRecord {
  const diagnostics: RecordAuthoringDiagnostic[] = [];
  const owner = zoneName(draft.owner, 'owner', diagnostics, { allowAt: true, wildcard: true });
  const ttl = parseTtl(draft.ttl.trim());
  if (ttl === null)
    diagnostics.push(diagnostic('ttl-invalid', 'ttl', 'TTL must be a valid DNS TTL value.'));
  const result = makeRdata(draft, diagnostics);
  let valid =
    owner !== null &&
    ttl !== null &&
    result !== null &&
    !diagnostics.some((item) => item.severity === 'error');
  let bind =
    valid && result !== null && owner !== null
      ? `${owner} ${String(ttl)} IN ${draft.type} ${result.rdata}`
      : undefined;
  if (bind !== undefined && owner !== null && ttl !== null) {
    const failure = verifyBindRecord(bind, {
      owner,
      ttl,
      type: draft.type,
      ...(draft.type === 'TXT'
        ? { txtValue: draft.fields['value'] ?? '', txtChunks: result?.txtChunks ?? [] }
        : {}),
    });
    if (failure !== null) {
      diagnostics.push(diagnostic('export-conformance', 'record', failure));
      valid = false;
      bind = undefined;
    }
  }
  return {
    ...(bind === undefined ? {} : { bind }),
    diagnostics,
    json: JSON.stringify(
      {
        class: 'IN',
        ...(owner === null ? {} : { owner }),
        ...(result === null ? {} : { rdata: result.rdata }),
        ...(ttl === null ? {} : { ttl }),
        type: draft.type,
      },
      null,
      2,
    ),
    ...(result === null ? {} : { rdata: result.rdata }),
    ...(result?.txtChunks === undefined ? {} : { txtChunks: result.txtChunks }),
    valid,
  };
}
