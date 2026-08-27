import { parseDkimMessage } from '../dkim/message-verifier';

export interface ArcInstance {
  readonly authenticationResults: boolean;
  readonly cv: string | null;
  readonly domain: string | null;
  readonly instance: number;
  readonly messageSignature: boolean;
  readonly seal: boolean;
  readonly selector: string | null;
}

export interface ArcChainReport {
  readonly diagnostics: readonly string[];
  readonly instances: readonly ArcInstance[];
  readonly state: 'structurally-valid' | 'invalid' | 'none';
}

function tags(value: string): {
  readonly duplicates: readonly string[];
  readonly values: Readonly<Record<string, string>>;
} {
  const output: Record<string, string> = {};
  const duplicates = new Set<string>();
  for (const segment of value.replaceAll(/\r\n[ \t]+/gu, ' ').split(';')) {
    const equals = segment.indexOf('=');
    if (equals < 1) continue;
    const name = segment.slice(0, equals).trim().toLowerCase();
    if (Object.hasOwn(output, name)) duplicates.add(name);
    else output[name] = segment.slice(equals + 1).trim();
  }
  return { duplicates: [...duplicates], values: output };
}

export function inspectArcChain(source: string | Uint8Array): ArcChainReport {
  const message = parseDkimMessage(source);
  const grouped = new Map<
    number,
    {
      aar: boolean;
      ams: Readonly<Record<string, string>> | null;
      seal: Readonly<Record<string, string>> | null;
    }
  >();
  const diagnostics: string[] = [];
  for (const header of message.headers) {
    const name = header.name.toLowerCase();
    if (!['arc-seal', 'arc-message-signature', 'arc-authentication-results'].includes(name))
      continue;
    const parsedTags = tags(header.value);
    const parsed = parsedTags.values;
    for (const duplicate of parsedTags.duplicates)
      diagnostics.push(`${header.name} repeats the ${duplicate} tag.`);
    const instanceText = parsed['i'] ?? /^\s*i\s*=\s*(\d+)/iu.exec(header.value)?.[1];
    if (
      instanceText === undefined ||
      !/^[1-9]\d{0,2}$/u.test(instanceText) ||
      Number(instanceText) > 50
    ) {
      diagnostics.push(`${header.name} has an invalid or missing instance number.`);
      continue;
    }
    const instance = Number(instanceText);
    const current = grouped.get(instance) ?? { aar: false, ams: null, seal: null };
    if (name === 'arc-authentication-results') {
      if (current.aar)
        diagnostics.push(
          `ARC instance ${String(instance)} repeats ARC-Authentication-Results.`,
        );
      current.aar = true;
    } else if (name === 'arc-message-signature') {
      if (current.ams !== null)
        diagnostics.push(`ARC instance ${String(instance)} repeats ARC-Message-Signature.`);
      current.ams = parsed;
    } else {
      if (current.seal !== null)
        diagnostics.push(`ARC instance ${String(instance)} repeats ARC-Seal.`);
      current.seal = parsed;
    }
    grouped.set(instance, current);
  }
  if (grouped.size === 0) return { diagnostics: [], instances: [], state: 'none' };
  const ordered = [...grouped.entries()].sort(([left], [right]) => left - right);
  const instances: ArcInstance[] = [];
  for (const [index, [instance, value]] of ordered.entries()) {
    if (instance !== index + 1)
      diagnostics.push(`ARC instances are not contiguous at ${String(index + 1)}.`);
    if (!value.aar || value.ams === null || value.seal === null)
      diagnostics.push(
        `ARC instance ${String(instance)} does not contain exactly one complete header set.`,
      );
    const cv = value.seal?.['cv']?.toLowerCase() ?? null;
    if (instance === 1 ? cv !== 'none' : cv !== 'pass' && cv !== 'fail')
      diagnostics.push(
        `ARC instance ${String(instance)} has an invalid cv value for its position.`,
      );
    for (const [label, signature] of [
      ['ARC-Message-Signature', value.ams],
      ['ARC-Seal', value.seal],
    ] as const) {
      if (signature === null) continue;
      for (const required of ['a', 'b', 'd', 's'])
        if ((signature[required] ?? '') === '')
          diagnostics.push(`${label} instance ${String(instance)} is missing ${required}.`);
    }
    instances.push({
      authenticationResults: value.aar,
      cv,
      domain: value.seal?.['d'] ?? null,
      instance,
      messageSignature: value.ams !== null,
      seal: value.seal !== null,
      selector: value.seal?.['s'] ?? null,
    });
  }
  return {
    diagnostics,
    instances,
    state: diagnostics.length === 0 ? 'structurally-valid' : 'invalid',
  };
}
