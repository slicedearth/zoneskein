import { SaxesParser } from 'saxes';

export interface BimiRecord {
  readonly authorityUrl: string | null;
  readonly diagnostics: readonly string[];
  readonly logoUrl: string | null;
  readonly valid: boolean;
}

export interface BimiSvgReport {
  readonly diagnostics: readonly string[];
  readonly elements: number;
  readonly title: string | null;
  readonly valid: boolean;
  readonly viewBox: string | null;
}

function httpsUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && url.username === '' && url.password === '';
  } catch {
    return false;
  }
}

export function parseBimiRecord(value: string): BimiRecord {
  const diagnostics: string[] = [];
  if (value.length === 0 || value.length > 65_536)
    return {
      authorityUrl: null,
      diagnostics: ['The BIMI record is empty or exceeds 65,536 characters.'],
      logoUrl: null,
      valid: false,
    };
  const tags = new Map<string, string>();
  let first = '';
  for (const segment of value
    .split(';')
    .map((part) => part.trim())
    .filter(Boolean)) {
    const equals = segment.indexOf('=');
    if (equals < 1) {
      diagnostics.push(`Malformed segment: ${segment}.`);
      continue;
    }
    const name = segment.slice(0, equals).toLowerCase();
    first ||= name;
    if (tags.has(name)) diagnostics.push(`Tag ${name} is repeated.`);
    else tags.set(name, segment.slice(equals + 1).trim());
  }
  if (first !== 'v' || tags.get('v') !== 'BIMI1')
    diagnostics.push('v=BIMI1 must be the first tag.');
  const logo = tags.get('l') ?? '';
  const authority = tags.get('a') ?? '';
  if (logo !== '' && !httpsUrl(logo)) diagnostics.push('l must be empty or an HTTPS URL.');
  if (authority !== '' && !httpsUrl(authority))
    diagnostics.push('a must be empty or an HTTPS URL.');
  for (const tag of tags.keys())
    if (!['v', 'l', 'a'].includes(tag)) diagnostics.push(`Unknown BIMI tag ${tag}.`);
  return {
    authorityUrl: authority === '' ? null : authority,
    diagnostics,
    logoUrl: logo === '' ? null : logo,
    valid: diagnostics.length === 0,
  };
}

export function inspectBimiSvg(source: string): BimiSvgReport {
  const diagnostics: string[] = [];
  if (source.length === 0 || source.length > 2 * 1024 * 1024)
    return {
      diagnostics: ['The SVG is empty or exceeds the 2 MiB safety limit.'],
      elements: 0,
      title: null,
      valid: false,
      viewBox: null,
    };
  if (/<!DOCTYPE/iu.test(source))
    return {
      diagnostics: ['SVG document type declarations are not accepted.'],
      elements: 0,
      title: null,
      valid: false,
      viewBox: null,
    };
  const forbidden = new Set([
    'script',
    'foreignobject',
    'image',
    'audio',
    'video',
    'iframe',
    'link',
    'object',
    'embed',
    'style',
    'animate',
    'animatemotion',
    'animatetransform',
    'set',
  ]);
  const parser = new SaxesParser({ xmlns: false });
  let elements = 0;
  let depth = 0;
  const documentState: {
    root: string;
    title: string | null;
    viewBox: string | null;
  } = { root: '', title: null, viewBox: null };
  let capturingTitle = false;
  let titleText = '';
  parser.on('doctype', () => {
    throw new Error('SVG document type declarations are not accepted.');
  });
  parser.on('opentag', (tag) => {
    depth += 1;
    elements += 1;
    if (depth > 64 || elements > 10_000)
      throw new Error('The SVG exceeds local structure limits.');
    const name = tag.name.toLowerCase();
    if (documentState.root === '') documentState.root = name;
    if (forbidden.has(name))
      diagnostics.push(`Element <${name}> is outside the safe static logo profile.`);
    const attributes = tag.attributes;
    for (const [attributeName, raw] of Object.entries(attributes)) {
      const attributeValue = typeof raw === 'string' ? raw : String(raw);
      const lowerName = attributeName.toLowerCase();
      if (lowerName.startsWith('on'))
        diagnostics.push(`Event attribute ${attributeName} is not allowed.`);
      if (
        (lowerName === 'href' || lowerName.endsWith(':href')) &&
        !attributeValue.startsWith('#')
      )
        diagnostics.push(`External reference ${attributeName} is not allowed.`);
      if (lowerName === 'style' && /url\s*\(/iu.test(attributeValue))
        diagnostics.push('CSS url() references are not allowed.');
    }
    if (depth === 1) {
      documentState.viewBox =
        typeof attributes['viewBox'] === 'string'
          ? attributes['viewBox']
          : typeof attributes['viewbox'] === 'string'
            ? attributes['viewbox']
            : null;
      const profile =
        typeof attributes['baseProfile'] === 'string'
          ? attributes['baseProfile']
          : typeof attributes['baseprofile'] === 'string'
            ? attributes['baseprofile']
            : '';
      if (profile !== 'tiny-ps')
        diagnostics.push('The root SVG should declare baseProfile="tiny-ps".');
    }
    if (name === 'title') {
      capturingTitle = true;
      titleText = '';
    }
  });
  parser.on('text', (value) => {
    if (capturingTitle) titleText += value;
  });
  parser.on('closetag', (tag) => {
    if (tag.name.toLowerCase() === 'title') {
      capturingTitle = false;
      documentState.title = titleText.trim().slice(0, 512) || null;
    }
    depth -= 1;
  });
  parser.on('error', (error) => {
    throw new Error('The BIMI SVG is not well-formed XML.', { cause: error });
  });
  try {
    parser.write(source).close();
  } catch (cause) {
    diagnostics.push(
      cause instanceof Error ? cause.message : 'The BIMI SVG could not be parsed.',
    );
  }
  if (documentState.root !== 'svg') diagnostics.push('The document root must be <svg>.');
  if (
    documentState.viewBox === null ||
    !/^\s*-?(?:\d+(?:\.\d+)?|\.\d+)\s+-?(?:\d+(?:\.\d+)?|\.\d+)\s+(?:\d+(?:\.\d+)?|\.\d+)\s+(?:\d+(?:\.\d+)?|\.\d+)\s*$/u.test(
      documentState.viewBox,
    )
  )
    diagnostics.push('The root SVG needs a four-number viewBox.');
  if (documentState.title === null)
    diagnostics.push('A concise <title> is recommended for the logo document.');
  return {
    diagnostics,
    elements,
    title: documentState.title,
    valid: diagnostics.length === 0,
    viewBox: documentState.viewBox,
  };
}
