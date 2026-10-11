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
  const svgNamespace = 'http://www.w3.org/2000/svg';
  const xlinkNamespace = 'http://www.w3.org/1999/xlink';
  const xmlNamespace = 'http://www.w3.org/XML/1998/namespace';
  const xmlnsNamespace = 'http://www.w3.org/2000/xmlns/';
  const staticElements = new Set([
    'svg',
    'g',
    'defs',
    'desc',
    'title',
    'metadata',
    'path',
    'rect',
    'circle',
    'ellipse',
    'line',
    'polyline',
    'polygon',
    'text',
    'tspan',
    'textArea',
    'tbreak',
    'use',
    'linearGradient',
    'radialGradient',
    'stop',
    'solidColor',
    'font',
    'font-face',
    'font-face-src',
    'font-face-name',
    'glyph',
    'missing-glyph',
    'hkern',
  ]);
  const presentationReferences = new Set([
    'style',
    'fill',
    'stroke',
    'filter',
    'clip-path',
    'mask',
    'marker',
    'marker-start',
    'marker-mid',
    'marker-end',
    'cursor',
    'color-profile',
  ]);
  const diagnose = (message: string) => {
    if (diagnostics.length >= 511)
      throw new Error('The SVG exceeds the local diagnostic limit.');
    diagnostics.push(message);
  };
  const parser = new SaxesParser({ xmlns: true });
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
  parser.on('processinginstruction', () => {
    diagnose('Processing instructions are outside the static logo profile.');
  });
  parser.on('opentag', (tag) => {
    depth += 1;
    elements += 1;
    if (depth > 64 || elements > 10_000)
      throw new Error('The SVG exceeds local structure limits.');
    const name = tag.local;
    if (documentState.root === '')
      documentState.root = tag.uri === svgNamespace ? name : tag.name;
    if (tag.uri !== svgNamespace || !staticElements.has(name))
      diagnose(`Element <${tag.name}> is outside the static SVG logo profile.`);
    const attributes = tag.attributes;
    for (const attribute of Object.values(attributes)) {
      const attributeName = attribute.name;
      const attributeValue = attribute.value;
      const lowerName = attribute.local.toLowerCase();
      if (attribute.uri === xmlnsNamespace) continue;
      if (
        attribute.uri !== '' &&
        !(attribute.uri === xlinkNamespace && lowerName === 'href') &&
        !(attribute.uri === xmlNamespace && ['space', 'lang', 'id'].includes(lowerName))
      )
        diagnose(`Attribute namespace for ${attributeName} is outside the static profile.`);
      if (lowerName.startsWith('on'))
        diagnose(`Event attribute ${attributeName} is not allowed.`);
      if (lowerName === 'href' && !/^#[A-Za-z_][\w:.-]*$/u.test(attributeValue))
        diagnose(`External reference ${attributeName} is not allowed.`);
      if (presentationReferences.has(lowerName)) {
        // Permit literal local paint references, not CSS escapes, imports or remote URLs.
        const remaining = attributeValue.replaceAll(
          /url\(\s*(?:#[A-Za-z_][\w:.-]*|"#[A-Za-z_][\w:.-]*"|'#[A-Za-z_][\w:.-]*')\s*\)/giu,
          '',
        );
        if (/url\s*\(|\\|@|\/\*|(?:https?:|data:|javascript:|\/\/)/iu.test(remaining))
          diagnose(`External or indirect CSS reference in ${attributeName} is not allowed.`);
      }
      if (attribute.uri === xmlNamespace && lowerName === 'base')
        diagnose('xml:base is not allowed.');
    }
    if (depth === 1) {
      documentState.viewBox = attributes['viewBox']?.value ?? null;
      const profile = attributes['baseProfile']?.value ?? '';
      if (profile !== 'tiny-ps') diagnose('The root SVG should declare baseProfile="tiny-ps".');
      if (attributes['x'] !== undefined || attributes['y'] !== undefined)
        diagnose('The root SVG must not contain x or y attributes.');
    }
    if (tag.uri === svgNamespace && name === 'title') {
      capturingTitle = true;
      titleText = '';
    }
  });
  parser.on('text', (value) => {
    if (capturingTitle) titleText += value;
  });
  parser.on('closetag', (tag) => {
    if (tag.uri === svgNamespace && tag.local === 'title') {
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
