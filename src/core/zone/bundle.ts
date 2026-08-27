import { canonicalMasterName } from './master-name';
import { ZONE_ANALYSIS_LIMITS } from './parser';
import { validateDnsName } from '../dns/names';

export const ZONE_BUNDLE_LIMITS = Object.freeze({
  diagnostics: ZONE_ANALYSIS_LIMITS.diagnostics,
  files: 32,
  generatedRecords: ZONE_ANALYSIS_LIMITS.records,
  includeDepth: 16,
  sourceCharacters: ZONE_ANALYSIS_LIMITS.characters,
});

export interface ZoneBundleFile {
  readonly name: string;
  readonly source: string;
}

export interface ZoneBundleDiagnostic {
  readonly file: string;
  readonly line: number;
  readonly message: string;
  readonly severity: 'error' | 'warning';
}

export interface ZoneBundleProvenance {
  readonly generatedIndex: number | null;
  readonly outputLine: number;
  readonly sourceFile: string;
  readonly sourceLine: number;
}

export interface ExpandedZoneBundle {
  readonly diagnostics: readonly ZoneBundleDiagnostic[];
  readonly entry: string;
  readonly provenance: readonly ZoneBundleProvenance[];
  readonly source: string;
  readonly status: 'complete' | 'invalid';
}

interface ExpansionState {
  readonly diagnostics: ZoneBundleDiagnostic[];
  readonly files: ReadonlyMap<string, string>;
  generated: number;
  outputCharacters: number;
  outputLines: string[];
  provenance: ZoneBundleProvenance[];
}

function safeName(value: string): string | null {
  const normalised = value.replaceAll('\\', '/').replace(/^\.\//u, '');
  if (
    normalised === '' ||
    normalised.length > 1_024 ||
    normalised.startsWith('/') ||
    normalised.split('/').some((part) => part === '' || part === '.' || part === '..')
  )
    return null;
  for (const character of normalised) {
    const point = character.codePointAt(0);
    if (point !== undefined && (point <= 31 || point === 127)) return null;
  }
  return normalised;
}

function relativeName(parent: string, child: string): string | null {
  const supplied = safeName(child);
  if (supplied === null) return null;
  const slash = parent.lastIndexOf('/');
  return safeName(slash < 0 ? supplied : `${parent.slice(0, slash + 1)}${supplied}`);
}

function directiveText(value: string): string {
  let quoted = false;
  let escaped = false;
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index];
    if (escaped) escaped = false;
    else if (character === '\\') escaped = true;
    else if (character === '"') quoted = !quoted;
    else if (character === ';' && !quoted) return value.slice(0, index).trim();
  }
  return value.trim();
}

function directiveTokens(value: string): readonly string[] | null {
  const tokens: string[] = [];
  let token = '';
  let quote = false;
  let escaped = false;
  for (const character of value) {
    if (escaped) {
      token += character;
      escaped = false;
    } else if (character === '\\') escaped = true;
    else if (character === '"') quote = !quote;
    else if (/\s/u.test(character) && !quote) {
      if (token !== '') tokens.push(token);
      token = '';
    } else token += character;
  }
  if (escaped || quote) return null;
  if (token !== '') tokens.push(token);
  return tokens;
}

function nibble(value: number, width: number, upper: boolean): string {
  const hexadecimal = Math.abs(value).toString(16).padStart(width, '0').slice(-width);
  const sign = value < 0 ? '-' : '';
  const rendered = `${sign}${hexadecimal.split('').reverse().join('.')}`;
  return upper ? rendered.toUpperCase() : rendered;
}

function generatedValue(index: number, modifier: string | undefined): string | null {
  if (modifier === undefined) return String(index);
  const parts = modifier.split(',');
  if (parts.length > 3) return null;
  const offsetText = parts[0] ?? '';
  const widthText = parts[1] ?? '0';
  const base = parts[2] ?? 'd';
  if (!/^-?\d+$/u.test(offsetText) || !/^\d{1,2}$/u.test(widthText)) return null;
  const offset = Number(offsetText);
  const width = Number(widthText);
  if (!Number.isSafeInteger(offset) || width > 64) return null;
  const value = index + offset;
  if (base === 'n' || base === 'N') return nibble(value, width, base === 'N');
  const radix = base === 'd' ? 10 : base === 'o' ? 8 : base === 'x' || base === 'X' ? 16 : 0;
  if (radix === 0) return null;
  const sign = value < 0 ? '-' : '';
  const absolute = Math.abs(value).toString(radix).padStart(width, '0');
  const rendered = `${sign}${absolute}`;
  return base === 'X' ? rendered.toUpperCase() : rendered;
}

function substitute(value: string, index: number): string | null {
  let output = '';
  for (let offset = 0; offset < value.length; offset += 1) {
    const character = value.charAt(offset);
    if (character === '\\' && value[offset + 1] === '$') {
      output += '$';
      offset += 1;
      continue;
    }
    if (character !== '$') {
      output += character;
      continue;
    }
    if (value[offset + 1] !== '{') {
      output += String(index);
      continue;
    }
    const end = value.indexOf('}', offset + 2);
    if (end < 0) return null;
    const replacement = generatedValue(index, value.slice(offset + 2, end));
    if (replacement === null) return null;
    output += replacement;
    offset = end;
  }
  return output;
}

function range(value: string): readonly number[] | null {
  const match = /^(\d+)-(\d+)(?:\/(\d+))?$/u.exec(value);
  if (match === null) return null;
  const start = Number(match[1]);
  const stop = Number(match[2]);
  const step = Number(match[3] ?? '1');
  if (
    !Number.isSafeInteger(start) ||
    !Number.isSafeInteger(stop) ||
    !Number.isSafeInteger(step) ||
    step < 1 ||
    stop < start ||
    Math.floor((stop - start) / step) + 1 > ZONE_BUNDLE_LIMITS.generatedRecords
  )
    return null;
  const values: number[] = [];
  for (let current = start; current <= stop; current += step) values.push(current);
  return values;
}

function append(
  state: ExpansionState,
  text: string,
  sourceFile: string,
  sourceLine: number,
  generatedIndex: number | null,
): boolean {
  const added = text.length + 1;
  if (state.outputCharacters + added > ZONE_BUNDLE_LIMITS.sourceCharacters) {
    state.diagnostics.push({
      file: sourceFile,
      line: sourceLine,
      message: `Expanded zone text exceeds the ${String(ZONE_BUNDLE_LIMITS.sourceCharacters)}-character safety limit.`,
      severity: 'error',
    });
    return false;
  }
  state.outputCharacters += added;
  state.outputLines.push(text);
  state.provenance.push({
    generatedIndex,
    outputLine: state.outputLines.length,
    sourceFile,
    sourceLine,
  });
  return true;
}

function normalisedOrigin(value: string, current: string | null): string | null {
  if (current === null) {
    const validated = validateDnsName(value);
    return validated.ok ? validated.value.absolute : null;
  }
  return canonicalMasterName(value, current)?.absolute ?? null;
}

function expandFile(
  state: ExpansionState,
  name: string,
  inheritedOrigin: string | null,
  stack: readonly string[],
): void {
  if (stack.length >= ZONE_BUNDLE_LIMITS.includeDepth) {
    state.diagnostics.push({
      file: name,
      line: 1,
      message: `Include nesting exceeds the ${String(ZONE_BUNDLE_LIMITS.includeDepth)}-file depth limit.`,
      severity: 'error',
    });
    return;
  }
  if (stack.includes(name)) {
    state.diagnostics.push({
      file: name,
      line: 1,
      message: `Include cycle detected: ${[...stack, name].join(' → ')}.`,
      severity: 'error',
    });
    return;
  }
  const source = state.files.get(name);
  if (source === undefined) return;
  let currentOrigin = inheritedOrigin;
  const lines = source.replaceAll('\r\n', '\n').replaceAll('\r', '\n').split('\n');
  for (const [offset, line] of lines.entries()) {
    const lineNumber = offset + 1;
    const directive = directiveText(line);
    const tokens = directiveTokens(directive);
    const keyword = tokens?.[0]?.toUpperCase();
    if (keyword === '$ORIGIN') {
      const nextOrigin =
        tokens?.length === 2 ? normalisedOrigin(tokens[1] ?? '', currentOrigin) : null;
      if (nextOrigin === null) {
        state.diagnostics.push({
          file: name,
          line: lineNumber,
          message: '$ORIGIN requires exactly one valid absolute or relative DNS name.',
          severity: 'error',
        });
      } else {
        currentOrigin = nextOrigin;
        append(state, line, name, lineNumber, null);
      }
      continue;
    }
    if (keyword === '$INCLUDE') {
      if (tokens === null || tokens.length < 2 || tokens.length > 3) {
        state.diagnostics.push({
          file: name,
          line: lineNumber,
          message: '$INCLUDE requires a local file name and an optional origin.',
          severity: 'error',
        });
        continue;
      }
      const includeName = relativeName(name, tokens[1] ?? '');
      const includeOrigin =
        tokens[2] === undefined ? currentOrigin : normalisedOrigin(tokens[2], currentOrigin);
      if (includeName === null || (includeOrigin === null && tokens[2] !== undefined)) {
        state.diagnostics.push({
          file: name,
          line: lineNumber,
          message: '$INCLUDE contains an unsafe file name or invalid origin.',
          severity: 'error',
        });
        continue;
      }
      if (!state.files.has(includeName)) {
        state.diagnostics.push({
          file: name,
          line: lineNumber,
          message: `Included file ${includeName} was not supplied.`,
          severity: 'error',
        });
        continue;
      }
      if (includeOrigin !== null)
        append(state, `$ORIGIN ${includeOrigin}`, name, lineNumber, null);
      expandFile(state, includeName, includeOrigin, [...stack, name]);
      if (currentOrigin !== null)
        append(state, `$ORIGIN ${currentOrigin}`, name, lineNumber, null);
      else
        state.diagnostics.push({
          file: name,
          line: lineNumber,
          message:
            'The caller origin is unknown, so an included $ORIGIN cannot be restored reliably. Supply an origin or place $ORIGIN before this include.',
          severity: 'error',
        });
      continue;
    }
    if (keyword === '$GENERATE') {
      if (tokens === null || tokens.length < 4) {
        state.diagnostics.push({
          file: name,
          line: lineNumber,
          message: '$GENERATE requires a range, owner pattern, and record fields.',
          severity: 'error',
        });
        continue;
      }
      const values = range(tokens[1] ?? '');
      if (
        values === null ||
        state.generated + values.length > ZONE_BUNDLE_LIMITS.generatedRecords
      ) {
        state.diagnostics.push({
          file: name,
          line: lineNumber,
          message: `$GENERATE has an invalid range or exceeds the ${String(ZONE_BUNDLE_LIMITS.generatedRecords)}-record safety limit.`,
          severity: 'error',
        });
        continue;
      }
      const template = tokens.slice(2).join(' ');
      for (const value of values) {
        const rendered = substitute(template, value);
        if (rendered === null) {
          state.diagnostics.push({
            file: name,
            line: lineNumber,
            message: '$GENERATE contains an invalid substitution modifier.',
            severity: 'error',
          });
          break;
        }
        if (!append(state, rendered, name, lineNumber, value)) break;
        state.generated += 1;
      }
      continue;
    }
    if (!append(state, line, name, lineNumber, null)) return;
  }
}

export function expandZoneBundle(
  inputFiles: readonly ZoneBundleFile[],
  entryName: string,
  origin?: string,
): ExpandedZoneBundle {
  const diagnostics: ZoneBundleDiagnostic[] = [];
  if (inputFiles.length === 0 || inputFiles.length > ZONE_BUNDLE_LIMITS.files)
    return {
      diagnostics: [
        {
          file: entryName,
          line: 1,
          message: `Supply between one and ${String(ZONE_BUNDLE_LIMITS.files)} zone files.`,
          severity: 'error',
        },
      ],
      entry: entryName,
      provenance: [],
      source: '',
      status: 'invalid',
    };
  const files = new Map<string, string>();
  let inputCharacters = 0;
  for (const file of inputFiles) {
    const name = safeName(file.name);
    inputCharacters += file.source.length;
    if (name === null)
      diagnostics.push({
        file: file.name,
        line: 1,
        message: 'File name is unsafe.',
        severity: 'error',
      });
    else if (files.has(name))
      diagnostics.push({
        file: name,
        line: 1,
        message: 'File name is repeated.',
        severity: 'error',
      });
    else files.set(name, file.source);
  }
  const entry = safeName(entryName);
  if (inputCharacters > ZONE_BUNDLE_LIMITS.sourceCharacters)
    diagnostics.push({
      file: entryName,
      line: 1,
      message: `Combined source exceeds the ${String(ZONE_BUNDLE_LIMITS.sourceCharacters)}-character safety limit.`,
      severity: 'error',
    });
  if (entry === null || !files.has(entry))
    diagnostics.push({
      file: entryName,
      line: 1,
      message: 'Choose a supplied, safely named entry file.',
      severity: 'error',
    });
  const initialOrigin =
    origin === undefined || origin.trim() === '' ? null : normalisedOrigin(origin, null);
  if (origin !== undefined && origin.trim() !== '' && initialOrigin === null)
    diagnostics.push({
      file: entryName,
      line: 1,
      message: 'The supplied origin is invalid.',
      severity: 'error',
    });
  const state: ExpansionState = {
    diagnostics,
    files,
    generated: 0,
    outputCharacters: 0,
    outputLines: [],
    provenance: [],
  };
  if (!diagnostics.some((item) => item.severity === 'error') && entry !== null)
    expandFile(state, entry, initialOrigin, []);
  const hasErrors = diagnostics.some((item) => item.severity === 'error');
  const boundedDiagnostics = diagnostics.slice(0, ZONE_BUNDLE_LIMITS.diagnostics - 1);
  if (diagnostics.length >= ZONE_BUNDLE_LIMITS.diagnostics)
    boundedDiagnostics.push({
      file: entryName,
      line: 1,
      message: `Only the first ${String(ZONE_BUNDLE_LIMITS.diagnostics - 1)} bundle diagnostics are shown.`,
      severity: 'error',
    });
  return {
    diagnostics: boundedDiagnostics,
    entry: entry ?? entryName,
    provenance: hasErrors ? [] : state.provenance,
    source: hasErrors ? '' : state.outputLines.join('\n'),
    status: hasErrors ? 'invalid' : 'complete',
  };
}
