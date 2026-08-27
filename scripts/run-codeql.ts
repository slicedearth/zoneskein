import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { access, chmod, lstat, mkdtemp, open, rename, rm } from 'node:fs/promises';
import { homedir, tmpdir, totalmem } from 'node:os';
import { dirname, isAbsolute, join, normalize, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

interface CodeQlFinding {
  readonly level: 'error' | 'warning' | 'note' | 'none';
  readonly line: number | null;
  readonly message: string;
  readonly path: string | null;
  readonly rule: string;
}

interface CodeQlReport {
  readonly findings: readonly CodeQlFinding[];
  readonly status: 'pass' | 'findings';
  readonly totalFindings: number;
  readonly truncated: boolean;
  readonly version: string;
}

interface ParsedFindings {
  readonly findings: readonly CodeQlFinding[];
  readonly total: number;
  readonly truncated: boolean;
}

interface ProcessOptions {
  readonly cwd: string;
  readonly maxOutputBytes: number;
  readonly timeoutMs: number;
}

interface ProcessResult {
  readonly exitCode: number;
  readonly stderr: string;
  readonly stdout: string;
}

type ProcessRunner = (
  command: string,
  arguments_: readonly string[],
  options: ProcessOptions,
) => Promise<ProcessResult>;

interface LocalCodeQlOptions {
  readonly codeQlCommand?: string;
  readonly makeTemporaryDirectory?: (prefix: string) => Promise<string>;
  readonly removeTemporaryDirectory?: (directory: string) => Promise<void>;
  readonly repositoryRoot?: string;
  readonly runProcess?: ProcessRunner;
  readonly temporaryRoot?: string;
}

interface TemporaryReservation {
  readonly dev: bigint;
  readonly directory: string;
  readonly ino: bigint;
  readonly root: string;
}

const CODEQL_LANGUAGE = 'javascript-typescript';
const CODEQL_QUERY_SUITE =
  'codeql/javascript-queries:codeql-suites/javascript-security-extended.qls';
const CODEQL_THREADS = 2;
const MIN_CODEQL_RAM_MB = 1_024;
const MAX_CODEQL_RAM_MB = 4_096;
const CODEQL_PROCESS_TIMEOUT_MS = 15 * 60 * 1_000;
const MAX_CODEQL_OUTPUT_BYTES = 4 * 1_024 * 1_024;
const MAX_CODEQL_SARIF_BYTES = 16 * 1_024 * 1_024;
const MAX_CODEQL_FINDINGS = 1_000;
const MAX_DISPLAYED_FINDINGS = 100;
const MAX_CODEQL_COMMAND_LENGTH = 4_096;
const CODEQL_TEMP_DIRECTORY_PREFIX = 'zoneskein-codeql-';
const PROJECT_ROOT = resolve(import.meta.dirname, '..');
const CODEQL_CONFIGURATION = join(PROJECT_ROOT, '.github', 'codeql-config.yml');

function isMissingPath(error: unknown): boolean {
  return (
    typeof error === 'object' && error !== null && 'code' in error && error.code === 'ENOENT'
  );
}

function sanitisedText(value: unknown, fallback: string, maximum: number): string {
  if (typeof value !== 'string') return fallback;
  let pendingSpace = false;
  let sanitised = '';
  for (const character of value) {
    const codePoint = character.codePointAt(0) ?? 0;
    const unsafe =
      codePoint <= 0x1f ||
      (codePoint >= 0x7f && codePoint <= 0x9f) ||
      codePoint === 0xad ||
      codePoint === 0x34f ||
      codePoint === 0x61c ||
      (codePoint >= 0x200b && codePoint <= 0x200f) ||
      (codePoint >= 0x202a && codePoint <= 0x202e) ||
      (codePoint >= 0x2060 && codePoint <= 0x206f) ||
      codePoint === 0xfeff;
    if (unsafe || character.trim() === '') {
      pendingSpace = sanitised !== '';
      continue;
    }
    const addition = `${pendingSpace ? ' ' : ''}${character}`;
    if (sanitised.length + addition.length > maximum)
      return `${sanitised.slice(0, maximum - 1)}…`;
    sanitised += addition;
    pendingSpace = false;
  }
  return sanitised === '' ? fallback : sanitised;
}

function boundedDiagnostic(value: unknown, maximum = 1_000): string {
  const source = typeof value === 'string' ? value : '';
  const boundedSource =
    source.length <= maximum * 2
      ? source
      : `${source.slice(0, maximum)} ${source.slice(-maximum)}`;
  const text = sanitisedText(
    boundedSource,
    'No diagnostic output was returned.',
    maximum * 2 + 1,
  );
  if (text.length <= maximum) return text;
  const separator = ' ... ';
  const headLength = Math.floor((maximum - separator.length) * 0.35);
  const tailLength = maximum - separator.length - headLength;
  return `${text.slice(0, headLength)}${separator}${text.slice(-tailLength)}`;
}

function object(value: unknown): Record<string, unknown> | null {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function nestedObject(
  value: Record<string, unknown>,
  key: string,
): Record<string, unknown> | null {
  return object(value[key]);
}

function firstObject(
  value: Record<string, unknown>,
  key: string,
): Record<string, unknown> | null {
  const values = value[key];
  return Array.isArray(values) ? object(values[0]) : null;
}

function normaliseFinding(value: unknown): CodeQlFinding {
  const result = object(value);
  if (result === null) throw new TypeError('CodeQL produced an invalid SARIF result.');
  const message = nestedObject(result, 'message');
  const location = firstObject(result, 'locations');
  const physical = location === null ? null : nestedObject(location, 'physicalLocation');
  const artifact = physical === null ? null : nestedObject(physical, 'artifactLocation');
  const region = physical === null ? null : nestedObject(physical, 'region');
  const suppliedLevel = result['level'];
  const level =
    suppliedLevel === 'error' ||
    suppliedLevel === 'warning' ||
    suppliedLevel === 'note' ||
    suppliedLevel === 'none'
      ? suppliedLevel
      : 'warning';
  const uri = typeof artifact?.['uri'] === 'string' ? artifact['uri'].split(/[?#]/u)[0] : null;
  const suppliedLine = region?.['startLine'];
  return Object.freeze({
    level,
    line:
      typeof suppliedLine === 'number' && Number.isSafeInteger(suppliedLine) && suppliedLine > 0
        ? suppliedLine
        : null,
    message: sanitisedText(message?.['text'], 'CodeQL reported a finding.', 500),
    path: uri === null ? null : sanitisedText(uri, 'unknown path', 1_000),
    rule: sanitisedText(result['ruleId'], 'unknown rule', 200),
  });
}

function parseCodeQlSarif(value: string | Buffer): ParsedFindings {
  const size = Buffer.isBuffer(value) ? value.byteLength : Buffer.byteLength(value, 'utf8');
  if (size > MAX_CODEQL_SARIF_BYTES)
    throw new RangeError(
      `CodeQL SARIF output exceeded ${String(MAX_CODEQL_SARIF_BYTES)} bytes.`,
    );

  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.isBuffer(value) ? value.toString('utf8') : value) as unknown;
  } catch {
    throw new TypeError('CodeQL produced malformed SARIF JSON.');
  }
  const log = object(parsed);
  const runs = log?.['runs'];
  if (log?.['version'] !== '2.1.0' || !Array.isArray(runs))
    throw new TypeError('CodeQL produced an unexpected SARIF document.');
  if (runs.length === 0) throw new TypeError('CodeQL SARIF contains no analysis run.');

  const findings: CodeQlFinding[] = [];
  let total = 0;
  for (const runValue of runs) {
    const run = object(runValue);
    const results = run?.['results'];
    if (!Array.isArray(results))
      throw new TypeError('CodeQL SARIF contains an invalid analysis run.');
    total += results.length;
    const remaining = MAX_CODEQL_FINDINGS - findings.length;
    for (const result of results.slice(0, Math.max(0, remaining)))
      findings.push(normaliseFinding(result));
  }
  return Object.freeze({
    findings: Object.freeze(findings),
    total,
    truncated: total > findings.length,
  });
}

function parseCodeQlVersion(value: string): string {
  try {
    const parsed = object(JSON.parse(value) as unknown);
    if (parsed !== null && typeof parsed['version'] === 'string')
      return sanitisedText(parsed['version'], 'unknown', 100);
  } catch {
    // Older supported bundles may not emit JSON for this command.
  }
  return sanitisedText(value.split(/\r?\n/u)[0], 'unknown', 100);
}

function codeQlRamMegabytes(systemMemoryBytes = totalmem()): number {
  const halfSystemMemory = Math.floor(systemMemoryBytes / (2 * 1_024 * 1_024));
  return Math.max(MIN_CODEQL_RAM_MB, Math.min(MAX_CODEQL_RAM_MB, halfSystemMemory));
}

function containsAsciiControl(value: string): boolean {
  for (const character of value) {
    const codePoint = character.codePointAt(0) ?? 0;
    if (codePoint <= 0x1f || codePoint === 0x7f) return true;
  }
  return false;
}

function resolveCodeQlCommand(value: unknown = process.env['CODEQL_PATH']): string {
  if (value === undefined || value === null || value === '') return 'codeql';
  if (
    typeof value !== 'string' ||
    value.length > MAX_CODEQL_COMMAND_LENGTH ||
    containsAsciiControl(value) ||
    !isAbsolute(value)
  )
    throw new TypeError('CODEQL_PATH must be a bounded absolute executable path.');
  return normalize(value);
}

async function findCodeQlCommand(value: unknown = process.env['CODEQL_PATH']): Promise<string> {
  const command = resolveCodeQlCommand(value);
  if (command !== 'codeql') return command;
  const userLocalCommand = join(homedir(), '.local', 'bin', 'codeql');
  try {
    await access(userLocalCommand, constants.X_OK);
    return userLocalCommand;
  } catch {
    return command;
  }
}

async function runProcessBounded(
  command: string,
  arguments_: readonly string[],
  options: ProcessOptions,
): Promise<ProcessResult> {
  return new Promise((resolveProcess, reject) => {
    const child = spawn(command, [...arguments_], {
      cwd: options.cwd,
      env: process.env,
      shell: false,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let capturedBytes = 0;
    let processError: Error | null = null;
    let terminationReason: 'deadline' | 'output' | null = null;
    let forceTimer: NodeJS.Timeout | undefined;

    const terminate = (): void => {
      child.kill('SIGTERM');
      forceTimer ??= setTimeout(() => child.kill('SIGKILL'), 2_000);
      forceTimer.unref();
    };
    const capture = (chunks: Buffer[], value: Buffer | string): void => {
      const buffer = Buffer.isBuffer(value) ? value : Buffer.from(value);
      const remaining = options.maxOutputBytes - capturedBytes;
      if (remaining > 0) {
        const kept = buffer.subarray(0, remaining);
        chunks.push(kept);
        capturedBytes += kept.byteLength;
      }
      if (buffer.byteLength > remaining && terminationReason === null) {
        terminationReason = 'output';
        terminate();
      }
    };
    child.stdout.on('data', (value: Buffer | string) => {
      capture(stdout, value);
    });
    child.stderr.on('data', (value: Buffer | string) => {
      capture(stderr, value);
    });
    child.once('error', (error) => {
      processError = error;
    });
    const timeout = setTimeout(() => {
      terminationReason ??= 'deadline';
      terminate();
    }, options.timeoutMs);
    child.once('close', (code) => {
      clearTimeout(timeout);
      if (forceTimer !== undefined) clearTimeout(forceTimer);
      if (processError !== null) {
        reject(processError);
        return;
      }
      if (terminationReason === 'output') {
        reject(
          new Error(`CodeQL process output exceeded ${String(options.maxOutputBytes)} bytes.`),
        );
        return;
      }
      if (terminationReason === 'deadline') {
        reject(
          new Error(`CodeQL exceeded its ${String(options.timeoutMs)} ms process deadline.`),
        );
        return;
      }
      resolveProcess({
        exitCode: Number.isInteger(code) ? Number(code) : 2,
        stderr: Buffer.concat(stderr).toString('utf8'),
        stdout: Buffer.concat(stdout).toString('utf8'),
      });
    });
  });
}

async function createTemporaryReservation(
  temporaryRoot: string,
  makeTemporaryDirectory: (prefix: string) => Promise<string>,
): Promise<TemporaryReservation> {
  const root = resolve(temporaryRoot);
  const directory = await makeTemporaryDirectory(join(root, CODEQL_TEMP_DIRECTORY_PREFIX));
  if (dirname(resolve(directory)) !== root)
    throw new TypeError('CodeQL temporary directory is outside the configured temporary root.');
  await chmod(directory, 0o700);
  const metadata = await lstat(directory, { bigint: true });
  if (!metadata.isDirectory() || metadata.isSymbolicLink())
    throw new TypeError('CodeQL temporary reservation must be a real directory.');
  return Object.freeze({ dev: metadata.dev, directory, ino: metadata.ino, root });
}

async function removeTemporaryReservation(reservation: TemporaryReservation): Promise<void> {
  if (dirname(resolve(reservation.directory)) !== reservation.root)
    throw new TypeError('CodeQL temporary reservation left its configured root.');
  const metadata = await lstat(reservation.directory, { bigint: true });
  if (
    !metadata.isDirectory() ||
    metadata.isSymbolicLink() ||
    metadata.dev !== reservation.dev ||
    metadata.ino !== reservation.ino
  )
    throw new Error('CodeQL temporary reservation changed and was preserved for review.');

  const quarantine = join(reservation.root, `.zoneskein-codeql-cleanup-${randomUUID()}`);
  await rename(reservation.directory, quarantine);
  const quarantined = await lstat(quarantine, { bigint: true });
  if (
    !quarantined.isDirectory() ||
    quarantined.isSymbolicLink() ||
    quarantined.dev !== reservation.dev ||
    quarantined.ino !== reservation.ino
  )
    throw new Error('CodeQL temporary reservation changed during cleanup and was preserved.');
  await rm(quarantine, { force: false, recursive: true });
}

async function readBoundedRegularFile(path: string, maximum: number): Promise<Buffer> {
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await handle.stat({ bigint: true });
    if (!before.isFile()) throw new TypeError('CodeQL SARIF output is not a regular file.');
    if (before.size > BigInt(maximum))
      throw new RangeError(`CodeQL SARIF output exceeded ${String(maximum)} bytes.`);

    const buffer = Buffer.alloc(maximum + 1);
    let offset = 0;
    while (offset < buffer.length) {
      const { bytesRead } = await handle.read(buffer, offset, buffer.length - offset, offset);
      if (bytesRead === 0) break;
      offset += bytesRead;
    }
    if (offset > maximum)
      throw new RangeError(`CodeQL SARIF output exceeded ${String(maximum)} bytes.`);

    const after = await handle.stat({ bigint: true });
    if (
      before.dev !== after.dev ||
      before.ino !== after.ino ||
      before.size !== after.size ||
      before.mtimeNs !== after.mtimeNs ||
      before.ctimeNs !== after.ctimeNs
    )
      throw new Error('CodeQL SARIF output changed while it was being read.');
    return buffer.subarray(0, offset);
  } finally {
    await handle.close();
  }
}

function processFailure(stage: string, result: ProcessResult): Error {
  const diagnostic = result.stderr.trim() === '' ? result.stdout : result.stderr;
  return new Error(
    `${stage} failed with exit status ${String(result.exitCode)}: ${boundedDiagnostic(diagnostic)}`,
  );
}

async function runLocalCodeQl(options: LocalCodeQlOptions = {}): Promise<CodeQlReport> {
  const repositoryRoot = resolve(options.repositoryRoot ?? PROJECT_ROOT);
  const configuration =
    options.repositoryRoot === undefined
      ? CODEQL_CONFIGURATION
      : join(repositoryRoot, '.github', 'codeql-config.yml');
  await Promise.all([access(repositoryRoot), access(configuration)]);
  const command = await findCodeQlCommand(options.codeQlCommand);
  const runProcess = options.runProcess ?? runProcessBounded;
  const temporaryRoot = resolve(options.temporaryRoot ?? tmpdir());
  const reservation = await createTemporaryReservation(
    temporaryRoot,
    options.makeTemporaryDirectory ?? mkdtemp,
  );
  const database = join(reservation.directory, 'database');
  const sarif = join(reservation.directory, 'results.sarif');
  const ram = codeQlRamMegabytes();
  const processOptions = {
    cwd: repositoryRoot,
    maxOutputBytes: MAX_CODEQL_OUTPUT_BYTES,
    timeoutMs: CODEQL_PROCESS_TIMEOUT_MS,
  } as const;

  try {
    let versionResult: ProcessResult;
    try {
      versionResult = await runProcess(command, ['version', '--format=json'], processOptions);
    } catch (error) {
      if (isMissingPath(error))
        throw new Error(
          'CodeQL CLI was not found. Install the current official bundle with codeql on PATH, or set CODEQL_PATH to its absolute executable path.',
          { cause: error },
        );
      throw error;
    }
    if (versionResult.exitCode !== 0)
      throw processFailure('CodeQL version check', versionResult);

    const createResult = await runProcess(
      command,
      [
        'database',
        'create',
        database,
        `--language=${CODEQL_LANGUAGE}`,
        '--build-mode=none',
        `--source-root=${repositoryRoot}`,
        `--codescanning-config=${configuration}`,
        `--threads=${String(CODEQL_THREADS)}`,
        `--ram=${String(ram)}`,
        '--verbosity=warnings',
      ],
      processOptions,
    );
    if (createResult.exitCode !== 0)
      throw processFailure('CodeQL database creation', createResult);

    const analyzeResult = await runProcess(
      command,
      [
        'database',
        'analyze',
        database,
        CODEQL_QUERY_SUITE,
        '--format=sarifv2.1.0',
        '--sarif-category=javascript-typescript',
        `--output=${sarif}`,
        `--threads=${String(CODEQL_THREADS)}`,
        `--ram=${String(ram)}`,
        '--download',
        '--verbosity=warnings',
      ],
      processOptions,
    );
    if (analyzeResult.exitCode !== 0) throw processFailure('CodeQL analysis', analyzeResult);

    const parsed = parseCodeQlSarif(
      await readBoundedRegularFile(sarif, MAX_CODEQL_SARIF_BYTES),
    );
    return Object.freeze({
      findings: Object.freeze(parsed.findings.slice(0, MAX_DISPLAYED_FINDINGS)),
      status: parsed.total === 0 ? 'pass' : 'findings',
      totalFindings: parsed.total,
      truncated: parsed.truncated || parsed.findings.length > MAX_DISPLAYED_FINDINGS,
      version: parseCodeQlVersion(versionResult.stdout),
    });
  } finally {
    if (options.removeTemporaryDirectory === undefined)
      await removeTemporaryReservation(reservation);
    else await options.removeTemporaryDirectory(reservation.directory);
  }
}

function formatCodeQlReport(report: CodeQlReport): string {
  const lines = [
    'ZoneSkein local CodeQL check',
    `CodeQL: ${report.version}`,
    `Suite: ${CODEQL_QUERY_SUITE.split(':').at(-1) ?? CODEQL_QUERY_SUITE}`,
    `Result: ${report.status === 'pass' ? 'PASS' : 'FINDINGS'}`,
    `Findings: ${String(report.totalFindings)}`,
  ];
  for (const finding of report.findings) {
    const location = `${finding.path ?? 'unknown location'}${finding.line === null ? '' : `:${String(finding.line)}`}`;
    lines.push(
      '',
      `${finding.level.toUpperCase()} ${finding.rule} at ${location}`,
      `  ${finding.message}`,
    );
  }
  if (report.truncated)
    lines.push('', `Output was truncated after ${String(report.findings.length)} findings.`);
  return `${lines.join('\n')}\n`;
}

function parseArguments(arguments_: readonly string[]): void {
  if (arguments_.length > 0) throw new TypeError('Usage: npm run security:codeql');
}

async function main(arguments_ = process.argv.slice(2)): Promise<number> {
  try {
    parseArguments(arguments_);
    const report = await runLocalCodeQl();
    process.stdout.write(formatCodeQlReport(report));
    return report.status === 'pass' ? 0 : 1;
  } catch (error) {
    process.stderr.write(
      `${boundedDiagnostic(error instanceof Error ? error.message : error, 1_200)}\n`,
    );
    return 2;
  }
}

const invokedPath = process.argv[1];
if (invokedPath !== undefined && resolve(invokedPath) === fileURLToPath(import.meta.url))
  process.exitCode = await main();

export {
  CODEQL_LANGUAGE,
  CODEQL_PROCESS_TIMEOUT_MS,
  CODEQL_QUERY_SUITE,
  CODEQL_THREADS,
  MAX_CODEQL_FINDINGS,
  MAX_CODEQL_OUTPUT_BYTES,
  MAX_CODEQL_RAM_MB,
  MAX_CODEQL_SARIF_BYTES,
  MAX_DISPLAYED_FINDINGS,
  MIN_CODEQL_RAM_MB,
  boundedDiagnostic,
  codeQlRamMegabytes,
  findCodeQlCommand,
  formatCodeQlReport,
  main,
  parseArguments,
  parseCodeQlSarif,
  parseCodeQlVersion,
  resolveCodeQlCommand,
  runLocalCodeQl,
  runProcessBounded,
};
export type { CodeQlFinding, CodeQlReport, LocalCodeQlOptions, ProcessResult, ProcessRunner };
