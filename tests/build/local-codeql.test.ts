/** @vitest-environment node */

import { access, mkdir, mkdtemp, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

import {
  CODEQL_LANGUAGE,
  CODEQL_QUERY_SUITE,
  CODEQL_THREADS,
  MAX_CODEQL_FINDINGS,
  MAX_CODEQL_OUTPUT_BYTES,
  MAX_CODEQL_RAM_MB,
  MAX_CODEQL_SARIF_BYTES,
  MIN_CODEQL_RAM_MB,
  boundedDiagnostic,
  codeQlRamMegabytes,
  formatCodeQlReport,
  parseArguments,
  parseCodeQlSarif,
  parseCodeQlVersion,
  resolveCodeQlCommand,
  runLocalCodeQl,
  runProcessBounded,
} from '../../scripts/run-codeql.ts';
import type { LocalCodeQlOptions } from '../../scripts/run-codeql.ts';

type SarifFinding = ReturnType<typeof finding>;
type ProcessRunner = NonNullable<LocalCodeQlOptions['runProcess']>;

interface ProcessCall {
  readonly arguments_: readonly string[];
  readonly command: string;
}

function sarif(results: readonly SarifFinding[] = []): string {
  return JSON.stringify({
    runs: [{ results, tool: { driver: { name: 'CodeQL' } } }],
    version: '2.1.0',
  });
}

function finding(overrides: Record<string, unknown> = {}) {
  return {
    level: 'warning',
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: 'src/example.ts' },
          region: { startLine: 42 },
        },
      },
    ],
    message: { text: 'Review this path.' },
    ruleId: 'js/example-rule',
    ...overrides,
  };
}

async function createRepositoryFixture(): Promise<string> {
  const repository = await mkdtemp(join(tmpdir(), 'zoneskein-codeql-repository-test-'));
  await mkdir(join(repository, '.github'));
  await writeFile(join(repository, '.github', 'codeql-config.yml'), 'paths-ignore: []\n');
  return repository;
}

describe('local CodeQL input handling', () => {
  it('uses PATH by default and accepts a bounded absolute executable path', () => {
    expect(resolveCodeQlCommand(undefined)).toBe('codeql');
    expect(resolveCodeQlCommand('/opt/codeql/codeql')).toBe('/opt/codeql/codeql');
  });

  it('rejects relative, controlled, and oversized executable paths', () => {
    for (const value of [
      'codeql',
      '../codeql',
      '/opt/codeql\n/codeql',
      `/${'x'.repeat(5_000)}`,
    ])
      expect(() => resolveCodeQlCommand(value)).toThrow(/absolute executable path/u);
  });

  it('accepts no command-line arguments and rejects every target or option', () => {
    expect(() => {
      parseArguments([]);
    }).not.toThrow();
    expect(() => {
      parseArguments(['.']);
    }).toThrow(/Usage/u);
    expect(() => {
      parseArguments(['--upload']);
    }).toThrow(/Usage/u);
  });

  it('extracts a bounded CLI version with a safe fallback', () => {
    expect(parseCodeQlVersion('{"version":"2.26.4"}')).toBe('2.26.4');
    expect(parseCodeQlVersion('CodeQL command-line toolchain release 2.26.4\n')).toBe(
      'CodeQL command-line toolchain release 2.26.4',
    );
    expect(parseCodeQlVersion('{bad json')).toBe('{bad json');
  });

  it('bounds memory and preserves both ends of long diagnostics', () => {
    expect(codeQlRamMegabytes(1 * 1_024 * 1_024 * 1_024)).toBe(MIN_CODEQL_RAM_MB);
    expect(codeQlRamMegabytes(32 * 1_024 * 1_024 * 1_024)).toBe(MAX_CODEQL_RAM_MB);
    const diagnostic = boundedDiagnostic(`start ${'x'.repeat(2_000)} terminal failure`, 100);
    expect(diagnostic).toHaveLength(100);
    expect(diagnostic.startsWith('start ')).toBe(true);
    expect(diagnostic.endsWith('terminal failure')).toBe(true);
  });
});

describe('local CodeQL SARIF parsing', () => {
  it('returns no findings for a valid empty analysis', () => {
    expect(parseCodeQlSarif(sarif())).toEqual({ findings: [], total: 0, truncated: false });
  });

  it('normalises and sanitises untrusted finding fields', () => {
    const parsed = parseCodeQlSarif(
      sarif([
        finding({
          level: 'unexpected',
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: 'src/file.ts?secret=value#fragment' },
                region: { startLine: -1 },
              },
            },
          ],
          message: { text: `review\n\u0085\u034f${'x'.repeat(1_000)}` },
          ruleId: 'bad\nrule\u00ad',
        }),
      ]),
    );
    expect(parsed.total).toBe(1);
    const parsedFinding = parsed.findings[0];
    expect(parsedFinding?.level).toBe('warning');
    expect(parsedFinding?.line).toBeNull();
    expect(parsedFinding?.message).toMatch(/^review /u);
    expect(parsedFinding?.message.length).toBeLessThanOrEqual(500);
    expect(parsedFinding?.path).toBe('src/file.ts');
    expect(parsedFinding?.rule).toBe('bad rule');
    for (const unsafeCharacter of ['\u0085', '\u00ad', '\u034f'])
      expect(JSON.stringify(parsed)).not.toContain(unsafeCharacter);
  });

  it('caps parsed findings while retaining the total', () => {
    const parsed = parseCodeQlSarif(
      sarif(Array.from({ length: MAX_CODEQL_FINDINGS + 7 }, () => finding())),
    );
    expect(parsed.total).toBe(MAX_CODEQL_FINDINGS + 7);
    expect(parsed.findings).toHaveLength(MAX_CODEQL_FINDINGS);
    expect(parsed.truncated).toBe(true);
  });

  it('rejects malformed, structurally invalid, and oversized SARIF', () => {
    expect(() => parseCodeQlSarif('{bad json')).toThrow(/malformed SARIF/u);
    expect(() => parseCodeQlSarif('{"version":"2.1.0","runs":[]}')).toThrow(/no analysis run/u);
    expect(() => parseCodeQlSarif(Buffer.alloc(MAX_CODEQL_SARIF_BYTES + 1))).toThrow(
      /exceeded/u,
    );
  });
});

describe('local CodeQL process and orchestration', () => {
  it('rejects child-process output beyond the shared bound', async () => {
    await expect(
      runProcessBounded(
        process.execPath,
        ['-e', `process.stdout.write('x'.repeat(${String(MAX_CODEQL_OUTPUT_BYTES + 1)}))`],
        { cwd: process.cwd(), maxOutputBytes: 1_024, timeoutMs: 10_000 },
      ),
    ).rejects.toThrow(/output exceeded 1024 bytes/u);
  });

  it('terminates a child process that exceeds its deadline', async () => {
    await expect(
      runProcessBounded(process.execPath, ['-e', 'setInterval(() => {}, 1_000)'], {
        cwd: process.cwd(),
        maxOutputBytes: 1_024,
        timeoutMs: 100,
      }),
    ).rejects.toThrow(/100 ms process deadline/u);
  });

  it('runs the fixed language and extended suite without upload or build commands', async () => {
    const repository = await createRepositoryFixture();
    const temporaryRoot = await mkdtemp(join(tmpdir(), 'zoneskein-codeql-root-test-'));
    const calls: ProcessCall[] = [];
    const runProcess: ProcessRunner = async (command, arguments_) => {
      calls.push({ arguments_, command });
      if (arguments_[0] === 'version')
        return { exitCode: 0, stderr: '', stdout: '{"version":"2.26.4"}' };
      if (arguments_[0] === 'database' && arguments_[1] === 'analyze') {
        const output = arguments_.find((argument) => argument.startsWith('--output='));
        if (output === undefined) throw new Error('Expected a SARIF output path.');
        await writeFile(output.slice('--output='.length), sarif());
      }
      return { exitCode: 0, stderr: '', stdout: '' };
    };

    try {
      const report = await runLocalCodeQl({
        codeQlCommand: '/opt/codeql/codeql',
        repositoryRoot: repository,
        runProcess,
        temporaryRoot,
      });

      expect(report).toEqual({
        findings: [],
        status: 'pass',
        totalFindings: 0,
        truncated: false,
        version: '2.26.4',
      });
      expect(calls).toHaveLength(3);
      expect(calls[1]?.arguments_).toEqual(
        expect.arrayContaining([
          `--language=${CODEQL_LANGUAGE}`,
          '--build-mode=none',
          `--threads=${String(CODEQL_THREADS)}`,
        ]),
      );
      expect(calls[2]?.arguments_).toEqual(
        expect.arrayContaining([CODEQL_QUERY_SUITE, '--download']),
      );
      expect(calls.flatMap((call) => call.arguments_)).not.toContain('upload-results');
      expect(
        calls
          .flatMap((call) => call.arguments_)
          .some((argument) => argument.startsWith('--command')),
      ).toBe(false);
      expect(await readdir(temporaryRoot)).toEqual([]);
    } finally {
      await Promise.all([
        rm(repository, { force: true, recursive: true }),
        rm(temporaryRoot, { force: true, recursive: true }),
      ]);
    }
  });

  it('cleans up the temporary database when analysis fails', async () => {
    const repository = await createRepositoryFixture();
    const temporaryRoot = await mkdtemp(join(tmpdir(), 'zoneskein-codeql-root-test-'));
    const cleanup: { directory?: string } = {};
    const runProcess: ProcessRunner = (_command, arguments_) =>
      Promise.resolve(
        arguments_[0] === 'version'
          ? { exitCode: 0, stderr: '', stdout: '{"version":"2.26.4"}' }
          : { exitCode: 3, stderr: 'database creation failed', stdout: '' },
      );

    try {
      await expect(
        runLocalCodeQl({
          codeQlCommand: '/opt/codeql/codeql',
          removeTemporaryDirectory: async (directory) => {
            cleanup.directory = directory;
            await rm(directory, { recursive: true });
          },
          repositoryRoot: repository,
          runProcess,
          temporaryRoot,
        }),
      ).rejects.toThrow(/database creation failed/u);
      expect(cleanup.directory).toBeDefined();
      if (cleanup.directory === undefined) throw new Error('Expected temporary cleanup.');
      await expect(access(cleanup.directory)).rejects.toMatchObject({ code: 'ENOENT' });
    } finally {
      await Promise.all([
        rm(repository, { force: true, recursive: true }),
        rm(temporaryRoot, { force: true, recursive: true }),
      ]);
    }
  });

  it('turns a missing executable into stable installation guidance', async () => {
    const repository = await createRepositoryFixture();
    const temporaryRoot = await mkdtemp(join(tmpdir(), 'zoneskein-codeql-root-test-'));
    const runProcess: ProcessRunner = () =>
      Promise.reject(Object.assign(new Error('spawn failed'), { code: 'ENOENT' }));

    try {
      await expect(
        runLocalCodeQl({
          codeQlCommand: '/missing/codeql',
          repositoryRoot: repository,
          runProcess,
          temporaryRoot,
        }),
      ).rejects.toThrow(/official bundle/u);
      expect(await readdir(temporaryRoot)).toEqual([]);
    } finally {
      await Promise.all([
        rm(repository, { force: true, recursive: true }),
        rm(temporaryRoot, { force: true, recursive: true }),
      ]);
    }
  });

  it('formats a concise failing report', () => {
    const output = formatCodeQlReport({
      findings: [
        {
          level: 'warning',
          line: 9,
          message: 'Review the input path.',
          path: 'src/example.ts',
          rule: 'js/example-rule',
        },
      ],
      status: 'findings',
      totalFindings: 1,
      truncated: false,
      version: '2.26.4',
    });
    expect(output).toContain('Result: FINDINGS');
    expect(output).toContain('WARNING js/example-rule at src/example.ts:9');
  });
});
