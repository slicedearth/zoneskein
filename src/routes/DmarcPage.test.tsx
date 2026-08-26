import { encode, decode } from '@dnsquery/dns-packet';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { DmarcPage } from './DmarcPage';
import {
  decodeMailAuthenticationEvidence,
  encodeMailAuthenticationEvidence,
  MAIL_AUTHENTICATION_EVIDENCE_SCHEMA,
} from '../core/mail/evidence';

vi.mock('../core/doh/rate-limit', () => ({
  BrowserRateLimiter: class {
    imposeCooldown(): void {
      // Route tests retain the wire resolver but do not exercise cross-tab pacing.
    }

    wait(): Promise<void> {
      return Promise.resolve();
    }
  },
}));

interface DnsFixture {
  readonly error?: boolean;
  readonly rcode?: 'NOERROR' | 'NXDOMAIN' | 'SERVFAIL';
  readonly values?: readonly string[];
}

function response(questionBytes: Uint8Array, fixture: DnsFixture): Response {
  const question = decode(questionBytes).questions?.[0];
  if (question === undefined) throw new Error('Expected one DNS question.');
  if (fixture.error === true)
    return new Response('', { headers: { 'Content-Type': 'text/plain' }, status: 503 });
  const values = fixture.values ?? [];
  const flags =
    fixture.rcode === 'SERVFAIL' ? 0x8182 : fixture.rcode === 'NXDOMAIN' ? 0x8183 : 0x8180;
  const bytes = encode({
    answers: values.map((value) => ({
      class: 'IN',
      data: [value],
      name: question.name,
      ttl: 300,
      type: 'TXT',
    })),
    flags,
    id: 0,
    questions: [question],
    type: 'response',
  });
  const body = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(body).set(bytes);
  return new Response(body, {
    headers: { 'Content-Type': 'application/dns-message' },
    status: 200,
  });
}

function requestBytes(input: RequestInfo | URL, init?: RequestInit): Uint8Array {
  if (init?.body instanceof ArrayBuffer) return new Uint8Array(init.body);
  if (typeof input !== 'string') throw new Error('Expected a string DNS request URL.');
  const encoded = new URL(input).searchParams.get('dns');
  if (encoded === null) throw new Error('Expected a DNS wire query.');
  const base64 = encoded.replaceAll('-', '+').replaceAll('_', '/');
  const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, '=');
  return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
}

function queryName(bytes: Uint8Array): string {
  return decode(bytes).questions?.[0]?.name.toLowerCase().replace(/\.$/u, '') ?? '';
}

function installDns(fixtures: Readonly<Record<string, DnsFixture>>) {
  const fetchMock = vi.fn<typeof fetch>((input, init) => {
    const bytes = requestBytes(input, init);
    return Promise.resolve(
      response(bytes, fixtures[queryName(bytes)] ?? { rcode: 'NXDOMAIN' }),
    );
  });
  vi.stubGlobal('fetch', fetchMock);
  return fetchMock;
}

afterEach(() => vi.unstubAllGlobals());

describe('DmarcPage', () => {
  const transferredEvidence = () => {
    const decoded = decodeMailAuthenticationEvidence(
      JSON.stringify({
        createdAt: '2026-08-26T00:01:00.000Z',
        dkim: [
          {
            capturedAt: '2026-08-26T00:00:00.000Z',
            domain: 'signer.example',
            reconstructed: false,
            resolverId: 'google',
            source: 'dkim-message',
          },
        ],
        evidenceSchema: MAIL_AUTHENTICATION_EVIDENCE_SCHEMA,
        spf: {
          capturedAt: '2026-08-26T00:01:00.000Z',
          domain: 'bounce.example',
          identitySource: 'mail-from',
          resolverId: 'cloudflare',
          result: 'pass',
          source: 'spf-sender',
        },
      }),
    );
    if (!decoded.ok) throw new Error(decoded.error);
    return decoded.value;
  };

  it('loads a minimal in-memory hand-off and detaches provenance after manual changes', async () => {
    const user = userEvent.setup();
    const onEvidenceChange = vi.fn();
    render(
      <DmarcPage initialEvidence={transferredEvidence()} onEvidenceChange={onEvidenceChange} />,
    );

    expect(screen.getByRole('button', { name: 'Alignment check' })).toHaveAttribute(
      'aria-pressed',
      'true',
    );
    expect(screen.getByLabelText('Domains from passing DKIM signatures')).toHaveValue(
      'signer.example',
    );
    expect(screen.getByLabelText('Previous SPF result')).toHaveValue('pass');
    expect(screen.getByLabelText('Domain authenticated by SPF')).toHaveValue('bounce.example');
    expect(
      screen.getByText(/does not contain raw messages.*mailbox local parts/iu),
    ).toBeVisible();
    expect(
      screen.getByRole('button', { name: 'Copy prior authentication JSON' }),
    ).toBeVisible();

    await user.type(
      screen.getByLabelText('Domains from passing DKIM signatures'),
      '\nother.example',
    );
    expect(onEvidenceChange).toHaveBeenLastCalledWith(null);
    expect(
      screen.queryByRole('button', { name: 'Copy prior authentication JSON' }),
    ).not.toBeInTheDocument();
  });

  it('strictly imports a portable hand-off and rejects ambiguous JSON', async () => {
    const user = userEvent.setup();
    const onEvidenceChange = vi.fn();
    render(<DmarcPage onEvidenceChange={onEvidenceChange} />);
    await user.click(screen.getByRole('button', { name: 'Alignment check' }));
    await user.click(screen.getByText('Import prior authentication JSON'));

    const input = screen.getByLabelText('Prior authentication hand-off JSON');
    fireEvent.change(input, {
      target: {
        value:
          '{"createdAt":"2026-08-26T00:00:00.000Z","createdAt":"2026-08-27T00:00:00.000Z"}',
      },
    });
    await user.click(screen.getByRole('button', { name: 'Import prior evidence' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(/keys must be unique/iu);

    const evidence = transferredEvidence();
    fireEvent.change(input, { target: { value: encodeMailAuthenticationEvidence(evidence) } });
    await user.click(screen.getByRole('button', { name: 'Import prior evidence' }));
    expect(screen.getByLabelText('Domains from passing DKIM signatures')).toHaveValue(
      'signer.example',
    );
    expect(onEvidenceChange).toHaveBeenLastCalledWith(evidence);
  });

  it('discloses the Netlify intermediary when the Quad9 relay is selected', async () => {
    const user = userEvent.setup();
    render(<DmarcPage />);

    const resolver = screen.getByLabelText('Resolver');
    await user.selectOptions(resolver, 'quad9-relay');

    const note = screen.getByText(/DNS question and connection metadata to Netlify/iu);
    expect(note).toHaveAttribute('id', 'dmarc-resolver-note');
    expect(resolver).toHaveAttribute('aria-describedby', 'dmarc-resolver-note');
  });

  const resolverFor = (testNumber: number): 'cloudflare' | 'google' | 'quad9' =>
    ['cloudflare', 'google', 'quad9'][testNumber % 3] as 'cloudflare' | 'google' | 'quad9';

  it('uses pressed-button mode semantics and rejects alignment input locally', async () => {
    const fetchMock = installDns({});
    const user = userEvent.setup();
    render(<DmarcPage />);

    const policyMode = screen.getByRole('button', { name: 'Policy discovery' });
    const alignmentMode = screen.getByRole('button', { name: 'Alignment check' });
    expect(policyMode).toHaveAttribute('aria-pressed', 'true');
    expect(alignmentMode).toHaveAttribute('aria-pressed', 'false');
    expect(screen.queryByRole('tab')).not.toBeInTheDocument();

    await user.click(alignmentMode);
    expect(policyMode).toHaveAttribute('aria-pressed', 'false');
    expect(alignmentMode).toHaveAttribute('aria-pressed', 'true');
    expect(screen.queryByLabelText(/Raw/iu)).not.toBeInTheDocument();
    expect(
      screen.getByText(/part after @ in the message’s visible From address/iu),
    ).toBeVisible();
    expect(screen.getByText(/DKIM Message verifier/iu)).toBeVisible();
    expect(screen.getByText(/SPF Sender evaluation/iu)).toBeVisible();
    await user.type(screen.getByLabelText('Visible From address domain'), 'mail.example.com');
    await user.selectOptions(screen.getByLabelText('Previous SPF result'), 'pass');
    await user.click(screen.getByRole('button', { name: 'Check alignment' }));

    expect(await screen.findByRole('alert')).toHaveTextContent(
      /domain authenticated by the passing SPF result/iu,
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('discovers every relaxed DKIM boundary and renders per-method pass evidence', async () => {
    const fetchMock = installDns({
      '_dmarc.mail.align-one.test': {
        values: ['v=DMARC1; p=reject; adkim=r; aspf=r'],
      },
      '_dmarc.align-one.test': { values: ['v=DMARC1; p=none; psd=n'] },
      '_dmarc.signer.align-one.test': { values: [] },
    });
    const user = userEvent.setup();
    render(<DmarcPage />);

    await user.click(screen.getByRole('button', { name: 'Alignment check' }));
    await user.type(
      screen.getByLabelText('Visible From address domain'),
      'mail.align-one.test',
    );
    await user.type(
      screen.getByLabelText('Domains from passing DKIM signatures'),
      'signer.align-one.test',
    );
    await user.selectOptions(screen.getByLabelText('Previous SPF result'), 'fail');
    await user.type(
      screen.getByLabelText('Domain authenticated by SPF'),
      'bounce.unrelated.test',
    );
    await user.click(
      screen.getByRole('checkbox', {
        name: /confirm these prior SPF and DKIM results belong/iu,
      }),
    );
    await user.click(screen.getByRole('button', { name: 'Check alignment' }));

    expect(await screen.findByRole('heading', { name: 'DMARC pass' })).toBeVisible();
    expect(screen.getByRole('status', { name: 'DMARC run status' })).toHaveTextContent(
      'DMARC alignment check complete: pass.',
    );
    expect(screen.getByRole('heading', { name: 'Per-method evidence' })).toBeVisible();
    expect(screen.getAllByText('signer.align-one.test').length).toBeGreaterThan(1);
    expect(
      screen.queryByText(/independently selected destination boundary/iu),
    ).not.toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledTimes(3);
    const targets = fetchMock.mock.calls.map(([input, init]) =>
      queryName(requestBytes(input, init)),
    );
    expect(targets).toContain('_dmarc.signer.align-one.test');
    for (const [input, init] of fetchMock.mock.calls) {
      expect(typeof input === 'string' ? input : '').not.toContain('signer.align-one.test');
      expect(init).toEqual(
        expect.objectContaining({
          cache: 'no-store',
          credentials: 'omit',
          referrerPolicy: 'no-referrer',
        }),
      );
    }
  });

  it('shows temperror and no pass when a required identifier walk is incomplete', async () => {
    installDns({
      '_dmarc.mail.align-temp.test': {
        values: ['v=DMARC1; p=reject; adkim=r; aspf=r'],
      },
      '_dmarc.align-temp.test': { values: ['v=DMARC1; p=none; psd=n'] },
      '_dmarc.signer.align-temp.test': { rcode: 'SERVFAIL' },
    });
    const user = userEvent.setup();
    render(<DmarcPage />);

    await user.click(screen.getByRole('button', { name: 'Alignment check' }));
    await user.type(
      screen.getByLabelText('Visible From address domain'),
      'mail.align-temp.test',
    );
    await user.type(
      screen.getByLabelText('Domains from passing DKIM signatures'),
      'signer.align-temp.test',
    );
    await user.click(screen.getByRole('button', { name: 'Check alignment' }));

    expect(await screen.findByRole('heading', { name: 'DMARC temperror' })).toBeVisible();
    expect(screen.queryByRole('heading', { name: 'DMARC pass' })).not.toBeInTheDocument();
    expect(screen.getAllByText(/temporary error/iu).length).toBeGreaterThan(0);
  });

  it('independently discovers reporting boundaries and honours RFC 9990 authorisation tags', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    const user = userEvent.setup();
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText },
    });
    installDns({
      '_dmarc.report-auth.test': {
        values: ['v=DMARC1; p=none; psd=n; rua=mailto:dmarc@reports.report-auth.test'],
      },
      '_dmarc.reports.report-auth.test': {
        values: ['v=DMARC1; p=none; psd=n'],
      },
      'report-auth.test._report._dmarc.reports.report-auth.test': {
        values: ['v=DMARC1; xprovider=allowed'],
      },
    });
    render(<DmarcPage />);

    await user.selectOptions(screen.getByLabelText('Resolver'), resolverFor(0));
    await user.type(screen.getByLabelText('Domain'), 'report-auth.test');
    await user.click(screen.getByRole('button', { name: 'Inspect DMARC' }));

    expect(
      await screen.findByText('Reporting boundaries and authorisation', undefined, {
        timeout: 5_000,
      }),
    ).toBeVisible();
    expect(screen.getByText('authorised', { selector: '.status-badge' })).toBeVisible();
    expect(screen.getByText(/basic-valid authorisation record/iu)).toBeVisible();
    expect(screen.getAllByText('mailto:dmarc@reports.report-auth.test').length).toBeGreaterThan(
      1,
    );
    await user.click(screen.getByRole('button', { name: 'Copy DMARC evidence JSON' }));
    await waitFor(() => expect(writeText).toHaveBeenCalled());
    const evidence = String(writeText.mock.calls[0]?.[0]);
    expect(evidence.length).toBeLessThan(65_536);
    expect(evidence).toContain('zoneskein-dmarc-policy-v1');
    expect(evidence).toContain('report-auth.test._report._dmarc.reports.report-auth.test');
    const parsedEvidence = JSON.parse(evidence) as {
      capturedAt?: string;
      resolver?: { id?: string };
    };
    expect(parsedEvidence.capturedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/iu);
    expect(parsedEvidence.resolver?.id).toBe('cloudflare');
    expect(screen.getByRole('status', { name: 'DMARC run status' })).toHaveTextContent(
      /policy discovery complete/iu,
    );
  });

  it('fails reporting authorisation closed when a same-suffix destination boundary errors', async () => {
    installDns({
      '_dmarc.report-temp.test': {
        values: ['v=DMARC1; p=none; psd=n; rua=mailto:dmarc@reports.report-temp.test'],
      },
      '_dmarc.reports.report-temp.test': { rcode: 'SERVFAIL' },
    });
    const user = userEvent.setup();
    render(<DmarcPage />);

    await user.selectOptions(screen.getByLabelText('Resolver'), resolverFor(2));
    await user.type(screen.getByLabelText('Domain'), 'report-temp.test');
    await user.click(screen.getByRole('button', { name: 'Inspect DMARC' }));

    expect(await screen.findByText('temperror', { selector: '.status-badge' })).toBeVisible();
    expect(screen.getByText('No authorised destination')).toBeVisible();
  });

  it('uses ruf rather than a cross-kind rua override for forensic reporting', async () => {
    installDns({
      '_dmarc.report-ruf.test': {
        values: ['v=DMARC1; p=none; psd=n; ruf=mailto:old@reports.report-ruf.test'],
      },
      '_dmarc.reports.report-ruf.test': {
        values: ['v=DMARC1; p=none; psd=n'],
      },
      'report-ruf.test._report._dmarc.reports.report-ruf.test': {
        values: [
          'v=DMARC1; rua=mailto:wrong@attacker.test; ruf=mailto:new@reports.report-ruf.test',
        ],
      },
    });
    const user = userEvent.setup();
    render(<DmarcPage />);

    await user.selectOptions(screen.getByLabelText('Resolver'), resolverFor(0));
    await user.type(screen.getByLabelText('Domain'), 'report-ruf.test');
    await user.click(screen.getByRole('button', { name: 'Inspect DMARC' }));

    expect(
      await screen.findByText('mailto:new@reports.report-ruf.test', undefined, {
        timeout: 5_000,
      }),
    ).toBeVisible();
    expect(screen.queryByText(/wrong@attacker/iu)).not.toBeInTheDocument();
  });

  it('caps passing DKIM entries before any network request without blocking policy mode', async () => {
    const fetchMock = installDns({});
    const user = userEvent.setup();
    render(<DmarcPage />);

    await user.click(screen.getByRole('button', { name: 'Alignment check' }));
    await user.type(screen.getByLabelText('Visible From address domain'), 'example.com');
    fireEvent.change(screen.getByLabelText('Domains from passing DKIM signatures'), {
      target: {
        value: Array.from({ length: 21 }, (_, index) => `s${String(index)}.example.com`).join(
          '\n',
        ),
      },
    });
    await user.click(screen.getByRole('button', { name: 'Check alignment' }));

    expect(await screen.findByRole('alert')).toHaveTextContent(/no more than 20/iu);
    expect(fetchMock).not.toHaveBeenCalled();

    await user.click(screen.getByRole('button', { name: 'Policy discovery' }));
    await user.click(screen.getByRole('button', { name: 'Inspect DMARC' }));

    expect(await screen.findByRole('heading', { name: 'DMARC policy' })).toBeVisible();
    expect(fetchMock).toHaveBeenCalled();
  });

  it('copies bounded alignment evidence without persisting unrelated identifiers', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    const user = userEvent.setup();
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText },
    });
    installDns({
      '_dmarc.mail.evidence.test': {
        values: ['v=DMARC1; p=reject; adkim=s; aspf=s'],
      },
      '_dmarc.evidence.test': { values: ['v=DMARC1; p=none; psd=n'] },
    });
    render(<DmarcPage />);

    await user.click(screen.getByRole('button', { name: 'Alignment check' }));
    await user.type(screen.getByLabelText('Visible From address domain'), 'mail.evidence.test');
    await user.type(
      screen.getByLabelText('Domains from passing DKIM signatures'),
      'mail.evidence.test',
    );
    expect(
      screen.getByText(/does not verify the signatures again or rerun SPF/iu),
    ).toBeVisible();
    await user.click(screen.getByRole('button', { name: 'Check alignment' }));
    expect(await screen.findByRole('heading', { name: 'DMARC indeterminate' })).toBeVisible();
    expect(screen.getByText(/relationship was not acknowledged/iu)).toBeVisible();

    await user.click(
      screen.getByRole('checkbox', {
        name: /confirm these prior SPF and DKIM results belong/iu,
      }),
    );
    expect(
      screen.queryByRole('heading', { name: 'DMARC indeterminate' }),
    ).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Check alignment' }));
    await screen.findByRole('heading', { name: 'DMARC pass' });
    expect(screen.getByText(/any pass is conditional/iu)).toBeVisible();
    await user.click(screen.getByRole('button', { name: 'Copy alignment evidence JSON' }));

    await waitFor(() => expect(writeText).toHaveBeenCalled());
    const evidence = String(writeText.mock.calls[0]?.[0]);
    expect(evidence.length).toBeLessThan(65_536);
    expect(evidence).toContain('zoneskein-dmarc-alignment-v2');
    expect(evidence).toContain('mail.evidence.test');
    expect(evidence).not.toContain('postmaster');
    const parsedEvidence = JSON.parse(evidence) as {
      capturedAt?: string;
      evidence?: readonly {
        acknowledged?: boolean;
        provenance?: { correlation?: string; source?: string };
        qualification?: string;
      }[];
      evidenceAcknowledged?: boolean;
      fromDomain?: string;
      resolver?: { id?: string };
    };
    expect(parsedEvidence.capturedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/iu);
    expect(parsedEvidence.evidenceAcknowledged).toBe(true);
    expect(parsedEvidence.fromDomain).toBe('mail.evidence.test');
    expect(parsedEvidence.evidence?.[0]).toEqual(
      expect.objectContaining({
        acknowledged: true,
        provenance: { correlation: 'unbound', source: 'manual' },
      }),
    );
    expect(parsedEvidence.evidence?.[0]?.qualification).toMatch(
      /not cryptographically bound/iu,
    );
    expect(parsedEvidence.resolver?.id).toBe('google');
  });

  it('makes hostile policy text visible while preserving exact record evidence', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    const user = userEvent.setup();
    const control = String.fromCodePoint(0x202e);
    const record = `v=DMARC1; p=none; x=literal \\u{202E}; y=${control}hidden`;
    const visible = String.raw`v=DMARC1; p=none; x=literal \\u{202E}; y=\u{202E}hidden`;
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText },
    });
    installDns({
      '_dmarc.control-text.test': { values: [record] },
    });
    render(<DmarcPage />);

    await user.type(screen.getByLabelText('Domain'), 'control-text.test');
    await user.click(screen.getByRole('button', { name: 'Inspect DMARC' }));

    const result = (
      await screen.findByRole('heading', { name: '_dmarc.control-text.test' })
    ).closest('article');
    if (result === null) throw new Error('Expected a DMARC policy result panel.');
    expect(within(result).getByText(visible, { selector: 'pre' })).toBeVisible();
    expect(result.textContent).not.toContain(control);
    expect(document.body.textContent).not.toContain(control);

    await user.click(within(result).getByRole('button', { name: 'Copy safe DMARC record' }));
    await user.click(
      within(result).getByRole('button', { name: 'Copy exact DMARC record as Base64' }),
    );
    await user.click(screen.getByRole('button', { name: 'Copy DMARC evidence JSON' }));
    await waitFor(() => expect(writeText).toHaveBeenCalledTimes(3));

    expect(writeText.mock.calls[0]?.[0]).toBe(visible);
    const exactBase64 = String(writeText.mock.calls[1]?.[0]);
    const exactBytes = Uint8Array.from(atob(exactBase64), (character) =>
      character.charCodeAt(0),
    );
    expect(new TextDecoder().decode(exactBytes)).toBe(record);
    const evidenceText = String(writeText.mock.calls[2]?.[0]);
    expect(evidenceText).not.toContain(control);
    const evidence = JSON.parse(evidenceText) as {
      discovery?: {
        selected?: {
          record?: string;
          recordRaw?: { encoding?: string; value?: string };
        };
      };
      textProjection?: string;
    };
    expect(evidence).toMatchObject({
      discovery: {
        selected: {
          record: visible,
          recordRaw: { encoding: 'base64', value: exactBase64 },
        },
      },
      textProjection: 'visible-escapes-v1',
    });
  });

  it.each([
    ['Visible From address domain', 'text'],
    ['Domains from passing DKIM signatures', 'text'],
    ['Previous SPF result', 'select'],
    ['Domain authenticated by SPF', 'text'],
  ] as const)(
    'invalidates a completed alignment result after %s changes',
    async (label, control) => {
      const user = userEvent.setup();
      installDns({
        '_dmarc.mail.stale-result.test': {
          values: ['v=DMARC1; p=reject; adkim=s; aspf=s'],
        },
      });
      render(<DmarcPage />);

      await user.click(screen.getByRole('button', { name: 'Alignment check' }));
      await user.type(
        screen.getByLabelText('Visible From address domain'),
        'mail.stale-result.test',
      );
      await user.type(
        screen.getByLabelText('Domains from passing DKIM signatures'),
        'mail.stale-result.test',
      );
      await user.click(
        screen.getByRole('checkbox', {
          name: /confirm these prior SPF and DKIM results belong/iu,
        }),
      );
      await user.click(screen.getByRole('button', { name: 'Check alignment' }));
      expect(await screen.findByRole('heading', { name: 'DMARC pass' })).toBeVisible();

      const input = screen.getByLabelText(label);
      if (control === 'select') await user.selectOptions(input, 'fail');
      else await user.type(input, 'x');

      expect(screen.queryByRole('heading', { name: 'DMARC pass' })).not.toBeInTheDocument();
      expect(
        screen.getByRole('checkbox', {
          name: /confirm these prior SPF and DKIM results belong/iu,
        }),
      ).not.toBeChecked();
    },
  );

  it('invalidates a completed policy report after its domain changes', async () => {
    const user = userEvent.setup();
    installDns({
      '_dmarc.stale-policy.test': { values: ['v=DMARC1; p=reject'] },
    });
    render(<DmarcPage />);

    await user.type(screen.getByLabelText('Domain'), 'stale-policy.test');
    await user.click(screen.getByRole('button', { name: 'Inspect DMARC' }));
    expect(await screen.findByRole('heading', { name: 'DMARC policy' })).toBeVisible();
    expect(screen.getByRole('button', { name: 'Copy DMARC evidence JSON' })).toBeVisible();

    await user.type(screen.getByLabelText('Domain'), 'x');

    expect(screen.queryByRole('heading', { name: 'DMARC policy' })).not.toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: 'Copy DMARC evidence JSON' }),
    ).not.toBeInTheDocument();
  });

  it('distinguishes a declared policy from the t=y disposition in UI and evidence', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    const user = userEvent.setup();
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText },
    });
    installDns({
      '_dmarc.testing-policy.test': {
        values: ['v=DMARC1; p=reject; t=y; psd=n'],
      },
    });
    render(<DmarcPage />);

    await user.type(screen.getByLabelText('Domain'), 'testing-policy.test');
    await user.click(screen.getByRole('button', { name: 'Inspect DMARC' }));

    const result = (
      await screen.findByRole('heading', {
        name: '_dmarc.testing-policy.test',
      })
    ).closest('article');
    if (result === null) throw new Error('Expected a DMARC policy result panel.');
    expect(within(result).getByText('reject')).toBeVisible();
    expect(within(result).getByText('quarantine')).toBeVisible();
    expect(
      within(result).getByText(/Testing mode reduces reject to quarantine/iu),
    ).toBeVisible();

    await user.click(screen.getByRole('button', { name: 'Copy DMARC evidence JSON' }));
    await waitFor(() => expect(writeText).toHaveBeenCalled());
    const evidence = JSON.parse(String(writeText.mock.calls[0]?.[0])) as {
      discovery?: { selected?: { assessment?: { appliedDisposition?: string } } };
    };
    expect(evidence.discovery?.selected?.assessment?.appliedDisposition).toBe('quarantine');
  });

  it('cancels an active DNS walk and does not render a partial result', async () => {
    const fetchMock = vi.fn<typeof fetch>(
      (_input, init) =>
        new Promise<Response>((_resolve, reject) => {
          const signal = init?.signal;
          const abort = () => reject(new DOMException('Aborted', 'AbortError'));
          if (signal?.aborted === true) abort();
          else signal?.addEventListener('abort', abort, { once: true });
        }),
    );
    vi.stubGlobal('fetch', fetchMock);
    const user = userEvent.setup();
    render(<DmarcPage />);

    await user.type(screen.getByLabelText('Domain'), 'cancel-route.test');
    await user.click(screen.getByRole('button', { name: 'Inspect DMARC' }));
    await user.click(await screen.findByRole('button', { name: 'Cancel' }));

    expect(await screen.findByText('The DMARC run was cancelled.')).toBeVisible();
    expect(screen.queryByRole('heading', { name: 'DMARC policy' })).not.toBeInTheDocument();
  });

  it('keeps material controls bound to the pending DMARC run', async () => {
    let finishRequest: (() => void) | undefined;
    let pendingRequest: Promise<Response> | undefined;
    let firstRequest = true;
    const fetchMock = vi.fn<typeof fetch>((input, init) => {
      if (!firstRequest)
        return Promise.resolve(
          response(requestBytes(input, init), { values: ['v=DMARC1; p=reject'] }),
        );
      firstRequest = false;
      pendingRequest = new Promise<Response>((resolve) => {
        finishRequest = () =>
          resolve(
            response(requestBytes(input, init), {
              values: ['v=DMARC1; p=reject'],
            }),
          );
      });
      return pendingRequest;
    });
    vi.stubGlobal('fetch', fetchMock);
    const user = userEvent.setup();
    render(<DmarcPage />);

    const domain = screen.getByLabelText('Domain');
    const resolver = screen.getByLabelText('Resolver');
    await user.type(domain, 'locked-dmarc.test');
    await user.selectOptions(resolver, 'cloudflare');
    await user.click(screen.getByRole('button', { name: 'Inspect DMARC' }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledOnce());

    expect(domain).toBeDisabled();
    expect(resolver).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Policy discovery' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Alignment check' })).toBeDisabled();
    expect(domain).toHaveValue('locked-dmarc.test');
    expect(resolver).toHaveValue('cloudflare');
    if (pendingRequest === undefined || finishRequest === undefined) {
      throw new Error('Expected the DMARC request to be pending.');
    }

    finishRequest();
    await pendingRequest;
    expect(await screen.findByRole('heading', { name: 'DMARC policy' })).toBeVisible();
    expect(screen.getByRole('heading', { name: '_dmarc.locked-dmarc.test' })).toBeVisible();
    expect(domain).toBeEnabled();
    expect(resolver).toBeEnabled();
  });
});
