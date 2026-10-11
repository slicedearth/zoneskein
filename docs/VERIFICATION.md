# Offline verification corpus

The deterministic suite uses synthetic data and does not contact DNS resolvers.

| Corpus                                                                   | Evidence and scope                                                                                                                                                                                                                                                                    |
| ------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/core/spf/grammar-corpus.test.ts`                                    | Fixed grammar cases and seeded qualifier combinations shared across parser, analyser, sender and flattener. Successful address and MX fixtures must not conceal invalid syntax.                                                                                                       |
| `src/core/dnssec/published-vectors.test.ts`                              | Published RFC 5702, 6605 and 8080 key material; separately generated immutable DNSKEY signatures and signed bytes; DS digest and canonicalisation fixtures. These generated signatures are not verbatim RFC signatures. The corrected RFC 8080 Ed448 vector is identified separately. |
| `src/core/dnssec/chain.test.ts`, `denial.test.ts`, `application.test.ts` | Synthetic signed delegation, exact denial, Opt-Out uncertainty, positive/negative application and alias-continuation paths. This is bounded proof-branch coverage, not certification as a recursive resolver.                                                                         |
| `src/core/zone/zonemd.test.ts`                                           | RFC 8976 SIMPLE/complex examples, numeric aliases, exclusion rules, duplicates, fixed-wire origin and escaped-name cases.                                                                                                                                                             |
| `src/core/zone/canonical-wire.test.ts`                                   | Independently assembled fixed RDATA bytes for MX, escaped CNAME, binary TXT and whitespace-bearing NAPTR. Not RFC signature vectors.                                                                                                                                                  |
| `src/core/zone/export-conformance.test.ts`                               | Exact TXT byte/chunk roundtrips, split boundaries, malformed output and Unicode preservation. Record Studio and SPF withhold output when conformance fails.                                                                                                                           |

RFC-derived test data retains the IETF notices in `THIRD_PARTY_NOTICES.md`. Original synthetic cases use the project licence. Live resolver observations are not substituted for these fixtures.

The immutable DNSKEY corpus exercises algorithms 5, 7, 8, 10, 13, 14 and 15; the separate corrected RFC 8080 MX vector exercises algorithm 16. The short RSA keys for algorithms 5, 7 and 8 are rejected under the current key-strength policy, not counted as successful signature validation. Published DS examples cover digest types 1, 2 and 4. Original RFC key material and independently generated DNSKEY signatures remain distinct evidence.

The synthetic proof corpus covers signed delegation chains, wrong-owner/class/section and modified-RRset rejection, exact positive application RRsets, CNAME continuation, exact NSEC/NSEC3 DS denial, NSEC empty non-terminals and DNAME boundaries, NSEC3 Opt-Out uncertainty and shared work-budget exhaustion. It does not turn an unsupported proof, missing evidence or an Opt-Out interval into authenticated existence. These tests do not establish interoperability against every authoritative server, cryptographic implementation or DNSSEC proof form.

## Reproducing bounded timing samples

With the locked dependencies and supported Node/npm toolchain, run:

```sh
npm test -- src/test/responsiveness.test.ts --maxWorkers=1
```

The output records Node's version, five parse/comparison/planning samples at 4,096 records, and one 16-signature/32-candidate DNSSEC verification sample. Record the CPU and operating system alongside the output. Timings are observations, not pass thresholds or device guarantees. Cryptographic backend scheduling, CPU power mode and concurrent work affect them.

For a low-powered device, build and serve the same source, open Change Lab locally, and paste 4,096 synthetic `hostN.example.test. 300 IN A 192.0.2.1` records into the current field with `.2` addresses in the proposed field. Record a browser Performance trace from Compare snapshots until the results paint, five times after one warm-up. Record device, browser, power mode, peak main-thread task time and time to next keyboard response. Repeat at 320 CSS pixels. CPU throttling on a desktop is a separate simulation, not a physical-device measurement. Do not increase supported limits to make a benchmark appear more capable.

The populated browser accessibility cases include large Change Lab output, imported integrity quarantine, malformed SPF evidence and untrusted DNSSEC key evidence, with keyboard operation, light/dark reflow, forced colours and reduced motion. Automated checks do not replace screen-reader or physical-device testing.
