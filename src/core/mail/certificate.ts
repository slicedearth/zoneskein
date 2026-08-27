import { AsnParser, AsnSerializer } from '@peculiar/asn1-schema';
import { Certificate } from '@peculiar/asn1-x509';

export interface CertificateInspection {
  readonly extensions: readonly string[];
  readonly fingerprintSha256: string;
  readonly issuer: string;
  readonly notAfter: string;
  readonly notBefore: string;
  readonly publicKeyAlgorithm: string;
  readonly serialHex: string;
  readonly signatureAlgorithm: string;
  readonly spki: Uint8Array;
  readonly subject: string;
}

const NAME_OIDS: Readonly<Record<string, string>> = {
  '2.5.4.3': 'CN',
  '2.5.4.6': 'C',
  '2.5.4.7': 'L',
  '2.5.4.8': 'ST',
  '2.5.4.10': 'O',
  '2.5.4.11': 'OU',
};

function bytes(buffer: ArrayBuffer): Uint8Array {
  return new Uint8Array(buffer.slice(0));
}

function cryptoBytes(value: Uint8Array): Uint8Array<ArrayBuffer> {
  const copied = new Uint8Array(value.length);
  copied.set(value);
  return copied;
}

function hex(value: Uint8Array): string {
  return [...value]
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase();
}

function pemBytes(value: string): Uint8Array {
  const trimmed = value.trim();
  const containsPemBoundary = trimmed.includes('-----BEGIN') || trimmed.includes('-----END');
  const match = containsPemBoundary
    ? /^-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\r\n ]+?)\s*-----END CERTIFICATE-----$/u.exec(
        trimmed,
      )
    : null;
  if (containsPemBoundary && match === null)
    throw new Error('Enter exactly one PEM certificate without surrounding content.');
  const encoded = (match?.[1] ?? trimmed).replaceAll(/\s+/gu, '');
  if (
    encoded.length === 0 ||
    encoded.length > 131_072 ||
    !/^[A-Za-z0-9+/]+={0,2}$/u.test(encoded)
  )
    throw new Error('Enter one bounded PEM or Base64 DER certificate.');
  try {
    return Uint8Array.from(atob(encoded), (character) => character.charCodeAt(0));
  } catch (cause) {
    throw new Error('The certificate is not valid Base64.', { cause });
  }
}

function name(value: Certificate['tbsCertificate']['subject']): string {
  return value
    .flatMap((rdn) =>
      [...rdn].map(
        (attribute) =>
          `${NAME_OIDS[attribute.type] ?? attribute.type}=${attribute.value.toString()}`,
      ),
    )
    .join(', ');
}

export async function inspectCertificate(
  value: string,
): Promise<{ readonly der: Uint8Array; readonly inspection: CertificateInspection }> {
  const der = pemBytes(value);
  if (der.length > 64 * 1024)
    throw new Error('The DER certificate exceeds the 64 KiB safety limit.');
  let certificate: Certificate;
  try {
    certificate = AsnParser.parse(der, Certificate);
  } catch (cause) {
    throw new Error('The certificate is not valid bounded X.509 DER.', { cause });
  }
  const spki = bytes(AsnSerializer.serialize(certificate.tbsCertificate.subjectPublicKeyInfo));
  const fingerprint = bytes(await crypto.subtle.digest('SHA-256', cryptoBytes(der)));
  return {
    der,
    inspection: {
      extensions: (certificate.tbsCertificate.extensions ?? []).map(
        (extension) => extension.extnID,
      ),
      fingerprintSha256: hex(fingerprint),
      issuer: name(certificate.tbsCertificate.issuer),
      notAfter: certificate.tbsCertificate.validity.notAfter.getTime().toISOString(),
      notBefore: certificate.tbsCertificate.validity.notBefore.getTime().toISOString(),
      publicKeyAlgorithm: certificate.tbsCertificate.subjectPublicKeyInfo.algorithm.algorithm,
      serialHex: hex(bytes(certificate.tbsCertificate.serialNumber)),
      signatureAlgorithm: certificate.signatureAlgorithm.algorithm,
      spki,
      subject: name(certificate.tbsCertificate.subject),
    },
  };
}

export async function verifyTlsaAssociation(
  record: string,
  der: Uint8Array,
  spki: Uint8Array,
): Promise<{ readonly matches: boolean; readonly reason: string }> {
  const parts = record.trim().split(/\s+/u);
  if (parts.length !== 4)
    return {
      matches: false,
      reason: 'TLSA input must contain usage, selector, matching type, and association data.',
    };
  const [usageText, selectorText, matchingText, associationText] = parts;
  if (
    usageText === undefined ||
    selectorText === undefined ||
    matchingText === undefined ||
    associationText === undefined ||
    !/^[0-3]$/u.test(usageText) ||
    !/^[01]$/u.test(selectorText) ||
    !/^[0-2]$/u.test(matchingText) ||
    !/^[0-9A-Fa-f]+$/u.test(associationText) ||
    associationText.length % 2 !== 0
  )
    return {
      matches: false,
      reason:
        'The TLSA fields are outside the supported RFC 6698 ranges or the association is not hexadecimal.',
    };
  const selected = selectorText === '0' ? der : spki;
  const compared =
    matchingText === '0'
      ? selected
      : bytes(
          await crypto.subtle.digest(
            matchingText === '1' ? 'SHA-256' : 'SHA-512',
            cryptoBytes(selected),
          ),
        );
  if (associationText.length !== compared.length * 2)
    return {
      matches: false,
      reason: `TLSA matching type ${matchingText} requires exactly ${String(compared.length * 2)} hexadecimal characters.`,
    };
  const expected = associationText.toUpperCase();
  return {
    matches: hex(compared) === expected,
    reason:
      hex(compared) === expected
        ? 'The selected certificate bytes match the supplied TLSA association.'
        : 'The selected certificate bytes do not match the supplied TLSA association.',
  };
}
