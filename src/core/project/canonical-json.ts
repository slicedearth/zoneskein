import { failure, success, type Result } from '../result';
import { CHANGE_WORKSPACE_LIMITS } from './limits';
import type { ChangeWorkspaceCodecError } from './types';

const encoder = new TextEncoder();

function codecFailure(
  code: ChangeWorkspaceCodecError['code'],
  message: string,
  path?: string,
): Result<never, ChangeWorkspaceCodecError> {
  return failure({ code, message, ...(path === undefined ? {} : { path }) });
}

function hasUnpairedSurrogate(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const following = value.charCodeAt(index + 1);
      if (!(following >= 0xdc00 && following <= 0xdfff)) return true;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) return true;
  }
  return false;
}

function pathForKey(path: string, key: string): string {
  return /^[A-Za-z_$][A-Za-z0-9_$]*$/u.test(key)
    ? `${path}.${key}`
    : `${path}[${JSON.stringify(key)}]`;
}

class CanonicalJsonWriter {
  readonly #ancestors = new WeakSet<object>();
  #octets = 0;
  #values = 0;

  write(value: unknown, path = '$', depth = 0): Result<string, ChangeWorkspaceCodecError> {
    this.#values += 1;
    if (this.#values > CHANGE_WORKSPACE_LIMITS.jsonValues) {
      return codecFailure(
        'resource-limit',
        `JSON input exceeds the ${String(CHANGE_WORKSPACE_LIMITS.jsonValues)}-value safety limit.`,
        path,
      );
    }
    if (depth > CHANGE_WORKSPACE_LIMITS.jsonDepth) {
      return codecFailure(
        'resource-limit',
        `JSON input exceeds the ${String(CHANGE_WORKSPACE_LIMITS.jsonDepth)}-level depth safety limit.`,
        path,
      );
    }
    if (value === null) return this.#literal('null', path);
    if (typeof value === 'boolean') return this.#literal(value ? 'true' : 'false', path);
    if (typeof value === 'string') return this.#string(value, path);
    if (typeof value === 'number') {
      if (!Number.isSafeInteger(value) || Object.is(value, -0)) {
        return codecFailure(
          'unsupported-value',
          'JSON numbers must be finite safe integers and must not be negative zero.',
          path,
        );
      }
      return this.#literal(String(value), path);
    }
    if (typeof value !== 'object') {
      return codecFailure(
        'unsupported-value',
        `JSON input contains an unsupported ${typeof value} value.`,
        path,
      );
    }
    return Array.isArray(value)
      ? this.#array(value, path, depth)
      : this.#object(value, path, depth);
  }

  #consume(octets: number, path: string): Result<true, ChangeWorkspaceCodecError> {
    this.#octets += octets;
    if (this.#octets > CHANGE_WORKSPACE_LIMITS.jsonOctets) {
      return codecFailure(
        'resource-limit',
        `Canonical JSON exceeds the ${String(CHANGE_WORKSPACE_LIMITS.jsonOctets)}-octet safety limit.`,
        path,
      );
    }
    return success(true);
  }

  #literal(value: string, path: string): Result<string, ChangeWorkspaceCodecError> {
    const consumed = this.#consume(value.length, path);
    return consumed.ok ? success(value) : consumed;
  }

  #string(value: string, path: string): Result<string, ChangeWorkspaceCodecError> {
    if (hasUnpairedSurrogate(value)) {
      return codecFailure(
        'unsupported-value',
        'JSON strings must not contain unpaired UTF-16 surrogates.',
        path,
      );
    }
    if (encoder.encode(value).length > CHANGE_WORKSPACE_LIMITS.jsonStringOctets) {
      return codecFailure(
        'resource-limit',
        `A JSON string exceeds the ${String(CHANGE_WORKSPACE_LIMITS.jsonStringOctets)}-octet safety limit.`,
        path,
      );
    }
    const serialised = JSON.stringify(value);
    const consumed = this.#consume(encoder.encode(serialised).length, path);
    return consumed.ok ? success(serialised) : consumed;
  }

  #enter(value: object, path: string): Result<true, ChangeWorkspaceCodecError> {
    if (this.#ancestors.has(value)) {
      return codecFailure('unsupported-value', 'JSON input must not contain cycles.', path);
    }
    this.#ancestors.add(value);
    return success(true);
  }

  #array(
    value: readonly unknown[],
    path: string,
    depth: number,
  ): Result<string, ChangeWorkspaceCodecError> {
    if (Object.getPrototypeOf(value) !== Array.prototype) {
      return codecFailure(
        'unsupported-value',
        'JSON arrays must use the ordinary array prototype.',
        path,
      );
    }
    if (value.length > CHANGE_WORKSPACE_LIMITS.collectionItems) {
      return codecFailure(
        'resource-limit',
        `A JSON collection exceeds the ${String(CHANGE_WORKSPACE_LIMITS.collectionItems)}-item safety limit.`,
        path,
      );
    }
    const entered = this.#enter(value, path);
    if (!entered.ok) return entered;
    try {
      const punctuation = this.#consume(2 + Math.max(0, value.length - 1), path);
      if (!punctuation.ok) return punctuation;
      const ownKeys = Reflect.ownKeys(value);
      if (
        ownKeys.length !== value.length + 1 ||
        ownKeys.some(
          (key) =>
            typeof key !== 'string' || (key !== 'length' && !/^(?:0|[1-9]\d*)$/u.test(key)),
        )
      ) {
        return codecFailure(
          'unsupported-value',
          'JSON arrays must not contain symbol or named properties.',
          path,
        );
      }
      const parts: string[] = [];
      for (let index = 0; index < value.length; index += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
        if (descriptor === undefined) {
          return codecFailure(
            'unsupported-value',
            'JSON arrays must not contain empty slots.',
            `${path}[${String(index)}]`,
          );
        }
        if (!('value' in descriptor)) {
          return codecFailure(
            'unsupported-value',
            'JSON input must not contain accessor properties.',
            `${path}[${String(index)}]`,
          );
        }
        const item = this.write(descriptor.value, `${path}[${String(index)}]`, depth + 1);
        if (!item.ok) return item;
        parts.push(item.value);
      }
      return success(`[${parts.join(',')}]`);
    } finally {
      this.#ancestors.delete(value);
    }
  }

  #object(
    value: object,
    path: string,
    depth: number,
  ): Result<string, ChangeWorkspaceCodecError> {
    const prototype: unknown = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      return codecFailure(
        'unsupported-value',
        'JSON objects must be plain data objects.',
        path,
      );
    }
    const entered = this.#enter(value, path);
    if (!entered.ok) return entered;
    try {
      const ownKeys = Reflect.ownKeys(value);
      if (ownKeys.length > CHANGE_WORKSPACE_LIMITS.collectionItems) {
        return codecFailure(
          'resource-limit',
          `A JSON collection exceeds the ${String(CHANGE_WORKSPACE_LIMITS.collectionItems)}-item safety limit.`,
          path,
        );
      }
      if (ownKeys.some((key) => typeof key !== 'string')) {
        return codecFailure(
          'unsupported-value',
          'JSON objects must not contain symbol keys.',
          path,
        );
      }
      const keys = (ownKeys as string[]).sort((left, right) =>
        left < right ? -1 : left > right ? 1 : 0,
      );
      const punctuation = this.#consume(2 + Math.max(0, keys.length - 1), path);
      if (!punctuation.ok) return punctuation;
      const parts: string[] = [];
      for (const key of keys) {
        if (hasUnpairedSurrogate(key)) {
          return codecFailure(
            'unsupported-value',
            'JSON object keys must not contain unpaired UTF-16 surrogates.',
            path,
          );
        }
        if (encoder.encode(key).length > CHANGE_WORKSPACE_LIMITS.jsonKeyOctets) {
          return codecFailure(
            'resource-limit',
            `A JSON object key exceeds the ${String(CHANGE_WORKSPACE_LIMITS.jsonKeyOctets)}-octet safety limit.`,
            path,
          );
        }
        const serialisedKey = JSON.stringify(key);
        const keyOctets = this.#consume(encoder.encode(serialisedKey).length + 1, path);
        if (!keyOctets.ok) return keyOctets;
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        if (!descriptor?.enumerable) {
          return codecFailure(
            'unsupported-value',
            'JSON objects must contain only enumerable data properties.',
            pathForKey(path, key),
          );
        }
        if (!('value' in descriptor)) {
          return codecFailure(
            'unsupported-value',
            'JSON input must not contain accessor properties.',
            pathForKey(path, key),
          );
        }
        const item = this.write(descriptor.value, pathForKey(path, key), depth + 1);
        if (!item.ok) return item;
        parts.push(`${serialisedKey}:${item.value}`);
      }
      return success(`{${parts.join(',')}}`);
    } finally {
      this.#ancestors.delete(value);
    }
  }
}

export function canonicalJson(value: unknown): Result<string, ChangeWorkspaceCodecError> {
  return new CanonicalJsonWriter().write(value);
}
