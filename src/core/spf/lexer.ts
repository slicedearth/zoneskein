import type { SourceLocation } from './types';

export interface SpfToken {
  readonly location: SourceLocation;
  readonly text: string;
}

export function lexSpf(record: string): readonly SpfToken[] {
  const tokens: SpfToken[] = [];
  let start = -1;
  for (let index = 0; index <= record.length; index += 1) {
    const character = record[index];
    const separator = character === undefined || character === ' ';
    if (!separator && start < 0) start = index;
    if (separator && start >= 0) {
      tokens.push({
        location: { end: index, start },
        text: record.slice(start, index),
      });
      start = -1;
    }
  }
  return tokens;
}
