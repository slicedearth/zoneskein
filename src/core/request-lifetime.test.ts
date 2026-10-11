import { expect, it } from 'vitest';
import { RequestLifetime } from './request-lifetime';

it('invalidates unmounted requests and permits fresh work after an effect setup cycle', () => {
  const lifetime = new RequestLifetime();
  expect(lifetime.active).toBe(false);
  lifetime.enter();
  const old = lifetime.capture();
  expect(lifetime.isCurrent(old)).toBe(true);
  lifetime.leave();
  lifetime.enter();
  expect(lifetime.isCurrent(old)).toBe(false);
  expect(lifetime.isCurrent(lifetime.capture())).toBe(true);
  const request = lifetime.invalidate();
  expect(lifetime.isCurrent(request)).toBe(true);
  lifetime.invalidate();
  expect(lifetime.isCurrent(request)).toBe(false);
});
