/** Route-local generations fence asynchronous callbacks, including StrictMode remounts. */
export class RequestLifetime {
  #active = false;
  #generation = 0;

  get active(): boolean {
    return this.#active;
  }
  capture(): number {
    return this.#generation;
  }
  enter(): void {
    this.#active = true;
  }
  invalidate(): number {
    this.#generation += 1;
    return this.#generation;
  }
  leave(): void {
    this.#active = false;
    this.invalidate();
  }
  isCurrent(generation: number): boolean {
    return this.#active && this.#generation === generation;
  }
}
