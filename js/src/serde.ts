/** Timestamp handling pinned to the wire format (§3.2 of the spec).
 *
 * Timestamps inside signed payloads are RFC 3339 UTC with exactly three
 * fractional digits and a `Z` suffix. JS `Date` is already millisecond
 * precision and `toISOString()` emits exactly this spelling, so the work here
 * is validation: reject timezone-naive input and normalize offsets to UTC.
 */

export function canonicalTimestamp(value: Date): string {
  if (Number.isNaN(value.getTime())) throw new Error("invalid Date");
  return value.toISOString();
}

const OFFSET_RE =
  /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(\.\d+)?(Z|z|[+-]\d{2}:?\d{2})$/;

/**
 * Parse an RFC 3339 / ISO-8601 timestamp. Rejects timezone-naive input
 * (naive datetimes are ambiguous) and truncates — not rounds — fractional
 * seconds to milliseconds, matching the Python reference.
 */
export function parseTimestamp(name: string, value: string | Date): Date {
  if (value instanceof Date) {
    if (Number.isNaN(value.getTime())) throw new Error(`${name} is an invalid Date`);
    return value;
  }
  if (typeof value !== "string") {
    throw new TypeError(`${name} must be a Date or ISO-8601 string`);
  }
  const match = OFFSET_RE.exec(value);
  if (!match) {
    throw new Error(
      `${name} must be an ISO-8601 datetime carrying a timezone offset: ${JSON.stringify(value)}`
    );
  }
  const [, y, mo, d, h, mi, s, frac, offset] = match;
  // Truncate fractional seconds to milliseconds (pad to at least 3 digits).
  const ms = frac ? Number((frac.slice(1) + "000").slice(0, 3)) : 0;
  let epoch = Date.UTC(Number(y), Number(mo) - 1, Number(d), Number(h), Number(mi), Number(s), ms);
  if (offset !== "Z" && offset !== "z") {
    const sign = offset!.startsWith("-") ? -1 : 1;
    const [oh, om] = offset!.slice(1).replace(":", "").match(/^(\d{2})(\d{2})$/)!.slice(1);
    epoch -= sign * (Number(oh) * 60 + Number(om)) * 60_000;
  }
  const parsed = new Date(epoch);
  if (Number.isNaN(parsed.getTime())) throw new Error(`${name} is not a valid datetime: ${value}`);
  return parsed;
}

export function requireString(name: string, value: unknown): string {
  if (typeof value !== "string") {
    throw new TypeError(`${name} must be a string, got ${typeof value}`);
  }
  return value;
}

export function requireMapping(name: string, value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError(`${name} must be a plain object`);
  }
  return value as Record<string, unknown>;
}
