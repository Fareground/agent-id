/**
 * Canonical JSON serialization for signing — byte-identical to the Python
 * reference (`json.dumps(sort_keys=True, separators=(",",":"),
 * ensure_ascii=False)` followed by NFC normalization of the output text).
 *
 * Deterministic bytes for any JSON-compatible structure: keys sorted by
 * Unicode code point, no insignificant whitespace, UTF-8, NFC, no
 * NaN/Infinity, and no floats — float formatting differs across languages and
 * would break cross-implementation signature agreement.
 */

import { utf8Encode } from "./bytes.js";

export type JsonValue =
  | null
  | boolean
  | number
  | bigint
  | string
  | JsonValue[]
  | { [key: string]: JsonValue };

/** Compare strings by Unicode code point (Python `str` ordering), not by
 * UTF-16 code unit (JS default sort), which diverges beyond U+FFFF. */
export function compareCodePoints(a: string, b: string): number {
  const ia = a[Symbol.iterator]();
  const ib = b[Symbol.iterator]();
  for (;;) {
    const ra = ia.next();
    const rb = ib.next();
    if (ra.done && rb.done) return 0;
    if (ra.done) return -1;
    if (rb.done) return 1;
    const ca = ra.value.codePointAt(0)!;
    const cb = rb.value.codePointAt(0)!;
    if (ca !== cb) return ca - cb;
  }
}

/**
 * Serialize one JSON string exactly as Python's json.dumps(ensure_ascii=False)
 * does: escape `"` and `\`, use the two-character escapes for control
 * characters that have them, and \u00xx for the rest. JSON.stringify matches
 * this behavior for BMP text, but is used here explicitly so the contract is
 * visible and pinned. NFC-normalize first (the Python reference normalizes
 * the full output text; quoting is NFC-stable so per-string is equivalent).
 */
function encodeString(value: string): string {
  return JSON.stringify(value.normalize("NFC"));
}

function encodeNumber(value: number | bigint): string {
  if (typeof value === "bigint") return value.toString();
  if (!Number.isFinite(value)) {
    throw new Error("NaN/Infinity are not allowed in canonical JSON");
  }
  if (!Number.isInteger(value)) {
    throw new Error(
      "floats are not allowed in canonical (signed) payloads — " +
        "use an integer (e.g. milliseconds) or a string"
    );
  }
  if (!Number.isSafeInteger(value)) {
    throw new Error(
      "integer exceeds Number.MAX_SAFE_INTEGER — pass a bigint for exactness"
    );
  }
  // Integer-valued numbers print without exponent or trailing ".0" in both
  // languages; -0 must render as "0" (Python has no int -0).
  return String(value === 0 ? 0 : value);
}

function canonicalize(value: JsonValue): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "number":
    case "bigint":
      return encodeNumber(value);
    case "string":
      return encodeString(value);
  }
  if (Array.isArray(value)) {
    return "[" + value.map(canonicalize).join(",") + "]";
  }
  if (typeof value === "object") {
    // Sort the ORIGINAL keys by code point (as Python sorts before its
    // whole-text NFC pass), then emit each key NFC-normalized.
    const keys = Object.keys(value).sort(compareCodePoints);
    return (
      "{" +
      keys.map((k) => encodeString(k) + ":" + canonicalize(value[k]!)).join(",") +
      "}"
    );
  }
  throw new Error(`unsupported type in canonical JSON: ${typeof value}`);
}

/** Deterministic bytes for signing. */
export function canonicalJson(data: JsonValue): Uint8Array {
  return utf8Encode(canonicalize(data));
}
