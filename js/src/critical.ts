/**
 * Criticality: a signed artifact MAY carry a `critical` list of field names
 * that a verifier must understand to accept it. Unknown fields are normally
 * preserved-and-signed but not understood; naming one in `critical` turns
 * "tolerated" into "understood-or-rejected".
 */

import { SignatureError } from "./errors.js";

/** Validate a wire `critical` value into a string array (or undefined). */
export function parseCritical(value: unknown): string[] | undefined {
  if (value === undefined || value === null) return undefined;
  if (!Array.isArray(value) || value.some((v) => typeof v !== "string")) {
    throw new TypeError("critical must be a list of field names");
  }
  return [...(value as string[])];
}

/**
 * Enforce criticality: every name in `critical` must be a field this
 * implementation understands (`known`), plus any caller-supplied extension
 * names it explicitly handles (`understood`).
 */
export function enforceCritical(
  critical: readonly string[] | undefined,
  known: ReadonlySet<string>,
  understood: Iterable<string> = []
): void {
  if (!critical) return;
  const accepted = new Set([...known, ...understood, "critical"]);
  const unrecognized = critical.filter((name) => !accepted.has(name));
  if (unrecognized.length > 0) {
    throw new SignatureError(
      `artifact marks fields critical that this implementation does not ` +
        `understand: ${unrecognized.sort().join(", ")}`
    );
  }
}
