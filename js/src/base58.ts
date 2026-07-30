/** Base58 (Bitcoin alphabet), byte-identical to the Python reference. */

const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export function base58Encode(data: Uint8Array): string {
  let num = 0n;
  for (const byte of data) num = num * 256n + BigInt(byte);
  let encoded = "";
  while (num > 0n) {
    encoded = ALPHABET[Number(num % 58n)]! + encoded;
    num /= 58n;
  }
  let pad = 0;
  for (const byte of data) {
    if (byte === 0) pad++;
    else break;
  }
  return "1".repeat(pad) + encoded;
}

export function base58Decode(text: string): Uint8Array {
  let num = 0n;
  for (const char of text) {
    const index = ALPHABET.indexOf(char);
    if (index < 0) throw new Error(`invalid base58 character: ${char}`);
    num = num * 58n + BigInt(index);
  }
  const bytes: number[] = [];
  while (num > 0n) {
    bytes.unshift(Number(num % 256n));
    num /= 256n;
  }
  let pad = 0;
  for (const char of text) {
    if (char === "1") pad++;
    else break;
  }
  return new Uint8Array([...new Array(pad).fill(0), ...bytes]);
}
