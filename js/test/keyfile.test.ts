/** Key files on disk: loadOrCreate, both formats, error UX — mirroring
 * tests/test_keyfile.py. Cross-language byte-compat (Python writes → TS
 * loads) is exercised from the Python suite, which shells out to this build. */

import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  AgentIdentity,
  KeyFileError,
  OwnerIdentity,
  loadKeys,
  loadOrCreateKeys,
  saveKeys,
} from "../src/index.js";

async function withTmp(run: (dir: string) => Promise<void>) {
  const dir = await mkdtemp(join(tmpdir(), "fgid-keyfile-"));
  try {
    await run(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

test("loadOrCreate round trip, plain format", async () => {
  await withTmp(async (dir) => {
    const path = join(dir, "agent.key");
    const first = await AgentIdentity.loadOrCreate(path);
    const again = await AgentIdentity.loadOrCreate(path);
    assert.equal(again.address, first.address);
    assert.equal(again.name, "agent"); // defaults to the file stem
    assert.equal((await readFile(path)).length, 64); // raw 64-byte form
  });
});

test("loadOrCreate round trip, encrypted format", async () => {
  await withTmp(async (dir) => {
    const path = join(dir, "sealed.key");
    const first = await AgentIdentity.loadOrCreate(path, "open sesame");
    const again = await AgentIdentity.loadOrCreate(path, "open sesame");
    assert.equal(again.address, first.address);
    assert.equal((await readFile(path)).subarray(0, 4).toString(), "FGID");
  });
});

test("owner loadOrCreate and custom name", async () => {
  await withTmp(async (dir) => {
    const path = join(dir, "owner.key");
    const owner = await OwnerIdentity.loadOrCreate(path, null, { name: "acme" });
    assert.equal(owner.name, "acme");
    assert.equal((await OwnerIdentity.loadOrCreate(path)).address, owner.address);
  });
});

test("wrong passphrase is a friendly error", async () => {
  await withTmp(async (dir) => {
    const path = join(dir, "sealed.key");
    await AgentIdentity.loadOrCreate(path, "right");
    await assert.rejects(
      AgentIdentity.loadOrCreate(path, "wrong"),
      (err: unknown) => err instanceof KeyFileError && /wrong passphrase or corrupt/.test(String(err))
    );
  });
});

test("encrypted file without a passphrase says so", async () => {
  await withTmp(async (dir) => {
    const path = join(dir, "sealed.key");
    await AgentIdentity.loadOrCreate(path, "secret");
    await assert.rejects(AgentIdentity.loadOrCreate(path), /is encrypted — pass the passphrase/);
  });
});

test("plain file with a passphrase refuses to guess", async () => {
  await withTmp(async (dir) => {
    const path = join(dir, "plain.key");
    await AgentIdentity.loadOrCreate(path);
    await assert.rejects(
      AgentIdentity.loadOrCreate(path, "secret"),
      /is not encrypted, but a passphrase/
    );
  });
});

test("corrupt file is a friendly error", async () => {
  await withTmp(async (dir) => {
    const path = join(dir, "broken.key");
    await writeFile(path, new Uint8Array([1, 2, 3]));
    await assert.rejects(loadKeys(path), /corrupt/);
  });
});

test("bare key helpers round-trip both formats", async () => {
  await withTmp(async (dir) => {
    const keys = await loadOrCreateKeys(join(dir, "bare.key"));
    const reloaded = await loadKeys(join(dir, "bare.key"));
    assert.ok(reloaded.equals(keys));
    await saveKeys(keys, join(dir, "copy.key"), "p");
    assert.ok((await loadKeys(join(dir, "copy.key"), "p")).equals(keys));
  });
});
