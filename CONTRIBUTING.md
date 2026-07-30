# Contributing to agent-id

Thanks for helping build self-certifying agent identity.

## Development

### Python (reference implementation)

```bash
python -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/python -m pytest        # full suite
.venv/bin/ruff check src tests    # lint
.venv/bin/ruff format src tests   # format
```

Ruff is the single source for lint and format (config in `pyproject.toml`:
`line-length = 100`, rules `E, F, I, UP, B`).

### TypeScript

```bash
cd js
npm install          # dev deps only (typescript, @types/node)
npm test             # tsc + full suite (conformance, round-trip, negative)
npm run conformance  # golden-vector conformance only
```

Both implementations must reproduce every golden vector in
[`spec/vectors.json`](spec/vectors.json) byte-for-byte.

## Ground rules

- **Boring cryptography only.** Use audited primitives (pyca `cryptography` in
  Python, WebCrypto in TypeScript). Do not invent crypto. New security-relevant
  behavior needs a test that demonstrates both the accept path and the reject
  path.
- **Dependency-light.** `cryptography` is the only Python runtime dependency and
  the TypeScript build has zero runtime dependencies. Keep it that way; anything
  heavier belongs in a consumer, not here.
- **Signatures are domain-separated.** Every signed artifact names the context
  it covers (`fg-agent-id/v1/<context>`). If you add an artifact type, give it
  its own context so a signature can never be replayed as a different kind.
- **Canonical bytes are the contract.** Signing input is
  `uint16be(len(tag)) || tag || canonical_json(payload)`. Any change to
  canonicalization is a wire-breaking change.

## Changing the wire format

The golden vectors in `spec/vectors.json` are what other implementations test
against. If you change signing, canonicalization, or the domain tag:

1. Update [`spec/SPEC.md`](spec/SPEC.md) to describe the new behavior.
2. Regenerate vectors: `python spec/generate_vectors.py`.
3. Bump `DEFAULT_PROTOCOL_VERSION` in `src/fg_agent_id/version.py`.
4. Call it out in the changelog — artifacts signed under the old version will
   no longer verify.

## Commits & pull requests

- Follow [Conventional Commits](https://www.conventionalcommits.org):
  `feat:`, `fix:`, `refactor:`, `docs:`, `test:`, `chore:`, `perf:`, `ci:`.
- Commits must **not** include AI/assistant co-author attribution or
  `Co-authored-by` trailers for AI tools.
- Keep the test suite green and add tests for what you changed.
- One concern per PR. Cryptographic changes get reviewed on their own.
