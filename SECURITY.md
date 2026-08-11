# Security Policy

fg-agent-id is identity infrastructure: a flaw here can undermine every
protocol built on top of it. Reports are taken seriously and handled quickly.

## Reporting a vulnerability

Email **sandro@corza.ai** with:

- A description of the issue and the affected artifact type (card,
  delegation, proof of possession, rotation, revocation, canonicalization).
- Reproduction steps or a proof-of-concept — a failing test against the
  golden vectors in `spec/vectors.json` is ideal.
- The versions affected (Python `fg-agent-id` and/or npm
  `@fareground/agent-id`).

Please do **not** open a public issue for security-relevant bugs. You will
get an acknowledgement within 72 hours and a fix or mitigation plan before
any public disclosure.

## Scope

In scope: signature verification bypasses, canonicalization ambiguity
(anything that lets two implementations sign different bytes for the same
payload), replay across signing contexts or audiences, delegation-scope
widening, rotation/revocation bypasses, and key-at-rest encryption flaws.

Out of scope: vulnerabilities in consumer applications, and denial of
service against example code.
