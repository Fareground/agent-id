"""Proof of possession: an audience-bound challenge/response round-trip.

The verifier issues a single-use challenge naming ITS OWN identifier as the
audience; the agent signs it; the verifier consumes the challenge (single
use) and checks the response against its own audience string — so a proof
collected by one service can never be replayed to another.

Run (after `pip install -e .` from the repo root):

    python examples/python/02_proof_of_possession.py
"""

from fg_agent_id import AgentIdentity, ChallengeStore

agent = AgentIdentity.generate("prover")

# Verifier side: issue a challenge bound to this verifier's identity.
store = ChallengeStore()
challenge = store.issue(audience="https://verifier.example")
print(f"challenge id  : {challenge.challenge_id}")

# Agent side: sign the challenge with the identity key.
response = challenge.respond(agent.keys, agent.address)

# Verifier side: consume (single use), then verify against OUR audience —
# never the audience the response claims.
issued = store.consume(response.challenge_id)
assert issued is not None
address = response.verify(issued, audience="https://verifier.example")
print(f"proved holder : {address}")
assert address == agent.address

# The challenge is gone now: a second use fails.
assert store.consume(response.challenge_id) is None
print("replay        : blocked (challenge is single-use)")
