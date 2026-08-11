"""Issue and verify a signed agent card.

An owner (cold key) mints an agent (hot key) with scoped authority, the
agent publishes a self-verifying card, and any peer verifies both the card
and the delegation chain with no registry in sight.

Run (after `pip install -e .` from the repo root):

    python examples/python/01_identity.py
"""

from fg_agent_id import AgentCard, OwnerIdentity

owner = OwnerIdentity.generate("acme-corp")
agent = owner.create_agent("acme-buyer", scopes={"converse", "negotiate"})

# The agent publishes a signed card describing itself.
card = agent.card(endpoints={"http": "https://buyer.example/inbox"})
print(f"agent address : {agent.address}")
print(f"agent DID     : {card.did}")
print(f"operator      : {card.operator}")

# A peer receives the card as JSON and verifies it — the address IS the key.
received = AgentCard.model_validate(card.model_dump())
received.verify()
print("card verifies : yes (self-certifying, no registry)")

# The delegation chain proves who stands behind the agent, and with what
# authority. Scopes are the intersection of every link.
scopes = agent.delegation_chain.verify(agent.address)
print(f"owner grants  : {sorted(scopes)} (rooted at {agent.delegation_chain.root_issuer})")
assert agent.delegation_chain.root_issuer == owner.address
