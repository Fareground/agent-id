"""A persistent identity in one line, then a signed, self-verifying card.

`load_or_create` mints a keypair on the first run and reloads it on every
later one — run this file twice and the addresses match. Then an owner
(cold key) mints an agent (hot key) with scoped authority, the agent
publishes a card, and any peer verifies it with no registry in sight.

Run (after `pip install -e .` from the repo root):

    python examples/python/01_identity.py
"""

import tempfile
from pathlib import Path

from fg_agent_id import AgentCard, AgentIdentity, OwnerIdentity

# --- Hello, identity: the one-liner (persisted; same address every run) ---
key_path = Path(tempfile.gettempdir()) / "fg-example-agent.key"
me = AgentIdentity.load_or_create(key_path)  # pass a passphrase to seal at rest
print(f"persistent id : {me.address}")
assert AgentIdentity.load_or_create(key_path).address == me.address

# --- An owner stands behind an agent ---
owner = OwnerIdentity.generate("acme-corp")
agent = owner.create_agent("acme-buyer", scopes={"converse", "negotiate"})

# The agent publishes a signed card describing itself.
card = agent.card(endpoints={"http": "https://buyer.example/inbox"})
print(f"agent address : {agent.address}")
print(f"agent DID     : {card.did}")
print(f"operator      : {card.operator}")

# A peer receives the card as JSON and verifies it — the address IS the key.
received = AgentCard.from_json(card.to_json())
received.verify()
print("card verifies : yes (self-certifying, no registry)")

# The delegation chain proves who stands behind the agent, and with what
# authority. Scopes are the intersection of every link.
scopes = agent.delegation_chain.verify(agent.address)
print(f"owner grants  : {sorted(scopes)} (rooted at {agent.delegation_chain.root_issuer})")
assert agent.delegation_chain.root_issuer == owner.address
