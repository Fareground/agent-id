"""Key rotation with pre-rotation commitments.

An identity keeps one stable name (its inception address) while the key in
force changes. Each record commits in advance to the digest of the NEXT
key, so stealing the current key is not enough to hijack the identity.

Run (after `pip install -e .` from the repo root):

    python examples/python/03_key_rotation.py
"""

from fg_agent_id import RotatingIdentity, RotationRegistry

identity = RotatingIdentity.create()  # current keys + a pre-committed next key
print(f"stable name   : {identity.identity}")
print(f"key in force  : {identity.address}")

rotated = identity.rotate()  # promote the next key, commit to a fresh one
print(f"after rotate  : {rotated.address}")
assert rotated.identity == identity.identity  # the name never changes
assert rotated.address != identity.address  # the key in force does

# Verifier side: learn the chain, resolve the stable name to the live key.
registry = RotationRegistry()
registry.learn(rotated.chain)
assert registry.resolve(identity.identity) == rotated.address
print(f"resolves to   : {registry.resolve(identity.identity)}")

# Rotate again — same name, third key.
again = rotated.rotate()
registry.learn(again.chain)
assert registry.resolve(identity.identity) == again.address
print(f"second rotate : {again.address} (name unchanged)")
