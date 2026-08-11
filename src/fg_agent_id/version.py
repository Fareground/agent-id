"""Spec and package versions.

``SPEC_VERSION`` names the wire specification this implementation targets
(see ``spec/SPEC.md``). ``DEFAULT_PROTOCOL_VERSION`` is the bare protocol
version stamped into signed agent cards by default; embedding protocols
(e.g. AMP) may pass their own version instead. The two must agree:
``SPEC_VERSION == f"amp/{DEFAULT_PROTOCOL_VERSION}"``.
"""

SPEC_VERSION = "amp/0.2"
DEFAULT_PROTOCOL_VERSION = "0.2"
PACKAGE_VERSION = "0.2.0"
