"""Error hierarchy for the agent-id standard."""


class AgentIdError(Exception):
    """Base class for all agent-id errors."""


class AddressError(AgentIdError):
    """Malformed or unresolvable agent address."""


class SignatureError(AgentIdError):
    """Signature failed verification."""


class CardError(AgentIdError):
    """Agent card is malformed and cannot be deserialized."""


class KeyFileError(AgentIdError, ValueError):
    """Key file cannot be read: wrong passphrase, wrong format, or corrupt.

    Also a ValueError so callers that caught the original ValueError-based
    failures keep working.
    """


class DelegationError(AgentIdError):
    """Delegation chain is invalid, expired, or lacks required scope."""


class SpendScopeError(DelegationError):
    """Spend scope is malformed, or a payment exceeds the chain's caps."""


class RotationError(AgentIdError):
    """Key-rotation history is invalid, out of order, or contradictory."""
