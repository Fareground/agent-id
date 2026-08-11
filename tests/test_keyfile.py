"""Key files on disk: load_or_create, both formats, and the error UX."""

import shutil
import stat
import subprocess
from pathlib import Path

import pytest

from fg_agent_id import (
    AgentIdentity,
    OwnerIdentity,
    load_keys,
    load_or_create_keys,
    save_keys,
)
from fg_agent_id.card import ParticipantKind


def test_load_or_create_round_trip_plain(tmp_path):
    path = tmp_path / "agent.key"
    first = AgentIdentity.load_or_create(path)
    again = AgentIdentity.load_or_create(path)
    assert again.address == first.address
    assert again.name == "agent"  # defaults to the file stem
    # Written 0600 and exactly the raw 64-byte form.
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert len(path.read_bytes()) == 64


def test_load_or_create_round_trip_encrypted(tmp_path):
    path = tmp_path / "sealed.key"
    first = AgentIdentity.load_or_create(path, passphrase="open sesame")
    again = AgentIdentity.load_or_create(path, passphrase="open sesame")
    assert again.address == first.address
    assert path.read_bytes().startswith(b"FGID")


def test_load_or_create_owner_and_custom_fields(tmp_path):
    owner = OwnerIdentity.load_or_create(tmp_path / "owner.key", name="acme")
    assert owner.name == "acme"
    assert OwnerIdentity.load_or_create(tmp_path / "owner.key").address == owner.address

    agent = AgentIdentity.load_or_create(
        tmp_path / "endpoint.key", name="me", kind=ParticipantKind.HUMAN
    )
    assert (agent.name, agent.kind) == ("me", ParticipantKind.HUMAN)


def test_wrong_passphrase_is_a_friendly_error(tmp_path):
    path = tmp_path / "sealed.key"
    AgentIdentity.load_or_create(path, passphrase="right")
    with pytest.raises(ValueError, match="wrong passphrase or corrupt"):
        AgentIdentity.load_or_create(path, passphrase="wrong")


def test_encrypted_file_without_passphrase_says_so(tmp_path):
    path = tmp_path / "sealed.key"
    AgentIdentity.load_or_create(path, passphrase="secret")
    with pytest.raises(ValueError, match="is encrypted — pass the passphrase"):
        AgentIdentity.load_or_create(path)


def test_plain_file_with_passphrase_refuses_to_guess(tmp_path):
    path = tmp_path / "plain.key"
    AgentIdentity.load_or_create(path)
    with pytest.raises(ValueError, match="is not encrypted, but a passphrase"):
        AgentIdentity.load_or_create(path, passphrase="secret")


def test_corrupt_file_is_a_friendly_error(tmp_path):
    path = tmp_path / "broken.key"
    path.write_bytes(b"\x01\x02\x03")
    with pytest.raises(ValueError, match="corrupt"):
        load_keys(path)


def test_bare_key_helpers_round_trip(tmp_path):
    keys = load_or_create_keys(tmp_path / "bare.key")
    assert load_keys(tmp_path / "bare.key").public.signing == keys.public.signing
    save_keys(keys, tmp_path / "copy.key", passphrase="p")
    assert load_keys(tmp_path / "copy.key", "p").public.signing == keys.public.signing


JS_DIST = Path(__file__).parent.parent / "js" / "dist" / "src" / "index.js"


@pytest.mark.skipif(
    shutil.which("node") is None or not JS_DIST.exists(),
    reason="node or the built TypeScript dist is unavailable",
)
@pytest.mark.parametrize("passphrase", [None, "cross-language secret"])
def test_keyfile_cross_language_python_writes_ts_loads(tmp_path, passphrase):
    """Python writes both keyfile formats; the TypeScript build must load them
    and derive the identical address."""
    path = tmp_path / "shared.key"
    identity = AgentIdentity.load_or_create(path, passphrase)
    script = (
        f"import {{ AgentIdentity }} from {str(JS_DIST)!r};"
        f"const me = await AgentIdentity.loadOrCreate({str(path)!r}, "
        f"{'null' if passphrase is None else repr(passphrase)});"
        "console.log(me.address);"
    )
    result = subprocess.run(
        ["node", "--input-type=module", "-e", script],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == identity.address
