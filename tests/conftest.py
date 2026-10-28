import base64
import hashlib

import pytest

from prestige.store import Store


@pytest.fixture
def store(tmp_path):
    result = Store(tmp_path / "state")
    yield result
    result.close()


@pytest.fixture
def challenge(tmp_path):
    value = b"SYNTHETIC{independent_byte_proof}"
    path = tmp_path / "challenge.txt"
    path.write_bytes(base64.b64encode(value))
    return path, hashlib.sha256(value).hexdigest(), value
