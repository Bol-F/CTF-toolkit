from __future__ import annotations

import hashlib

import pytest

from stegolab.analysis.encoding import decoded_candidates, transform


@pytest.mark.parametrize("encoder,decoder", [("base64_encode", "base64_decode"), ("hex_encode", "hex_decode")])
def test_encoding_round_trips_unicode(encoder, decoder):
    value = "flag{local_ctf} — салом"
    encoded = transform(encoder, value)["output"]
    assert transform(decoder, encoded)["output"] == value


def test_hash_and_xor_known_answers():
    assert transform("sha256", "flag{local}")["output"] == hashlib.sha256(b"flag{local}").hexdigest()
    assert transform("xor", "ABC", "K")["output"] == "0a0908"
    assert transform("rot13", "synt{yvgreny}")["output"] == "flag{literal}"


@pytest.mark.parametrize("operation,value,key", [
    ("base64_decode", "not base64!", ""),
    ("hex_decode", "xyz", ""),
    ("xor", "abc", ""),
    ("run_shell", "echo x", ""),
])
def test_invalid_transform_is_rejected(operation, value, key):
    with pytest.raises(ValueError):
        transform(operation, value, key)


def test_transform_input_limit():
    with pytest.raises(ValueError, match="1 MiB"):
        transform("base64_encode", "x" * (1024 * 1024 + 1))


def test_base64_candidates_find_encoded_ctf_clue():
    encoded = transform("base64_encode", "flag{encoded_clue}")["output"]
    candidates = list(decoded_candidates("Clue: " + encoded))
    assert ("base64", 6, "flag{encoded_clue}") in candidates
