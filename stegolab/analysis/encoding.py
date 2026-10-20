"""Small deterministic encoding and cryptographic helpers, without shell tools."""
import base64
import binascii
import codecs
import hashlib


def transform(operation: str, value: str, key: str = "") -> dict:
    if len(value.encode("utf-8")) > 1048576:
        raise ValueError("Input exceeds 1 MiB")
    raw = value.encode("utf-8")
    if operation == "base64_encode":
        output = base64.b64encode(raw).decode("ascii")
    elif operation == "base64_decode":
        output = base64.b64decode(value, validate=True).decode("utf-8", "replace")
    elif operation == "hex_encode":
        output = raw.hex()
    elif operation == "hex_decode":
        output = bytes.fromhex(value).decode("utf-8", "replace")
    elif operation == "rot13":
        output = codecs.encode(value, "rot_13")
    elif operation in {"sha256", "sha1", "md5"}:
        output = hashlib.new(operation, raw).hexdigest()
    elif operation == "xor":
        if not key or len(key.encode("utf-8")) > 4096:
            raise ValueError("XOR requires a nonempty key of at most 4096 bytes")
        key_bytes = key.encode("utf-8")
        result = bytes(byte ^ key_bytes[i % len(key_bytes)] for i, byte in enumerate(raw))
        return {"operation": operation, "output": result.hex(), "encoding": "hex", "text": result.decode("utf-8", "replace")}
    else:
        raise ValueError("Unsupported operation")
    return {"operation": operation, "output": output, "encoding": "text"}


def decoded_candidates(text: str):
    """Only decode bounded candidates; no guessing loops or recursive decoding."""
    import re
    seen = set()
    for match in re.finditer(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{16,512}={0,2}(?![A-Za-z0-9+/=])", text):
        token = match.group()
        if len(token) % 4:
            continue
        try:
            decoded = base64.b64decode(token, validate=True).decode("utf-8")
        except (ValueError, UnicodeError, binascii.Error):
            continue
        if decoded not in seen and decoded and sum(char.isprintable() for char in decoded) / len(decoded) > .9:
            seen.add(decoded)
            yield "base64", match.start(), decoded
        if len(seen) >= 100:
            return
