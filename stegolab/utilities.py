"""Small deterministic utilities; never invoke a shell or a network service."""
import base64
import binascii
import codecs
import hashlib
import urllib.parse


def transform(operation: str, text: str, key: str = "") -> dict:
    raw = text.encode("utf-8")
    if len(raw) > 64 * 1024:
        raise ValueError("Utility input is limited to 64 KiB")
    try:
        if operation == "hashes":
            hashes = {name: hashlib.new(name, raw).hexdigest() for name in ("md5", "sha1", "sha256", "sha512")}
            return {"result": "\n".join(f"{name}: {value}" for name, value in hashes.items()), "hashes": hashes}
        if operation == "base64_encode":
            result = base64.b64encode(raw).decode("ascii")
        elif operation == "base64_decode":
            result = base64.b64decode("".join(text.split()), validate=True).decode("utf-8")
        elif operation == "hex_encode":
            result = raw.hex()
        elif operation == "hex_decode":
            result = bytes.fromhex(text).decode("utf-8")
        elif operation == "rot13":
            result = codecs.encode(text, "rot_13")
        elif operation == "url_encode":
            result = urllib.parse.quote(text, safe="")
        elif operation == "url_decode":
            result = urllib.parse.unquote(text, errors="strict")
        elif operation == "xor":
            secret = bytes.fromhex(key)
            if not secret or len(secret) > 256:
                raise ValueError("XOR key must be 1–256 bytes of hexadecimal")
            result = bytes(byte ^ secret[i % len(secret)] for i, byte in enumerate(raw)).hex()
        else:
            raise ValueError("Unsupported operation")
    except (binascii.Error, UnicodeError, ValueError) as exc:
        raise ValueError(f"Invalid input: {exc}") from exc
    return {"result": result}
