"""Byte-preserving CyberChef-style recipes with strict expansion limits."""
import base64
import codecs
import hashlib
import urllib.parse
import zlib

MAX_BYTES = 1024 * 1024
OPERATIONS = ["base64_encode", "base64_decode", "base32_encode", "base32_decode", "base85_encode", "base85_decode",
              "hex_encode", "hex_decode", "binary_encode", "binary_decode", "decimal_encode", "decimal_decode",
              "ascii_encode", "ascii_decode", "url_encode", "url_decode", "rot13", "rot47", "caesar", "atbash",
              "vigenere_encrypt", "vigenere_decrypt", "xor", "reverse_text", "reverse_bytes", "hashes",
              "gzip_decompress", "zlib_decompress", "utf8_encode", "utf8_decode", "unicode_escape", "unicode_unescape"]


def bounded_decompress(data, window):
    decoder = zlib.decompressobj(window)
    result = decoder.decompress(data, MAX_BYTES + 1)
    if len(result) > MAX_BYTES or decoder.unconsumed_tail:
        raise ValueError("Decompressed output exceeds 1 MiB")
    if not decoder.eof:
        raise ValueError("Truncated compressed stream")
    if decoder.unused_data:
        raise ValueError("Trailing or concatenated compressed streams are not accepted")
    return result


def letters(text, shifts):
    result, index = [], 0
    for char in text:
        if char.isascii() and char.isalpha():
            base = ord('A' if char.isupper() else 'a')
            result.append(chr(base + (ord(char) - base + shifts[index % len(shifts)]) % 26))
            index += 1
        else:
            result.append(char)
    return ''.join(result)


def apply(data: bytes, operation: str, key="", shift=13):
    if operation not in OPERATIONS:
        raise ValueError("Unsupported transformation")
    if operation.endswith("_encode") and operation.split('_')[0] in {"base64", "base32", "base85"}:
        return getattr(base64, {"base64_encode": "b64encode", "base32_encode": "b32encode", "base85_encode": "b85encode"}[operation])(data)
    if operation in {"base64_decode", "base32_decode", "base85_decode"}:
        compact = b''.join(data.split())
        if operation == "base64_decode":
            return base64.b64decode(compact, validate=True)
        return base64.b32decode(compact, casefold=True) if operation == "base32_decode" else base64.b85decode(compact)
    if operation == "hex_encode": return data.hex().encode()
    if operation == "hex_decode": return bytes.fromhex(data.decode('ascii'))
    if operation in {"binary_encode", "decimal_encode", "ascii_encode"}:
        return ' '.join(format(byte, '08b') if operation == "binary_encode" else str(byte) for byte in data).encode()
    if operation in {"binary_decode", "decimal_decode", "ascii_decode"}:
        text = data.decode('ascii')
        tokens = text.split()
        if operation == "binary_decode" and len(tokens) == 1:
            if len(text) % 8: raise ValueError("Binary input requires complete 8-bit bytes")
            tokens = [text[i:i+8] for i in range(0, len(text), 8)]
        return bytes(int(token, 2 if operation == "binary_decode" else 10) for token in tokens)
    if operation == "reverse_bytes": return data[::-1]
    if operation == "xor":
        secret = bytes.fromhex(key)
        if not secret or len(secret) > 256: raise ValueError("XOR key must contain 1–256 hexadecimal bytes")
        return bytes(byte ^ secret[i % len(secret)] for i, byte in enumerate(data))
    if operation == "hashes":
        return '\n'.join(f'{name}: {hashlib.new(name, data).hexdigest()}' for name in ('md5', 'sha1', 'sha256', 'sha512')).encode()
    if operation in {"gzip_decompress", "zlib_decompress"}:
        return bounded_decompress(data, 31 if operation == "gzip_decompress" else 15)
    if operation == "url_decode": return urllib.parse.unquote_to_bytes(data)
    if operation == "url_encode": return urllib.parse.quote_from_bytes(data, safe='').encode()
    text = data.decode('utf-8', errors='strict')
    if operation in {"utf8_encode", "utf8_decode"}: return text.encode('utf-8')
    if operation == "unicode_escape": return text.encode('unicode_escape')
    if operation == "unicode_unescape": return codecs.decode(text.encode('ascii'), 'unicode_escape').encode('utf-8')
    if operation == "reverse_text": return text[::-1].encode()
    if operation == "rot13": return codecs.encode(text, 'rot_13').encode()
    if operation == "rot47": return ''.join(chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c for c in text).encode()
    if operation == "caesar": return letters(text, [int(shift) % 26]).encode()
    if operation == "atbash":
        return ''.join(chr((ord('Z') + ord('A') if c.isupper() else ord('z') + ord('a')) - ord(c)) if c.isascii() and c.isalpha() else c for c in text).encode()
    if operation.startswith("vigenere_"):
        if not key or len(key) > 256 or not all(c.isascii() and c.isalpha() for c in key):
            raise ValueError("Vigenere key must contain 1–256 ASCII letters")
        sign = -1 if operation.endswith('decrypt') else 1
        return letters(text, [sign * (ord(c.lower()) - 97) for c in key]).encode()
    raise ValueError("Unsupported transformation")


def representation(data):
    text = None
    try: text = data.decode('utf-8')
    except UnicodeError: pass
    return {"size": len(data), "text": text, "hex": data[:65536].hex(),
            "base64": base64.b64encode(data).decode(), "sha256": hashlib.sha256(data).hexdigest(),
            "preview_truncated": len(data) > 65536}


def run_recipe(payload):
    encoding = payload.get('input_encoding', 'utf8')
    value = payload.get('input', '')
    if encoding == 'base64': data = base64.b64decode(value, validate=True)
    elif encoding == 'hex': data = bytes.fromhex(value)
    elif encoding == 'utf8': data = value.encode('utf-8')
    else: raise ValueError("Input encoding must be utf8, hex or base64")
    steps = payload.get('steps', [])
    if len(steps) > 20 or len(data) > 65536: raise ValueError("Recipe limit: 20 steps and 64 KiB input")
    history, intermediate, total = [], [], 0
    for index, step in enumerate(steps):
        try:
            data = apply(data, step['operation'], step.get('key', ''), step.get('shift', 13))
            if len(data) > MAX_BYTES: raise ValueError("Transformation output exceeds 1 MiB")
            total += len(data)
            if total > 4 * MAX_BYTES: raise ValueError("Recipe intermediate output budget exceeded")
        except Exception as exc:
            raise ValueError(f"Step {index + 1} ({step.get('operation')}): {exc}") from exc
        history.append(step['operation'])
        intermediate.append({"step": index + 1, "operation": step['operation'], "history": list(history), **representation(data)})
    from .flags import FlagFinder
    flags = FlagFinder().scan(data, source='crypto recipe', method='recipe', history=history)
    return {"steps": intermediate, "output": representation(data), "flags": flags}
