"""
Crimson Desert ChaCha20 decryption/encryption.
Ported from MrIkso/CrimsonDesertTools (C#), based on lazorr410's research.

The key and IV are derived deterministically from the filename.
ChaCha20 is symmetric: encrypt == decrypt (XOR with keystream).
"""
import struct

# ─── Constants ──────────────────────────────────────────────────────────

_HASH_INITVAL = 0x000C5EDE
_IV_XOR = 0x60616263
_XOR_DELTAS = [
    0x00000000, 0x0A0A0A0A, 0x0C0C0C0C, 0x06060606,
    0x0E0E0E0E, 0x0A0A0A0A, 0x06060606, 0x02020202,
]
_MASK = 0xFFFFFFFF


# ─── Jenkins hash (same variant as CrimsonCrypto.cs) ────────────────────

def _rot(v, k):
    v &= _MASK
    return ((v << k) | (v >> (32 - k))) & _MASK


def _jenkins_hash(data: bytes, initval: int) -> int:
    length = len(data)
    a = b = c = (0xDEADBEEF + length + initval) & _MASK

    off = 0
    remaining = length

    while remaining > 12:
        a = (a + struct.unpack_from('<I', data, off)[0]) & _MASK
        b = (b + struct.unpack_from('<I', data, off + 4)[0]) & _MASK
        c = (c + struct.unpack_from('<I', data, off + 8)[0]) & _MASK

        a = (a - c) & _MASK; a ^= _rot(c, 4);  c = (c + b) & _MASK
        b = (b - a) & _MASK; b ^= _rot(a, 6);  a = (a + c) & _MASK
        c = (c - b) & _MASK; c ^= _rot(b, 8);  b = (b + a) & _MASK
        a = (a - c) & _MASK; a ^= _rot(c, 16); c = (c + b) & _MASK
        b = (b - a) & _MASK; b ^= _rot(a, 19); a = (a + c) & _MASK
        c = (c - b) & _MASK; c ^= _rot(b, 4);  b = (b + a) & _MASK

        off += 12
        remaining -= 12

    # Tail — pad into 12-byte buffer
    tail = data[off:] + b'\x00' * (12 - remaining)

    if remaining >= 1:
        a = (a + struct.unpack_from('<I', tail, 0)[0] & (_MASK >> (8 * max(0, 4 - remaining)))) & _MASK if remaining < 4 else (a + struct.unpack_from('<I', tail, 0)[0]) & _MASK
    if remaining >= 5:
        b = (b + struct.unpack_from('<I', tail, 4)[0] & (_MASK >> (8 * max(0, 8 - remaining)))) & _MASK if remaining < 8 else (b + struct.unpack_from('<I', tail, 4)[0]) & _MASK
    if remaining >= 9:
        c = (c + struct.unpack_from('<I', tail, 8)[0] & (_MASK >> (8 * max(0, 12 - remaining)))) & _MASK if remaining < 12 else (c + struct.unpack_from('<I', tail, 8)[0]) & _MASK

    if remaining == 0:
        return c

    # Final mix
    c ^= b; c = (c - _rot(b, 14)) & _MASK
    a ^= c; a = (a - _rot(c, 11)) & _MASK
    b ^= a; b = (b - _rot(a, 25)) & _MASK
    c ^= b; c = (c - _rot(b, 16)) & _MASK
    a ^= c; a = (a - _rot(c, 4)) & _MASK
    b ^= a; b = (b - _rot(a, 14)) & _MASK
    c ^= b; c = (c - _rot(b, 24)) & _MASK

    return c


# ─── Key/IV derivation ──────────────────────────────────────────────────

def _derive_key_iv(filename: str):
    """Derive 32-byte key and 16-byte IV from filename (lowercase basename)."""
    import os
    basename = os.path.basename(filename).lower()
    seed = _jenkins_hash(basename.encode('utf-8'), _HASH_INITVAL)

    # IV: seed repeated 4 times
    iv = struct.pack('<I', seed) * 4

    # Key: (seed ^ IV_XOR) XORed with each delta
    key_base = seed ^ _IV_XOR
    key = b''
    for delta in _XOR_DELTAS:
        key += struct.pack('<I', (key_base ^ delta) & _MASK)

    return key, iv


# ─── ChaCha20 core ──────────────────────────────────────────────────────

def _quarter_round(x, a, b, c, d):
    x[a] = (x[a] + x[b]) & _MASK
    x[d] = _rot(x[d] ^ x[a], 16)
    x[c] = (x[c] + x[d]) & _MASK
    x[b] = _rot(x[b] ^ x[c], 12)
    x[a] = (x[a] + x[b]) & _MASK
    x[d] = _rot(x[d] ^ x[a], 8)
    x[c] = (x[c] + x[d]) & _MASK
    x[b] = _rot(x[b] ^ x[c], 7)


def _chacha20_block(state):
    """Generate 64-byte keystream block from state, increment counter."""
    x = list(state)
    for _ in range(10):
        _quarter_round(x, 0, 4, 8, 12)
        _quarter_round(x, 1, 5, 9, 13)
        _quarter_round(x, 2, 6, 10, 14)
        _quarter_round(x, 3, 7, 11, 15)
        _quarter_round(x, 0, 5, 10, 15)
        _quarter_round(x, 1, 6, 11, 12)
        _quarter_round(x, 2, 7, 8, 13)
        _quarter_round(x, 3, 4, 9, 14)

    out = b''
    for i in range(16):
        out += struct.pack('<I', (x[i] + state[i]) & _MASK)

    # Increment counter
    state[12] = (state[12] + 1) & _MASK
    return out


def _chacha20_crypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """Encrypt/decrypt data with ChaCha20. IV is 16 bytes: [counter(4) | nonce(12)]."""
    # Setup state: "expand 32-byte k" + key(32) + counter(4) + nonce(12)
    sigma = b'expand 32-byte k'
    state = list(struct.unpack('<4I', sigma))
    state += list(struct.unpack('<8I', key))
    counter = struct.unpack_from('<I', iv, 0)[0]
    nonce = iv[4:16]
    state.append(counter)
    state += list(struct.unpack('<3I', nonce))

    out = bytearray()
    offset = 0
    while offset < len(data):
        block = _chacha20_block(state)
        chunk_size = min(64, len(data) - offset)
        for i in range(chunk_size):
            out.append(data[offset + i] ^ block[i])
        offset += chunk_size

    return bytes(out)


# ─── Public API ─────────────────────────────────────────────────────────

def decrypt_chacha20(ciphertext: bytes, filename: str) -> bytes:
    """Decrypt a ChaCha20-encrypted PAZ file entry."""
    key, iv = _derive_key_iv(filename)
    return _chacha20_crypt(ciphertext, key, iv)


def encrypt_chacha20(plaintext: bytes, filename: str) -> bytes:
    """Encrypt data with ChaCha20 (symmetric — same as decrypt)."""
    key, iv = _derive_key_iv(filename)
    return _chacha20_crypt(plaintext, key, iv)
