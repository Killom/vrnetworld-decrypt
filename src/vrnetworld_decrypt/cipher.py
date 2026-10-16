"""Codieren128 aus Hbci1.dll, ohne die DLL.

Die Funktion ist symmetrisch: dieselbe Operation ver- und entschlüsselt.
Der Datenbankschlüssel ist eine feste Zeichenkette im Programm, nicht das
Passwort des Anwenders.
"""

from __future__ import annotations

import struct

# Feste Schlüsselzeichenkette, die Codieren128 für Datenbankfelder benutzt.
DEFAULT_KEY = "12int i = 1128?_*-"

# 256 Byte ab VA 0x5635c. Das sind die ersten Hexziffern von Pi.
_SBOX = bytes.fromhex(
    "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89"
    "452821e638d01377be5466cf34e90c6cc0ac29b7c97c50dd3f84d5b5b5470917"
    "9216d5d98979fb1bd1310ba698dfb5ac2ffd72dbd01adfb7b8e1afed6a267e96"
    "ba7c9045f12c7f9924a19947b3916cf70801f2e2858efc16636920d871574e69"
    "a458fea3f4933d7e0d95748f728eb658718bcd5882154aee7b54a41dc25a59b5"
    "9c30d5392af26013c5d1b023286085f0ca417918b8db38ef8e79dcb0603a180e"
    "6c9e0e8bb01e8a3ed71577c1bd314b2778af2fda55605c60e65525f3aa55ab94"
    "5748986263e8144055ca396a2aab10b6b4cc5c341141e8cea15486af7c72e993"
)

# Vier Dwords ab VA 0x5645c, unmittelbar hinter der Pi-Tabelle.
_TABLE = (0x55555555, 0xAAAAAAAA, 0x33333333, 0xCCCCCCCC)

# Abschlussauffüllung ab VA 0x57d74. Es werden nur so viele Byte gelesen,
# wie der 8-Byte-Zähler noch braucht.
_PAD = bytes.fromhex("0100000000000000")


def u32(value: int) -> int:
    return value & 0xFFFFFFFF


def _mix_words(a: int, b: int, c: int, d: int) -> tuple[int, int, int, int]:
    """Ein Durchlauf der 32-Bit-Mischung aus 0x14e2e und 0x13068."""
    a = u32(a + d)
    d = u32(d + a)
    a ^= a >> 7
    b = u32(b + a)
    a = u32(a + b)
    b ^= u32(b << 13)
    c = u32(c + b)
    b = u32(b + c)
    c ^= c >> 17
    d = u32(d + c)
    c = u32(c + d)
    d ^= u32(d << 9)
    a = u32(a + d)
    d = u32(d + a)
    a ^= a >> 3
    b = u32(b + a)
    a = u32(a + b)
    b ^= u32(b << 7)
    c = u32(c + b)
    b = u32(b + c)
    c ^= d >> 15
    d = u32(d + c)
    c = u32(c + d)
    d ^= u32(d << 11)
    return a, b, c, d


def _derive_key(key: bytes) -> bytes:
    """16 Byte aus der Hashfunktion 0x14d10 / 0x14d88 / 0x14f24."""
    index = 0
    sbox = bytearray(_SBOX)
    counter = 0
    words = [0x55555555, 0x55555555, 0x55555555, 0x55555555]

    def absorb(data: bytes) -> None:
        nonlocal index, counter, words
        for byte in data:
            sbox[index] ^= byte
            index += 1
            if index == 256:
                index = 0
            raw = bytearray(struct.pack("<4I", *words))
            raw[counter] ^= byte
            words = list(struct.unpack("<4I", raw))
            counter += 1
            if counter == 8:
                a, b, c, d = words[3], words[2], words[1], words[0]
                for _ in range(4):
                    a, b, c, d = _mix_words(a, b, c, d)
                words = [a, b, c, d]
                counter = 0

    absorb(key)
    absorb(_PAD[: 8 - counter])

    # 0x1345c baut aus den vier Mischworten 32 Dwords. 0x12ff4 liest davon 16.
    schedule: list[int] = []
    for entry in _TABLE:
        ec, e8, e4, e0 = words[0], entry, words[1], entry
        dc, d8, d4, d0 = words[2], entry, words[3], entry
        for _ in range(8):
            ec ^= u32(e8 << 11)
            e0 = u32(e0 + ec)
            e8 = u32(e8 + e4)
            e8 ^= e4 >> 2
            dc = u32(dc + e8)
            e4 = u32(e4 + e0)
            e4 ^= u32(e0 << 8)
            d8 = u32(d8 + e4)
            e0 = u32(e0 + dc)
            e0 ^= dc >> 16
            d4 = u32(d4 + e0)
            dc = u32(dc + d8)
            dc ^= u32(d8 << 10)
            d0 = u32(d0 + dc)
            d8 = u32(d8 + d4)
            d8 ^= d4 >> 4
            ec = u32(ec + d8)
            d4 = u32(d4 + d0)
            d4 ^= u32(d0 << 8)
            e8 = u32(e8 + d4)
            d0 = u32(d0 + ec)
            d0 ^= ec >> 9
            e4 = u32(e4 + d0)
            ec = u32(ec + e8)
        schedule.extend((ec, e8, e4, e0, dc, d8, d4, d0))

    # 0x12ff4 mischt jeden 16-Byte-Block der S-Box zurück an dieselbe Stelle.
    for offset in range(0, 256, 16):
        w0, w1, w2, w3 = struct.unpack_from("<4I", sbox, offset)
        for step in range(8):
            a, b = w0, schedule[step * 2]
            c, d = w1, schedule[step * 2 + 1]
            a, b, c, d = _mix_words(a, b, c, d)
            a, c = c, a
            b, d = d, b
            a, b, c, d = _mix_words(a, b, c, d)
            mixed0 = u32(w2 ^ a ^ b)
            mixed1 = u32(w3 ^ c ^ d)
            w2, w3, w0, w1 = w0, w1, mixed0, mixed1
        struct.pack_into("<4I", sbox, offset, w2, w3, w0, w1)

    return bytes(sbox[:16])


def _ksa(key: bytes) -> tuple[int, int, bytearray]:
    """Drei Runden der Schlüsselaustauschs 0x13ea8. j läuft über die Runden weiter."""
    box = bytearray(range(256))
    accum = 0
    for _ in range(3):
        for index in range(256):
            accum = u32(accum + box[index] + key[index % len(key)])
            other = accum & 0xFF
            box[index], box[other] = box[other], box[index]
    return 0, accum, box


def _prga(state: tuple[int, int, bytearray], buffer: bytearray) -> None:
    """Stromchiffre 0x13f60. i beginnt bei 0 und wird vor dem ersten Byte erhöht."""
    index, accum, box = state
    for position in range(len(buffer)):
        index = u32(index + 1)
        low = index & 0xFF
        sample = box[low]
        jump = u32(sample + box[sample])
        box[low] = box[jump & 0xFF]
        box[jump & 0xFF] = sample
        pick = ((jump >> 8) + (jump & 0xFF)) & 0xFF
        accum = u32(accum + box[pick])
        buffer[position] ^= accum & 0xFF


_SCHEDULE: dict[bytes, tuple[int, int, bytes]] = {}


def _schedule(key: bytes) -> tuple[int, int, bytearray]:
    cached = _SCHEDULE.get(key)
    if cached is None:
        index, accum, box = _ksa(_derive_key(key))
        cached = (index, accum, bytes(box))
        _SCHEDULE[key] = cached
    index, accum, box = cached
    return index, accum, bytearray(box)


def codieren128(data: bytes, key: str | bytes = DEFAULT_KEY) -> bytes:
    """Codieren128(Puffer, Länge, Schlüssel). Arbeitet auf einer Kopie."""
    if isinstance(key, str):
        key = key.encode("latin-1")
    if not key:
        raise ValueError("Schlüssel ist leer")
    buffer = bytearray(data)
    _prga(_schedule(key), buffer)
    return bytes(buffer)
