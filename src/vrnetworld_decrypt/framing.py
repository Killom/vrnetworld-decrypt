"""Rahmen, in dem VR-NetWorld die Codieren128-Nutzlast in TEXT-Zellen legt.

SQLite sieht die Zelle als Text. Byte ab 0x80 liegen deshalb oft als UTF-8
von Latin-1 vor (C2/C3 plus Folgebyte). Dahinter stehen 17 Kopfteile und die
Nutzlast. Ein gesetztes Bit im Kopf bedeutet, dass dieses Nutzlastbyte 0x00
war und als 0x58 abgelegt wurde, weil die Zelle kein Nullbyte tragen kann.
"""

from __future__ import annotations

from .cipher import DEFAULT_KEY, codieren128

_HEADER_LENGTH = 17
_ZERO_MARK = 0x58


def unwrap_text(raw: bytes) -> bytes:
    """Macht aus den gespeicherten Textbyte wieder die ursprünglichen Byte."""
    out = bytearray()
    index = 0
    while index < len(raw):
        current = raw[index]
        if (
            current in (0xC2, 0xC3)
            and index + 1 < len(raw)
            and 0x80 <= raw[index + 1] <= 0xBF
        ):
            out.append(((current & 0x1F) << 6) | (raw[index + 1] & 0x3F))
            index += 2
        else:
            out.append(current)
            index += 1
    return bytes(out)


def looks_encrypted(raw: bytes) -> bool:
    """Erkennt den 17-Byte-Kopf. Mindestens zwölf der Kopfteile sind 0x01."""
    data = unwrap_text(raw)
    if len(data) < _HEADER_LENGTH + 1:
        return False
    return data[:_HEADER_LENGTH].count(1) >= 12


def restore_zeros(header: bytes, payload: bytes) -> bytes:
    """Setzt mit 0x58 ersetzte Nullbyte zurück. Bit steht in (Kopfbyte - 1)."""
    restored = bytearray(payload)
    for index in range(len(restored)):
        group = index // 8
        if group >= len(header):
            break
        flags = (header[group] - 1) & 0xFF
        if flags >> (index % 8) & 1:
            restored[index] = 0
    return bytes(restored)


def decode_field(data: bytes) -> str:
    """Ein Byte nach cp1252, sonst Latin-1. 0x81 und ein paar weitere sind kein cp1252."""
    chars: list[str] = []
    for byte in data:
        try:
            chars.append(bytes((byte,)).decode("cp1252"))
        except UnicodeDecodeError:
            chars.append(chr(byte))
    return "".join(chars)


def decrypt_field(raw: bytes, key: str | bytes = DEFAULT_KEY) -> str | None:
    """Entschlüsselt eine Zelle. None, wenn sie nicht den Feldrahmen trägt."""
    data = unwrap_text(raw)
    if len(data) < _HEADER_LENGTH + 1 or data[:_HEADER_LENGTH].count(1) < 12:
        return None
    header = data[:_HEADER_LENGTH]
    payload = restore_zeros(header, data[_HEADER_LENGTH:])
    return decode_field(codieren128(payload, key))


def encrypt_field(text: str, key: str | bytes = DEFAULT_KEY) -> bytes:
    """Baut den gespeicherten Rahmen. Nur für Tests und die Gegenrichtung."""
    plain = bytearray()
    for char in text:
        encoded = char.encode("cp1252")
        if len(encoded) != 1:
            raise ValueError("Nur Einzelbyte-Zeichen können so abgelegt werden")
        plain.append(encoded[0])
    cipher = bytearray(codieren128(bytes(plain), key))
    header = bytearray(b"\x01" * _HEADER_LENGTH)
    for index, byte in enumerate(cipher):
        if byte != 0:
            continue
        group = index // 8
        if group >= _HEADER_LENGTH:
            raise ValueError("Nutzlast passt nicht in den 17-Byte-Kopf")
        flags = (header[group] - 1) & 0xFF
        header[group] = (flags | (1 << (index % 8))) + 1
        cipher[index] = _ZERO_MARK
    return bytes(header) + bytes(cipher)
