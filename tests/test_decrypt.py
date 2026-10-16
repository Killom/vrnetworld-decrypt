import unittest

from vrnetworld_decrypt import codieren128, decrypt_field, encrypt_field
from vrnetworld_decrypt.framing import unwrap_text


class CipherVectors(unittest.TestCase):
    def test_single_bytes_match_the_dll(self):
        self.assertEqual(codieren128(b"C"), bytes.fromhex("4f"))
        self.assertEqual(codieren128(b"D"), bytes.fromhex("48"))
        self.assertEqual(codieren128(b"H"), bytes.fromhex("44"))
        self.assertEqual(codieren128(b"S"), bytes.fromhex("5f"))

    def test_operation_is_symmetric(self):
        sample = "Name-12,50 EUR"
        self.assertEqual(decrypt_field(encrypt_field(sample)), sample)

    def test_latin1_bytes_are_stored_as_utf8(self):
        self.assertEqual(unwrap_text(bytes.fromhex("49c3901b")), bytes.fromhex("49d01b"))
        self.assertEqual(unwrap_text(bytes.fromhex("c280")), bytes.fromhex("80"))

    def test_zero_bytes_roundtrip_through_the_header(self):
        # Byte 0x0c verschlüsselt zu 0x00 und muss im Kopf als X markiert werden.
        sample = "\x0cAB"
        stored = encrypt_field(sample)
        self.assertIn(b"\x58", stored)
        self.assertNotIn(b"\x00", stored)
        self.assertEqual(decrypt_field(stored), sample)


if __name__ == "__main__":
    unittest.main()
