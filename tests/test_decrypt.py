import os
import stat
import tempfile
import unittest
from pathlib import Path

from vrnetworld_decrypt import codieren128, decrypt_field, encrypt_field
from vrnetworld_decrypt.database import (
    restrict_to_user,
    same_path,
    windows_acl_command,
    windows_principal,
)
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


class PlatformPaths(unittest.TestCase):
    def test_same_path_ignores_case_where_the_platform_does(self):
        left = Path.cwd() / "VrNws.db"
        right = Path.cwd() / "vrnws.db"
        self.assertEqual(same_path(left, right), os.path.normcase("A") == os.path.normcase("a"))

    def test_windows_acl_names_the_account(self):
        self.assertEqual(
            windows_principal({"USERDOMAIN": "PC", "USERNAME": "Martin"}),
            "PC\\Martin",
        )
        command = windows_acl_command(Path("klartext.db"), "PC\\Martin")
        self.assertEqual(command[0], "icacls")
        self.assertIn("/inheritance:r", command)
        self.assertEqual(command[-1], "PC\\Martin:(R,W)")

    def test_posix_copy_is_owner_only(self):
        if os.name != "posix":
            self.skipTest("Modus 0600 gilt nur unter Unix")
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "klartext.db"
            target.write_bytes(b"")
            os.chmod(target, 0o644)
            self.assertIsNone(restrict_to_user(target))
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
