"""Schreibt eine Klartextkopie einer VR-NetWorld-SQLite-Datei."""

from __future__ import annotations

import os
import shutil
import sqlite3
from pathlib import Path

from .cipher import DEFAULT_KEY
from .framing import decrypt_field


def _quote(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def decrypt_database(
    source: Path | str,
    destination: Path | str,
    key: str | bytes = DEFAULT_KEY,
) -> dict[str, int]:
    """Kopiert source nach destination und entschlüsselt dort alle passenden Textzellen.

    Die Zählung nennt nur Tabellen und Anzahlen, keine Zellinhalte.
    """
    source = Path(source)
    destination = Path(destination)
    if not source.is_file():
        raise FileNotFoundError(source)
    if destination.resolve() == source.resolve():
        raise ValueError("Quelle und Ziel müssen verschiedene Dateien sein")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    os.chmod(destination, 0o600)

    connection = sqlite3.connect(destination)
    connection.text_factory = bytes
    decrypted = 0
    examined = 0
    try:
        tables = [
            row[0].decode()
            for row in connection.execute(
                "select name from sqlite_master where type = 'table' "
                "and name not like 'sqlite_%'"
            )
        ]
        for table in tables:
            columns = [
                row[1].decode()
                for row in connection.execute(f"pragma table_info({_quote(table)})")
            ]
            if not columns:
                continue
            selected = ", ".join(_quote(column) for column in columns)
            rows = connection.execute(
                f"select _rowid_, {selected} from {_quote(table)}"
            )
            for row in rows:
                rowid = row[0]
                for column, value in zip(columns, row[1:]):
                    if not isinstance(value, (bytes, bytearray)):
                        continue
                    examined += 1
                    plain = decrypt_field(bytes(value), key)
                    if plain is None:
                        continue
                    connection.execute(
                        f"update {_quote(table)} set {_quote(column)} = ? "
                        f"where _rowid_ = ?",
                        (plain, rowid),
                    )
                    decrypted += 1
        connection.commit()
    finally:
        connection.close()
    return {"examined": examined, "decrypted": decrypted}
