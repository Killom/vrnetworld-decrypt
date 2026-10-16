"""Schreibt eine Klartextkopie einer VR-NetWorld-SQLite-Datei."""

from __future__ import annotations

import os
import shutil
import sqlite3
import stat
import subprocess
from pathlib import Path

from .cipher import DEFAULT_KEY
from .framing import decrypt_field


def _quote(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def same_path(left: Path, right: Path) -> bool:
    """Vergleicht zwei Pfade. Unter Windows unterscheidet der Vergleich keine Großschreibung."""
    return os.path.normcase(os.path.abspath(left)) == os.path.normcase(os.path.abspath(right))


def windows_principal(environ: dict[str, str] | None = None) -> str:
    """Konto für icacls, zum Beispiel COMPUTERNAME\\Benutzer."""
    env = os.environ if environ is None else environ
    user = env.get("USERNAME", "")
    domain = env.get("USERDOMAIN", "")
    if domain and user:
        return f"{domain}\\{user}"
    if user:
        return user
    return ""


def windows_acl_command(path: Path, principal: str) -> list[str]:
    return [
        "icacls",
        os.fspath(path),
        "/inheritance:r",
        "/grant:r",
        f"{principal}:(R,W)",
    ]


def restrict_to_user(path: Path) -> str | None:
    """Beschränkt die Klartextdatei auf den aktuellen Benutzer.

    Unter Unix entspricht das dem Modus 0600. Unter Windows ersetzt icacls die
    geerbten Zugriffsrechte. Schlägt das fehl, bleibt die Datei trotzdem liegen.
    """
    if os.name == "posix":
        os.chmod(path, 0o600)
        return None
    if os.name != "nt":
        return None
    os.chmod(path, stat.S_IREAD | stat.S_IWRITE)
    principal = windows_principal()
    if not principal:
        return "Die Dateirechte konnten nicht auf den aktuellen Benutzer beschränkt werden."
    try:
        result = subprocess.run(
            windows_acl_command(path, principal),
            capture_output=True,
            check=False,
        )
    except OSError:
        return "icacls konnte nicht gestartet werden. Die Klartextdatei behält die normalen Dateirechte."
    if result.returncode != 0:
        return "Die Windows-Dateirechte konnten nicht beschränkt werden. Die Klartextdatei behält die normalen Dateirechte."
    return None


def decrypt_database(
    source: Path | str,
    destination: Path | str,
    key: str | bytes = DEFAULT_KEY,
) -> dict[str, int | str]:
    """Kopiert source nach destination und entschlüsselt dort alle passenden Textzellen.

    Die Zählung nennt nur Tabellen und Anzahlen, keine Zellinhalte.
    """
    source = Path(source)
    destination = Path(destination)
    if not source.is_file():
        raise FileNotFoundError(source)
    if same_path(source, destination):
        raise ValueError("Quelle und Ziel müssen verschiedene Dateien sein")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    warning = restrict_to_user(destination)

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
    return {"examined": examined, "decrypted": decrypted, "warning": warning or ""}
