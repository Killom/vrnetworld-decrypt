"""Kommandozeile: python vrnetworld-decrypt.py QUELLE ZIEL"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .cipher import DEFAULT_KEY
from .database import decrypt_database


def configure_stdio() -> None:
    """Windows-Konsolen nutzen oft nicht UTF-8. Die Ausgabe soll daran nicht scheitern."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            continue


def main(argv: list[str] | None = None) -> int:
    configure_stdio()
    parser = argparse.ArgumentParser(
        description=(
            "Entschlüsselt die Codieren128-Felder einer VR-NetWorld-SQLite-Datei "
            "in eine neue Klartextdatei. Zellinhalte werden nicht ausgegeben."
        )
    )
    parser.add_argument("source", type=Path, help="verschlüsselte vrnws.db")
    parser.add_argument("destination", type=Path, help="neue Klartextkopie")
    parser.add_argument(
        "--key",
        default=DEFAULT_KEY,
        help="Schlüsselzeichenkette von Codieren128, voreingestellt der Datenbankschlüssel",
    )
    args = parser.parse_args(argv)
    if args.destination.exists():
        parser.error(f"Ziel existiert schon: {args.destination}")
    counts = decrypt_database(args.source, args.destination, args.key)
    print(
        f"{counts['decrypted']} Felder entschlüsselt, "
        f"{counts['examined']} Textfelder geprüft, "
        f"geschrieben nach {args.destination}"
    )
    if counts["warning"]:
        print(counts["warning"], file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
