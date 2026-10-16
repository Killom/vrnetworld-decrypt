"""Startet die Entschlüsselung aus dem Projektordner, ohne Installation.

Unter Windows und Unix derselbe Aufruf, nur der Python-Befehl davor ändert sich:

    py -3 vrnetworld-decrypt.py QUELLE ZIEL
    python3 vrnetworld-decrypt.py QUELLE ZIEL
"""

from __future__ import annotations

import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent / "src"
if _SRC.is_dir():
    sys.path.insert(0, str(_SRC))

from vrnetworld_decrypt.__main__ import main

if __name__ == "__main__":
    raise SystemExit(main())
