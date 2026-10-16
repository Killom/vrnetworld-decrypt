# vrnetworld-decrypt

Entschlüsselt die Feldinhalte einer VR-NetWorld-SQLite-Datei (`vrnws.db`) in eine neue Klartextdatei.

VR-NetWorld legt einen Teil der Textfelder mit `Codieren128` aus `Hbci1.dll` ab. Das ist eine symmetrische Stromchiffre. Davor steht ein 17-Byte-Kopf: dort, wo die verschlüsselte Nutzlast ein Nullbyte hätte, steht `X`, und das zugehörige Bit im Kopf ist gesetzt. Der Schlüssel ist eine feste Zeichenkette im Programm (`12int i = 1128?_*-`), nicht das Passwort der Bank oder von VR-NetWorld.

```bash
python -m vrnetworld_decrypt /pfad/vrnws.db /pfad/vrnws-klartext.db
```

Das Programm schreibt nur die Zieldatei und eine Zählung. Es gibt keine Feldinhalte aus. Die Zieldatei bekommt die Rechte `0600`.

```bash
PYTHONPATH=src python -m unittest discover -s tests
```
