# vrnetworld-decrypt

VR-NetWorld speichert seine Daten in einer SQLite-Datei, in der Regel `vrnws.db`. Ein Teil der Textspalten ist darin nicht lesbar. VR-NetWorld verschlüsselt jede dieser Zellen einzeln mit der Funktion `Codieren128`. Zahlen, leere Felder und Text ohne diesen Aufbau bleiben im Klartext.

Dieses Programm legt eine Kopie der Datei an und entschlüsselt darin genau die verschlüsselten Zellen. Die Kopie lässt sich danach mit einem gewöhnlichen SQLite-Programm öffnen. Die Originaldatei bleibt unangetastet. Auf dem Bildschirm erscheinen nur die Anzahl der geprüften und entschlüsselten Felder, nicht deren Inhalt.

## Anwendung

Voraussetzung ist Python 3.11 oder neuer. `Hbci1.dll` wird nicht gebraucht, und VR-NetWorld muss dafür nicht laufen. Hat die Anwendung die Datenbank noch geöffnet, sollte sie vorher geschlossen werden, sonst lässt sich die Datei unter Windows oft nicht kopieren.

Im Projektordner, unter Windows:

```text
py -3 vrnetworld-decrypt.py C:\Pfad\zur\VR-NetWorld\database\vrnws.db %USERPROFILE%\Desktop\vrnws-klartext.db
```

Unter Linux und macOS:

```text
python3 vrnetworld-decrypt.py /pfad/vrnws.db /pfad/vrnws-klartext.db
```

Pfade mit Leerzeichen in Anführungszeichen setzen. Die Zieldatei darf nur der aktuelle Benutzer lesen. Unter Unix setzt das Programm den Modus `0600`, unter Windows die Zugriffsrechte über `icacls`.

Der Schlüssel ist die feste Zeichenkette `12int i = 1128?_*-` aus dem Programm. Das Anmeldepasswort von VR-NetWorld oder der Bank wird dabei nicht verwendet. Eine andere Zeichenkette lässt sich mit `--key` übergeben, falls eine andere Programmversion einen anderen festen Schlüssel benutzt.

## Was mit einer Zelle passiert

Das Programm geht alle Tabellen durch und entscheidet pro Zelle, nicht nach Spaltenname. In den Umsätzen ist das Buchungsdatum zum Beispiel eine normale Zahl. Betrag, Währung, Name und Verwendungszweck liegen dagegen als verschlüsselter Text vor. Eine Zelle gilt als verschlüsselt, wenn nach dem ersten Schritt unten mindestens 17 Byte übrig sind und vom 17 Byte langen Kopf wenigstens zwölf den Wert `01` haben.

Verschlüsseln und Entschlüsseln sind dieselben Schritte in umgekehrter Reihenfolge. `Codieren128` ist symmetrisch: dieselbe Operation, die den Klartext in die Nutzlast verwandelt, macht aus der Nutzlast wieder den Klartext.

So entsteht der gespeicherte Inhalt:

1. Der Text wird byteweise als Windows-Text (cp1252) gelesen.
2. `Codieren128` verschlüsselt diese Byte. Aus dem festen Schlüssel werden dafür zuerst 16 Byte abgeleitet. Damit läuft eine Stromchiffre, die jedes Datenbyte mit dem nächsten Byte des Schlüsselstroms verknüpft.
3. Eine Textzelle kann kein Nullbyte enthalten. War ein Byte der verschlüsselten Nutzlast `00`, wird es durch `X` (`58`) ersetzt. Im Kopf merkt sich ein gesetztes Bit diese Stelle. Jedes Kopfbyte steht für acht Nutzlastbyte und ist ohne gesetztes Bit der Wert `01`. Mit gesetztem Bit ist es `01` plus den Wert dieses Bits.
4. Vor die Nutzlast werden diese 17 Kopfbyte gesetzt. Byte ab `80` landen in der SQLite-Datei oft als zwei UTF-8-Byte, weil sie als Latin-1-Zeichen gespeichert wurden. Sequenzen, die mit `C2` oder `C3` beginnen, sind so ein Paar. Andere Byte bleiben einzeln stehen.

Beim Entschlüsseln läuft das rückwärts. Zuerst werden solche UTF-8-Paare wieder zu einem Byte zusammengezogen. Dann trennt das Programm die 17 Kopfbyte von der Nutzlast und setzt jedes markierte `X` zurück auf `00`. `Codieren128` entschlüsselt nur die Nutzlast, der Kopf bleibt außen vor. Die entstandenen Byte werden wieder als cp1252 gelesen. Die wenigen Werte, die cp1252 nicht kennt, gelten als Latin-1. Dieser Text ersetzt in der Kopie den bisherigen Zellinhalt.

## Tests

```text
python3 -m unittest discover -s tests
```

Dafür muss `src` auf `PYTHONPATH` liegen. Unter Unix ist das `PYTHONPATH=src`, unter Windows `set PYTHONPATH=src`.
