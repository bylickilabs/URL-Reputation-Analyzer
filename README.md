# 🌐 URL Reputation Analyzer

|<img width="1280" height="640" alt="logo" src="https://github.com/user-attachments/assets/c296be1b-1bcf-41e6-8b9c-ac2f61f1f39a" />|
|---|

Ein leistungsstarkes, lokal arbeitendes Tool zur Analyse und Bewertung von URLs. 
Es hilft dabei, verdächtige oder unbekannte Links sicher zu überprüfen – komplett offline oder optional mit API-Anbindung (z. B. VirusTotal).

---

## German

### 🧩 Übersicht
Der **URL Reputation Analyzer** wurde entwickelt, um Administratoren, Forensikern und Entwicklern eine einfache Möglichkeit zu geben, URLs auf potenzielle Risiken zu überprüfen. 
Die Anwendung kann Domains extrahieren, DNS- und WHOIS-Abfragen durchführen und lokale Hashvergleiche bekannter bösartiger Domains vornehmen. 
Optional kann sie über die VirusTotal API erweitert werden.

### 🛠 Funktionen
- Analyse verdächtiger URLs (lokal/offline)
- WHOIS- und DNS-Abfragen
- Hash-Vergleich mit bekannter Malware-Liste
- IP- und Geoinformationen
- Optional: VirusTotal-Integration via API-Key (`config.py`)
- Mehrsprachig (Deutsch/Englisch)
- GUI mit Info-Button und GitHub-Link

### ⚙️ Systemanforderungen
- **Python 3.10 oder höher**
- Erforderliche Pakete:

```bash
pip install requests dnspython python-whois geocoder
```

### ▶️ Ausführen
```bash
python app.py
```

### 🔑 API-Integration
1. Lege eine Datei `config.py` im Projektverzeichnis an.
2. Trage deinen API-Key ein:
```python
VT_API_KEY = "YOUR_API_KEY_HERE"
```
3. Wenn kein Key vorhanden ist, arbeitet das Tool automatisch offline.

### 📜 Lizenz
Dieses Projekt steht unter der [LICENSE](LICENSE).

<br>

---

<br>

## English

### 🧩 Overview
The **URL Reputation Analyzer** is a local-first tool for analyzing and evaluating URLs. 
It helps users securely verify suspicious or unknown links – fully offline or optionally using APIs such as VirusTotal.

### 🛠 Features
- Local/offline URL analysis
- WHOIS and DNS lookups
- Hash comparison with known malicious domains
- IP and geolocation information
- Optional VirusTotal integration via API key (`config.py`)
- Dual-language support (German/English)
- GUI with Info button and GitHub link

### ⚙️ Requirements
- **Python 3.10 or higher**
- Required dependencies:

```bash
pip install requests dnspython python-whois geocoder
```

### ▶️ Run
```bash
python app.py
```

### 🔑 API Integration
1. Create a `config.py` file in your project directory.
2. Add your API key:
```python
VT_API_KEY = "YOUR_API_KEY_HERE"
```
3. If no key is provided, the tool automatically operates in offline mode.

### 📜 License
This project is licensed under the [LICENSE](LICENSE).

---
© 2025 – Developed with precision and security in mind.
