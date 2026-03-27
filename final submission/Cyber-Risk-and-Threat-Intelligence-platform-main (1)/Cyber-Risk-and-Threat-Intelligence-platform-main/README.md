# 🛡️ Cyber Risk & Threat Intelligence Platform

A Python-based cybersecurity platform that combines **Nmap network scanning**, **VirusTotal threat intelligence**, and **automated risk scoring** into an interactive Streamlit dashboard. It scans targets, detects dangerous open ports and services, checks URLs against VirusTotal's threat database, and generates composite risk scores with email alerting.

---

## 📁 Project Structure

```
Cyber-Risk-and-Threat-Intelligence-platform/
│
├── dashboard.py                  # Main Streamlit app — entry point
├── database.py                   # SQLite persistence layer
├── .env                          # API keys & credentials (not committed)
├── requirements.txt              # Python dependencies
├── sample_test_targets.txt       # Sample scan targets
├── cyberscan_logo-removebg-preview.png  # App logo
│
├── scanners/
│   ├── __init__.py
│   ├── risk_scoring.py           # Composite risk scoring engine
│   ├── nmap_scanner/
│   │   ├── __init__.py
│   │   └── nmap_scanner.py       # Nmap scan runner & XML parser
│   └── vt_scanner/
│       ├── __init__.py
│       └── vt_scanner.py         # VirusTotal API client
│
└── scans/                        # Auto-created; stores Nmap XML output files
```
---

## 📸 Screenshots


[screenshots - Cyber Risk and Threat Intelligence Platform.pdf](https://github.com/user-attachments/files/26314005/screenshots.-.Cyber.Risk.and.Threat.Intelligence.Platform.pdf)

---

## 📦 Libraries Used

| Library | Purpose |
|---|---|
| `streamlit` | Interactive web dashboard UI |
| `pandas` | Data manipulation and DataFrame operations |
| `plotly` | Interactive charts and visualizations |
| `requests` | HTTP calls to the VirusTotal API |
| `python-dotenv` | Loading secrets from `.env` file |
| `sqlite3` *(stdlib)* | Persisting scan history to a local database |
| `subprocess` *(stdlib)* | Running Nmap as a system process |
| `xml.etree.ElementTree` *(stdlib)* | Parsing Nmap's XML output |
| `smtplib` *(stdlib)* | Sending email alerts via Gmail SMTP |
| `base64` *(stdlib)* | URL encoding for VirusTotal API requests |

---

## 🗂️ File Descriptions

### `dashboard.py`
The main entry point for the application. Run with `streamlit run dashboard.py`. Handles:
- Loading credentials and scan targets from the `.env` file
- Orchestrating scans across all configured targets by calling `risk_scoring.getScore()`
- Rendering the Streamlit UI: summary cards, risk score tables, Plotly bar/gauge charts, and scan history
- Sending email alerts via Gmail SMTP when high-severity targets are detected
- Saving completed scan results to the SQLite database via `database.py`

### `database.py`
Handles all SQLite operations — no scanning or scoring logic lives here. Responsibilities:
- `init_db()` — creates the `scans` table on first run
- `save_scan(df, targets)` — persists a completed scan's DataFrame (port-level results) and summary stats (total hosts, critical/high counts, max/avg risk scores) as a JSON blob
- `load_scans()` — retrieves historical scan records for display in the dashboard's history tab

### `scanners/nmap_scanner/nmap_scanner.py`
Wraps Nmap as a subprocess and parses the resulting XML. Key functions:
- `run_nmap_scan(target)` — executes `nmap -Pn -sT -O -sV --script banner -oX` and saves results to `scans/<target>.xml`
- `parse_nmap_xml(xml_file)` — extracts open ports, service names, versions, OS guess, and banners from the XML
- Contains `DANGEROUS_SERVICES` and `DANGEROUS_PORT_COMBOS` dictionaries that tag high/medium-risk services (e.g., FTP, Telnet, RDP, Redis, MongoDB) with risk levels and reasons

### `scanners/vt_scanner/vt_scanner.py`
VirusTotal API v3 client. Key functions:
- `encodeUrl(url)` — Base64-encodes a URL for use in VirusTotal's endpoint
- `getData(url)` — makes authenticated GET requests using the `VT_API_KEY` from `.env`
- `isMalicious(target)` — returns `True` if any engine flagged the URL as malicious
- `run_vt_scan(target)` — fetches full analysis stats: total votes, malicious/suspicious/clean engine counts, reputation score, last analysis date, and number of malicious outbound links

### `scanners/risk_scoring.py`
The core scoring engine that combines Nmap and VT results into a single composite score (0–100). Key components:
- `PortRisk` and `RiskReport` dataclasses — structured containers for scan results
- `score_nmap(nmap_report)` — assigns scores based on dangerous services, open port count, SSL presence, unpatched/EOL OS signals
- `score_vt(vt_data)` — assigns scores based on malicious engine hits, suspicious hits, reputation, outlink malice, and data staleness
- `getScore(target)` — runs both scanners, combines scores with `clamp()`, and maps to a severity label: `CRITICAL / HIGH / MEDIUM / LOW / INFO`

---

## ⚙️ Setup & Run Instructions

### Prerequisites

- Python 3.9+
- [Nmap](https://nmap.org/download.html) installed and accessible on your system PATH
- A [VirusTotal API key](https://www.virustotal.com/gui/join-community) (free tier works)
- A Gmail account with an [App Password](https://support.google.com/accounts/answer/185833) for email alerts

### 1. Clone the Repository

```bash
git clone https://github.com/noornabeeha/Cyber-Risk-and-Threat-Intelligence-platform.git
cd Cyber-Risk-and-Threat-Intelligence-platform
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

`requirements.txt` includes:
```
python-dotenv==1.2.2
Requests==2.32.5
streamlit
pandas
plotly
```

### 3. Configure the `.env` File

Create a `.env` file in the project root (a template already exists):

```env
VT_API_KEY=your_virustotal_api_key_here
GMAIL_SENDER=your_email@gmail.com
GMAIL_PASSWORD=your_app_password_here
GMAIL_RECIPIENT=recipient@example.com
SCAN_TARGETS=scanme.nmap.org,testphp.vulnweb.com
```

> ⚠️ **Never commit your `.env` file.** It contains sensitive credentials.

| Variable | Description |
|---|---|
| `VT_API_KEY` | Your VirusTotal API v3 key |
| `GMAIL_SENDER` | Gmail address used to send alerts |
| `GMAIL_PASSWORD` | Gmail App Password (16-character, not your regular password) |
| `GMAIL_RECIPIENT` | Email address to receive high-risk alerts |
| `SCAN_TARGETS` | Comma-separated list of targets to scan |

### 4. Run the Dashboard

```bash
streamlit run dashboard.py
```

The app will open in your browser at `http://localhost:8501`.

---

## 🚀 How to Run the Project

1. **Ensure Nmap is installed** — verify with `nmap --version` in your terminal.
2. **Set up your `.env`** as described above.
3. **Launch the app:**
   ```bash
   streamlit run dashboard.py
   ```
4. **In the dashboard:**
   - The app automatically scans targets defined in `SCAN_TARGETS` (or falls back to the defaults: `testasp.vulnweb.com`, `testphp.vulnweb.com`, `zero.webappsecurity.com`)
   - Click **"Run Scan"** to start a new scan
   - View risk scores, severity levels, open ports, and VirusTotal results in the charts
   - Navigate to the **History** tab to review past scans stored in `cyberscan.db`
   - High-severity results will automatically trigger an email alert to `GMAIL_RECIPIENT`

> 💡 **Tip:** Nmap's `-O` (OS detection) flag may require elevated privileges on some systems. Run with `sudo` if OS detection fails.

---

## 🎯 About the Sample Targets

The `sample_test_targets.txt` file contains the following intentionally vulnerable / publicly available scan-safe targets:

| Target | Description |
|---|---|
| `scanme.nmap.org` | Official Nmap test host — explicitly provided by the Nmap project for testing purposes. Safe and legal to scan. |
| `testphp.vulnweb.com` | Acunetix's intentionally vulnerable PHP web application. Designed for security tool testing. |
| `demo.testfire.net` | IBM's AltoroMutual demo banking application, used to demonstrate web application security issues. |
| `testasp.vulnweb.com` | Acunetix's intentionally vulnerable ASP web application. Safe for security scanner testing. |
| `zero.webappsecurity.com` | HP/Micro Focus WebInspect demo site — an intentionally vulnerable banking web app used for security testing. |

> ⚠️ **Only scan targets you have explicit permission to test.** All sample targets above are publicly provided for security testing purposes.


## 👥 Team Members

| Name | GitHub |
|---|---|
| Dhanush Polasi | [@userid1](https://github.com/DhanushP545) |
| Sujithraa | [@userid2](https://github.com/Suji2007hub) |
| Akshay Bakale | [@userid3](https://github.com/AkshayBakale/) |
| Eswar V | [@userid4](https://github.com/eswar0113) |

**Repository:** [https://github.com/noornabeeha/Cyber-Risk-and-Threat-Intelligence-platform](https://github.com/noornabeeha/Cyber-Risk-and-Threat-Intelligence-platform)

---

## 🤖 AI Tools Declaration

The following AI tools were used during the development of this project:

| Tool | Usage |
|---|---|
| **Claude (Anthropic)** | Generating boilerplate Streamlit layout code (column structure, metric cards, custom CSS) Suggesting Plotly chart configurations Drafting the HTML email template structure for the automated alert Reviewing and improving error-handling logic |


> This declaration is made in the interest of academic integrity and transparency. All AI-assisted content was reviewed, verified, and adapted by the team.

---

*Last updated: March 2026*
