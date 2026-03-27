# README — Web Application Vulnerability Scanning, Risk Evaluation & Alert System
Project Overview

A Streamlit-based security dashboard that scans target URLs for vulnerabilities, 
visualises risk through interactive charts, and automatically dispatches HTML 
email alerts when High or Critical findings are detected. The full application lives in dashboard.py;
the notebook .ipynb documents each requirement and contains the launch cells for Google Colab.

Prerequisites

Python 3.10+
nmap (system tool, 7.x+)
cloudflared (system tool, latest)
Google Colab (recommended runtime)


# Setup & Run Instructions
Option A — Google Colab (Recommended)

Open the .ipynb in Google Colab.
Add the following Colab Secrets (key icon in the left panel):

API_KEY : your VirusTotal API key
GMAIL_SENDER : Gmail address used to send alerts
GMAIL_PASSWORD : Gmail App Password (16-character, not your account password)


Run the cells in order:

Cell A : installs nmap, streamlit, plotly, and cloudflared

Cell B : writes dashboard.py to disk

Cell C : writes .streamlit/config.toml (dark theme)

Cell D : launches Streamlit on port 8501

Cell E : creates a Cloudflare tunnel and prints a public URL

Click on the cloudflare link or -
Copy the trycloudflare.com URL from Cell E output and open it in any browser.

Option B (Local Machine)
bash# 1. Install system dependency
sudo apt-get install -y nmap        # Linux
brew install nmap                 # macOS


# Run Instructions
streamlit run dashboard.py
```

Open `http://localhost:8501` in your browser.

---

## Using the Dashboard

1. Enter one or more target hostnames or IPs in the sidebar (one per line).
2. Enter a recipient email address for alerts.
3. Click **Run Scan**.
4. Review the KPI cards, charts, and alert cards.
5. If any High or Critical findings are detected, an HTML email is sent automatically.

---

## Libraries Used

**Python Standard Library**
- `subprocess` — executes nmap as a system process
- `xml.etree.ElementTree` — parses nmap XML output
- `smtplib` — sends email via Gmail SMTP
- `email.mime.*` — constructs multipart HTML email messages
- `os` — environment variable access and directory management
- `threading` — runs Streamlit in a background thread (Colab)
- `time` — startup delay for Streamlit in Colab

**Third-Party Packages**
- `streamlit` — web dashboard framework
- `plotly` / `plotly.express` — interactive charts (donut pie, stacked bar, line, horizontal bar)
- `requests` — VirusTotal API HTTP calls
- `pandas` — DataFrame creation and styling (Streamlit dependency)

**System Tools**
- `nmap` — network port scanning and service detection (`-Pn -sV` flags)
- `cloudflared` — Cloudflare tunnel for public URL exposure from Colab

**External APIs**
- VirusTotal v3 `/domains/{target}` — domain reputation lookup
- Gmail SMTP `smtp.gmail.com:587` — automated alert delivery

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `API_KEY` | Optional | VirusTotal key — skipped gracefully if absent |
| `GMAIL_SENDER` | Required for alerts | Gmail address used as sender |
| `GMAIL_PASSWORD` | Required for alerts | Gmail App Password |

Credentials are never hardcoded. In Colab they are read from Secrets; locally they are read via `os.environ.get()`.

---
```
# Project Structure

.ipynb    ← Main notebook (requirements + launch cells)

dashboard.py              ← Streamlit app (written to disk by Cell B)

scan_results/             ← nmap XML outputs (created at runtime)

.streamlit/config.toml   ← Dark theme configuration

# Declaration of AI Tools Used
Claude (Anthropic) was used during development for the following purposes:

Generating boilerplate Streamlit layout code (column structure, metric cards, custom CSS)
Suggesting Plotly chart configurations
Drafting the HTML email template structure for the automated alert
Reviewing and improving error-handling logic

All AI-generated suggestions were reviewed, tested, and integrated by myself.
Core logic : the vulnerability classification rules, severity scoring, alert trigger condition, and dashboard layout decisions were authored independently.
No AI tool was used to write or submit assessment answers directly.

here are attached files for reference. 
[screenshots of threat scanner.docx](https://github.com/user-attachments/files/26113873/screenshots.of.threat.scanner.docx)
[Gmail - [CRITICAL] Vulnerability Alert for testphp.vulnweb.com.pdf](https://github.com/user-attachments/files/26113867/Gmail.-.CRITICAL.Vulnerability.Alert.for.testphp.vulnweb.com.pdf)

