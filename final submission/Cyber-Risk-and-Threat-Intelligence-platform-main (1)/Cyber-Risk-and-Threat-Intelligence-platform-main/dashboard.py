# dashboard.py  — run with:  streamlit run dashboard.py
# Lives at:  CYBER-RISK-AND-THREAT.../dashboard.py  (project root)
# Imports from:  scanners/risk_scoring.py  via  scanners.risk_scoring
# Credentials from:  .env  (project root)

import sys
import os

# ─── PATH SETUP ───────────────────────────────────────────────────────────────
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# ─── STANDARD LIBRARY ─────────────────────────────────────────────────────────
import smtplib
import time
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# ─── THIRD-PARTY ──────────────────────────────────────────────────────────────
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# ─── LOAD .env  ───────────────────────────────────────────────────────────────
try:
    from dotenv import load_dotenv
    load_dotenv(dotenv_path=os.path.join(ROOT_DIR, ".env"), override=False)
except ImportError:
    pass

# ─── CREDENTIALS ─────────────────────────────────────────────────────────────
VT_API_KEY      = os.environ.get("VT_API_KEY", "")
sender_email    = os.environ.get("GMAIL_SENDER", "")
app_password    = os.environ.get("GMAIL_PASSWORD", "")
recipient_email = os.environ.get("GMAIL_RECIPIENT", "")
targets_env     = os.environ.get("SCAN_TARGETS", "")

DEFAULT_TARGETS = "testasp.vulnweb.com,testphp.vulnweb.com,zero.webappsecurity.com"
targets = [t.strip() for t in (targets_env or DEFAULT_TARGETS).split(",") if t.strip()]

# ─── SCAN OUTPUT DIRECTORY ────────────────────────────────────────────────────
SCAN_DIR = os.path.join(ROOT_DIR, "scans")
os.makedirs(SCAN_DIR, exist_ok=True)

# ─── IMPORT getScore ──────────────────────────────────────────────────────────
_import_err_msg = ""
try:
    from scanners.risk_scoring import getScore
    RISK_SCORING_AVAILABLE = True
except Exception as _import_err:
    RISK_SCORING_AVAILABLE = False
    _import_err_msg = str(_import_err)

# ─── DATABASE ─────────────────────────────────────────────────────────────────
try:
    from database import save_scan, load_history, load_scan_by_id, delete_scan
    DB_AVAILABLE = True
except Exception as _db_err:
    DB_AVAILABLE = False

# ─── PAGE CONFIG ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="CyberScan Pro",
    page_icon="shield",
    layout="wide"
)

# ─── CUSTOM CSS ───────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap');

html, body, [class*="css"] { font-family: 'Rajdhani', sans-serif; }

.kpi-card {
    background: linear-gradient(135deg, #0d1117 0%, #161b22 100%);
    border: 1px solid #30363d;
    border-radius: 12px;
    padding: 1.2rem 1.4rem;
    text-align: center;
    position: relative;
    overflow: hidden;
}
.kpi-card::before {
    content: ''; position: absolute;
    top: 0; left: 0; right: 0; height: 2px;
    background: linear-gradient(90deg, #00d4ff, #0070f3);
}
.kpi-card.critical::before { background: linear-gradient(90deg, #ff4444, #ff0000); }
.kpi-card.warning::before  { background: linear-gradient(90deg, #ff9900, #ff6600); }
.kpi-card.safe::before     { background: linear-gradient(90deg, #00d68f, #00a86b); }
.kpi-label {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.7rem; color: #8b949e;
    letter-spacing: 0.15em; text-transform: uppercase; margin-bottom: 0.3rem;
}
.kpi-value {
    font-size: 2.2rem; font-weight: 700; color: #e6edf3;
    line-height: 1; font-family: 'Share Tech Mono', monospace;
}
.kpi-sub { font-size: 0.72rem; color: #6e7681; margin-top: 0.3rem; }

.badge {
    display: inline-block; padding: 0.2rem 0.7rem; border-radius: 20px;
    font-family: 'Share Tech Mono', monospace; font-size: 0.75rem;
    font-weight: 700; letter-spacing: 0.1em;
}
.badge-critical { background: rgba(255,68,68,0.15);  color: #ff4444; border: 1px solid #ff4444; }
.badge-high     { background: rgba(255,153,0,0.15);  color: #ff9900; border: 1px solid #ff9900; }
.badge-medium   { background: rgba(255,204,0,0.15);  color: #ffcc00; border: 1px solid #ffcc00; }
.badge-low      { background: rgba(0,214,143,0.15);  color: #00d68f; border: 1px solid #00d68f; }
.badge-info     { background: rgba(0,212,255,0.15);  color: #00d4ff; border: 1px solid #00d4ff; }

.section-header {
    font-family: 'Share Tech Mono', monospace; font-size: 0.7rem;
    letter-spacing: 0.25em; color: #0070f3; text-transform: uppercase;
    margin-bottom: 0.5rem; padding-bottom: 0.3rem; border-bottom: 1px solid #21262d;
}
</style>
""", unsafe_allow_html=True)

# ─── CHART THEME ──────────────────────────────────────────────────────────────
CHART_BG   = "#0d1117"
GRID_COL   = "#21262d"
FONT_COLOR = "#e6edf3"
SEV_COLORS = {
    "CRITICAL": "#ff4444",
    "HIGH":     "#ff9900",
    "MEDIUM":   "#ffcc00",
    "LOW":      "#00d68f",
    "INFO":     "#00d4ff",
}

# ─── SESSION STATE ────────────────────────────────────────────────────────────
for _k in ["reports", "scan_time", "last_refreshed"]:
    if _k not in st.session_state:
        st.session_state[_k] = None

# ─── SAMPLE DATA ──────────────────────────────────────────────────────────────
SAMPLE_REPORTS = [
    {
        "target": "example-host-1.com", "scan_time": "2025-01-01T00:00:00Z",
        "composite_score": 72, "severity": "HIGH",
        "nmap_score": 65, "vt_score": 80,
        "port_results": [
            {"portid": "22",  "service": "ssh",    "state": "open", "risk_tag": "medium", "score": 25},
            {"portid": "21",  "service": "ftp",    "state": "open", "risk_tag": "high",   "score": 45},
            {"portid": "80",  "service": "http",   "state": "open", "risk_tag": "low",    "score": 10},
            {"portid": "443", "service": "https",  "state": "open", "risk_tag": "low",    "score": 5},
            {"portid": "23",  "service": "telnet", "state": "open", "risk_tag": "high",   "score": 45},
        ],
        "findings": [
            "Port 21/ftp: HIGH -- FTP transmits credentials in plaintext",
            "Port 23/telnet: HIGH -- Telnet is unencrypted",
            "VT: 3/72 engines flagged as malicious",
        ],
        "breakdown": {
            "nmap": {"port_avg": 26, "uptime": 15, "eol_os": 0},
            "vt":   {"malicious": 35, "suspicious": 10, "outlinks": 0, "reputation": 5, "stale": 0},
        },
    },
    {
        "target": "example-host-2.com", "scan_time": "2025-01-01T00:00:00Z",
        "composite_score": 38, "severity": "MEDIUM",
        "nmap_score": 30, "vt_score": 48,
        "port_results": [
            {"portid": "80",   "service": "http",       "state": "open", "risk_tag": "low",    "score": 10},
            {"portid": "443",  "service": "https",      "state": "open", "risk_tag": "low",    "score": 5},
            {"portid": "8080", "service": "http-proxy", "state": "open", "risk_tag": "medium", "score": 25},
            {"portid": "3306", "service": "mysql",      "state": "open", "risk_tag": "high",   "score": 45},
        ],
        "findings": [
            "Port 3306/mysql: HIGH -- Database exposed to internet",
            "VT: 1/72 engines flagged as suspicious",
        ],
        "breakdown": {
            "nmap": {"port_avg": 21, "uptime": 0, "eol_os": 0},
            "vt":   {"malicious": 0, "suspicious": 10, "outlinks": 15, "reputation": 0, "stale": 10},
        },
    },
    {
        "target": "example-host-3.com", "scan_time": "2025-01-01T00:00:00Z",
        "composite_score": 15, "severity": "LOW",
        "nmap_score": 10, "vt_score": 20,
        "port_results": [
            {"portid": "80",  "service": "http",  "state": "open", "risk_tag": "low", "score": 10},
            {"portid": "443", "service": "https", "state": "open", "risk_tag": "low", "score": 5},
        ],
        "findings": ["VT: Last scan 45 days old -- may be stale"],
        "breakdown": {
            "nmap": {"port_avg": 7, "uptime": 0, "eol_os": 0},
            "vt":   {"malicious": 0, "suspicious": 0, "outlinks": 0, "reputation": 0, "stale": 10},
        },
    },
]

# ─── HELPERS ──────────────────────────────────────────────────────────────────
def reports_to_df(reports: list) -> pd.DataFrame:
    """Flatten list of getScore() dicts into one row per port."""
    rows = []
    for r in reports:
        target   = r.get("target", "unknown")
        comp     = r.get("composite_score", 0)
        sev      = r.get("severity", "INFO")
        nmap_sc  = r.get("nmap_score", 0)
        vt_sc    = r.get("vt_score", 0)
        bd       = r.get("breakdown", {})
        findings = r.get("findings", [])

        common = dict(
            target           = target,
            composite_score  = comp,
            severity         = sev,
            nmap_score       = nmap_sc,
            vt_score         = vt_sc,
            bd_port_avg      = bd.get("nmap", {}).get("port_avg", 0),
            bd_uptime        = bd.get("nmap", {}).get("uptime", 0),
            bd_eol_os        = bd.get("nmap", {}).get("eol_os", 0),
            bd_vt_malicious  = bd.get("vt", {}).get("malicious", 0),
            bd_vt_suspicious = bd.get("vt", {}).get("suspicious", 0),
            bd_vt_outlinks   = bd.get("vt", {}).get("outlinks", 0),
            bd_vt_reputation = bd.get("vt", {}).get("reputation", 0),
            bd_vt_stale      = bd.get("vt", {}).get("stale", 0),
            findings         = " | ".join(findings) if isinstance(findings, list) else str(findings),
        )

        port_results = r.get("port_results", [])
        if not port_results:
            rows.append({**common, "portid": "N/A", "service": "N/A",
                         "state": "N/A", "risk_tag": "ok", "port_score": 0})
            continue

        for p in port_results:
            if isinstance(p, dict):
                portid     = p.get("portid", "?")
                service    = p.get("service", "unknown")
                state      = p.get("state", "?")
                risk_tag   = p.get("risk_tag") or "ok"
                port_score = p.get("score", 0)
            else:
                portid     = p.portid
                service    = p.service
                state      = p.state
                risk_tag   = p.risk_tag or "ok"
                port_score = p.score
            rows.append({**common, "portid": portid, "service": service,
                         "state": state, "risk_tag": risk_tag, "port_score": port_score})

    return pd.DataFrame(rows) if rows else pd.DataFrame()


def kpi_card(label: str, value, sub: str = "", variant: str = "") -> str:
    return (f'<div class="kpi-card {variant}">'
            f'<div class="kpi-label">{label}</div>'
            f'<div class="kpi-value">{value}</div>'
            f'<div class="kpi-sub">{sub}</div></div>')


def make_gauge(value: int, title: str, sev: str) -> go.Figure:
    color = SEV_COLORS.get(sev, "#00d4ff")
    fig = go.Figure(go.Indicator(
        mode="gauge+number", value=value,
        title={"text": title, "font": {"color": FONT_COLOR, "size": 12,
                                        "family": "Share Tech Mono"}},
        number={"font": {"color": color, "size": 26, "family": "Share Tech Mono"}},
        gauge={
            "axis":       {"range": [0, 100], "tickcolor": GRID_COL,
                           "tickfont": {"color": "#6e7681", "size": 8}},
            "bar":        {"color": color, "thickness": 0.25},
            "bgcolor":    CHART_BG, "bordercolor": GRID_COL,
            "steps": [
                {"range": [0,  20],  "color": "rgba(0,214,143,0.12)"},
                {"range": [20, 40],  "color": "rgba(0,212,255,0.08)"},
                {"range": [40, 60],  "color": "rgba(255,204,0,0.10)"},
                {"range": [60, 80],  "color": "rgba(255,153,0,0.12)"},
                {"range": [80, 100], "color": "rgba(255,68,68,0.15)"},
            ],
            "threshold": {"line": {"color": color, "width": 3},
                          "thickness": 0.8, "value": value},
        }
    ))
    fig.update_layout(height=220, margin=dict(l=20, r=20, t=40, b=10),
                      paper_bgcolor=CHART_BG, font_color=FONT_COLOR)
    return fig


def send_alert_email(sender, password, recipient, df_high, scan_time):
    body = ("=" * 60 + "\n  CYBERSCAN PRO -- HIGH RISK ALERT\n" + "=" * 60 + "\n\n"
            + f"Scan completed        : {scan_time}\n"
            + f"High/Critical entries : {len(df_high)}\n"
            + f"Affected hosts        : {df_high['target'].nunique()}\n\n"
            + "-" * 60 + "\n")
    for _, row in df_high.iterrows():
        body += (f"  Host     : {row['target']}\n  Port     : {row['portid']}\n"
                 f"  Service  : {row['service']}\n  Severity : {row['severity']}\n"
                 f"  Score    : {row['composite_score']}\n\n")
    body += "Generated by CyberScan Pro\n"

    msg = MIMEMultipart()
    msg["From"]    = sender
    msg["To"]      = recipient
    msg["Subject"] = f"CyberScan Alert -- {len(df_high)} High/Critical Entries"
    msg.attach(MIMEText(body, "plain"))
    try:
        srv = smtplib.SMTP("smtp.gmail.com", 587)
        srv.starttls()
        srv.login(sender, password)
        srv.send_message(msg)
        srv.quit()
        return True
    except Exception as e:
        return str(e)


# ─── DATA SOURCE (early, so sidebar filters can use df) ───────────────────────
is_sample = st.session_state.reports is None
reports   = st.session_state.reports if not is_sample else SAMPLE_REPORTS
df        = reports_to_df(reports)

# ─── SIDEBAR ──────────────────────────────────────────────────────────────────
st.sidebar.image("cyberscan_logo-removebg-preview.png", width=100)
st.sidebar.title("CyberScan Pro")
st.sidebar.divider()

st.sidebar.title("Dashboard Mode")
view_mode = st.sidebar.radio(
    "Select your expertise level:",
    ["Naive User", "Technical User"]
)
st.sidebar.divider()

# ─── SIDEBAR FILTERS (between Dashboard Mode and Settings) ────────────────────
st.sidebar.subheader("Filter Results")
all_targets  = sorted(df["target"].unique().tolist())  if not df.empty else []
all_services = sorted(df["service"].unique().tolist()) if not df.empty else []

sel_target = st.sidebar.selectbox("Filter by Target",  ["All"] + all_targets)
sel_svc    = st.sidebar.selectbox("Filter by Service", ["All"] + all_services)
sel_sev    = st.sidebar.multiselect(
    "Filter by Severity",
    ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
    default=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
)
st.sidebar.divider()

st.sidebar.title("⚙️ Settings")
st.sidebar.caption("Configure your scanner.")

target_input = st.sidebar.text_area("Enter Targets (comma or newline separated)", value="")
targets = [t.strip() for t in target_input.replace('\n', ',').split(',') if t.strip()]

st.sidebar.divider()
st.sidebar.subheader("🔑 API Key")
VT_API_KEY = st.sidebar.text_input("Enter VirusTotal API Key", type="password")

st.sidebar.divider()
st.sidebar.subheader("✉️ Email Setup")
recipient_email = st.sidebar.text_input("Alert Recipient Address")

st.sidebar.subheader("Scan Controls")
scan_button    = st.sidebar.button("Run Full Scan",  use_container_width=True, type="primary")
refresh_button = st.sidebar.button("Refresh Scan",   use_container_width=True)
st.sidebar.divider()

# ─── STATUS BLOCK ─────────────────────────────────────────────────────────────
st.sidebar.subheader("Status")

if not RISK_SCORING_AVAILABLE:
    st.sidebar.error(f"scanners import failed:\n{_import_err_msg}")
else:
    st.sidebar.success("scanners package loaded")

if VT_API_KEY:
    st.sidebar.success("VT_API_KEY ready")
else:
    st.sidebar.error("VT_API_KEY not set in .env")

if sender_email and app_password and recipient_email:
    st.sidebar.success("Email credentials ready")
else:
    st.sidebar.warning("Email secrets missing in .env")

st.sidebar.caption(f"Targets: {', '.join(targets)}")
st.sidebar.divider()

# ─── RUN SCAN ─────────────────────────────────────────────────────────────────
if scan_button or refresh_button:
    if refresh_button:
        st.session_state.reports        = None
        st.session_state.scan_time      = None
        st.session_state.last_refreshed = None

    if not RISK_SCORING_AVAILABLE:
        st.error(
            "Could not import `scanners.risk_scoring`.\n\n"
            "Make sure:\n"
            "- `scanners/__init__.py` exists\n"
            "- `scanners/nmap_scanner/__init__.py` and `nmap_scanner.py` exist\n"
            "- `scanners/vt_scanner/__init__.py` and `vt_scanner.py` exist\n\n"
            f"Error detail: {_import_err_msg}"
        )
    elif not VT_API_KEY:
        st.error("VT_API_KEY not set. Add it to your `.env` file in the project root.")
    elif not targets:
        st.error("No targets configured. Set SCAN_TARGETS in `.env`.")
    else:
        collected = []
        bar    = st.progress(0)
        status = st.empty()

        for i, target in enumerate(targets):
            status.info(f"Scanning {target}...  ({i + 1}/{len(targets)})")
            try:
                report_dict = getScore(target)
                collected.append(report_dict)
            except Exception as e:
                st.warning(f"Scan failed for `{target}`: {e}")
            bar.progress((i + 1) / len(targets))

        bar.empty()
        if collected:
            st.session_state.reports        = collected
            st.session_state.scan_time      = time.strftime("%Y-%m-%d %H:%M:%S")
            st.session_state.last_refreshed = datetime.now().strftime("%d %b %Y  %H:%M:%S")
            status.success(f"Scan complete -- {len(collected)} target(s) processed.")
            if DB_AVAILABLE:
                try:
                    _save_df = reports_to_df(collected)
                    save_scan(_save_df, targets)
                except Exception as _db_save_err:
                    st.warning(f"History save failed: {_db_save_err}")
        else:
            status.error("No results returned. Check connectivity and credentials.")

# ─── HEADER ───────────────────────────────────────────────────────────────────
col_title, col_ref, col_btn = st.columns([6, 3, 1])
with col_title:
    st.image("cyberscan_logo-removebg-preview.png", width=150)
    st.title("CyberScan Pro")
    st.caption("Professional Network Reconnaissance & Threat Intelligence Dashboard")
with col_ref:
    if st.session_state.last_refreshed:
        st.info(f"Last refreshed: {st.session_state.last_refreshed}")
    elif is_sample:
        st.warning("Showing **sample data** — click **Run Full Scan** to scan live targets.")
    else:
        st.info("No scan run yet.")
with col_btn:
    if st.button("Reset", help="Clear results and reset", use_container_width=True):
        st.session_state.reports        = None
        st.session_state.scan_time      = None
        st.session_state.last_refreshed = None
        st.rerun()

st.divider()
filt = df.copy()
if not filt.empty:
    if sel_target != "All": filt = filt[filt["target"]  == sel_target]
    if sel_svc    != "All": filt = filt[filt["service"] == sel_svc]
    if sel_sev:             filt = filt[filt["severity"].isin(sel_sev)]

# ─── KPI CARDS (always visible) ───────────────────────────────────────────────
data_label = "SAMPLE DATA" if is_sample else "LIVE DATA"
st.markdown(f'<div class="section-header">Key Metrics -- {data_label}</div>',
            unsafe_allow_html=True)

target_summary = (
    df.groupby("target").agg(
        composite_score=("composite_score", "first"),
        severity       =("severity",        "first"),
        nmap_score     =("nmap_score",      "first"),
        vt_score       =("vt_score",        "first"),
        open_ports     =("portid", lambda x: len([p for p in x if p != "N/A"])),
    ).reset_index()
    if not df.empty
    else pd.DataFrame(columns=["target", "composite_score", "severity",
                                "nmap_score", "vt_score", "open_ports"])
)

n_targets   = len(target_summary)
n_ports     = int(target_summary["open_ports"].sum())       if not target_summary.empty else 0
avg_score   = int(target_summary["composite_score"].mean()) if not target_summary.empty else 0
max_score   = int(target_summary["composite_score"].max())  if not target_summary.empty else 0
worst_sev   = (target_summary.loc[target_summary["composite_score"].idxmax(), "severity"]
               if not target_summary.empty else "N/A")
n_high_crit = len(target_summary[target_summary["severity"].isin(["HIGH", "CRITICAL"])])
avg_vt      = int(target_summary["vt_score"].mean())        if not target_summary.empty else 0


def _variant(sev: str) -> str:
    return {"CRITICAL": "critical", "HIGH": "critical", "MEDIUM": "warning",
            "LOW": "safe", "INFO": ""}.get(sev, "")


k1, k2, k3, k4, k5, k6 = st.columns(6)
for col, lbl, val, sub, var in [
    (k1, "Targets Scanned", n_targets,   "hosts in scope",          ""),
    (k2, "Open Ports",      n_ports,     "across all targets",       "warning" if n_ports > 5 else "safe"),
    (k3, "Avg Risk Score",  avg_score,   "composite 0-100",          _variant(worst_sev)),
    (k4, "Peak Risk Score", max_score,   f"severity: {worst_sev}",   _variant(worst_sev)),
    (k5, "High/Crit Hosts", n_high_crit, "need immediate attention", "critical" if n_high_crit else "safe"),
    (k6, "Avg VT Score",    avg_vt,      "VirusTotal threat signal", "warning" if avg_vt > 30 else "safe"),
]:
    with col:
        st.markdown(kpi_card(lbl, val, sub, var), unsafe_allow_html=True)

if is_sample:
    st.caption("KPIs above reflect sample data. Run a real scan to populate live results.")

st.divider()

# ─── TABS ─────────────────────────────────────────────────────────────────────
tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
    "Charts",
    "Scan Data",
    "Threat Intel",
    "Export",
    "About KPIs",
    "History",
])



# ══════════════════════════════════════════════════════════════════════════════
# TAB 1 -- CHARTS
# ══════════════════════════════════════════════════════════════════════════════
with tab1:
    st.subheader("Interactive Charts")
    st.caption("Hover for details  |  Drag to zoom  |  Double-click to reset  |  Click legend to toggle")

    if df.empty:
        st.info("No data to chart -- run a scan first.")

    elif view_mode == "Naive User":
        # ── 4 CHARTS: 2 columns × 2 rows ─────────────────────────────────────
        st.markdown("#### Simplified View")

        _CHART_H = 360  # uniform height keeps both rows equal

        # ── ROW 1 ─────────────────────────────────────────────────────────────
        n_r1c1, n_r1c2 = st.columns(2)

        # [1][1] -- Open Ports per Target (bar)
        with n_r1c1:
            fig = px.bar(
                target_summary, x="target", y="open_ports",
                title="Open Ports per Target",
                color="open_ports",
                color_continuous_scale=["#00d68f", "#ffcc00", "#ff4444"],
                text="open_ports",
                labels={"target": "Target", "open_ports": "Open Ports"},
            )
            fig.update_traces(textposition="outside")
            fig.update_layout(
                height=_CHART_H, showlegend=False,
                paper_bgcolor=CHART_BG, plot_bgcolor=CHART_BG,
                font_color=FONT_COLOR,
                xaxis=dict(gridcolor=GRID_COL),
                yaxis=dict(gridcolor=GRID_COL),
                margin=dict(t=50, b=20, l=20, r=20),
                title_font=dict(family="Share Tech Mono", size=13),
            )
            st.plotly_chart(fig, use_container_width=True)

        # [1][2] -- Severity Distribution (pie / donut)
        with n_r1c2:
            sev_c = target_summary["severity"].value_counts().reset_index()
            sev_c.columns = ["Severity", "Count"]
            fig = px.pie(
                sev_c, names="Severity", values="Count",
                title="Severity Distribution",
                color="Severity", color_discrete_map=SEV_COLORS, hole=0.55,
            )
            fig.update_traces(textinfo="percent+label")
            fig.update_layout(
                height=_CHART_H,
                paper_bgcolor=CHART_BG,
                font_color=FONT_COLOR,
                legend=dict(bgcolor=CHART_BG),
                margin=dict(t=50, b=20, l=20, r=20),
                title_font=dict(family="Share Tech Mono", size=13),
            )
            st.plotly_chart(fig, use_container_width=True)

        # ── ROW 2 ─────────────────────────────────────────────────────────────
        n_r2c1, n_r2c2 = st.columns(2)

        # [2][1] -- Network Risk vs Threat Intelligence (scatter)
        with n_r2c1:
            fig = px.scatter(
                target_summary, x="nmap_score", y="vt_score",
                size="composite_score", color="severity",
                color_discrete_map=SEV_COLORS,
                hover_name="target", text="target",
                title="Network Risk vs Threat Intelligence",
                labels={
                    "nmap_score": "Network Risk (Nmap)",
                    "vt_score":   "Threat Intel (VirusTotal)",
                },
            )
            fig.update_traces(textposition="top center")
            fig.update_layout(
                height=_CHART_H,
                paper_bgcolor=CHART_BG, plot_bgcolor=CHART_BG,
                font_color=FONT_COLOR,
                xaxis=dict(gridcolor=GRID_COL, range=[-5, 105]),
                yaxis=dict(gridcolor=GRID_COL, range=[-5, 105]),
                legend=dict(bgcolor=CHART_BG),
                margin=dict(t=50, b=20, l=20, r=20),
                title_font=dict(family="Share Tech Mono", size=13),
            )
            st.plotly_chart(fig, use_container_width=True)

        # [2][2] -- Risk Hierarchy Sunburst
        with n_r2c2:
            _naive_port_df = df[(df["portid"] != "N/A") & (df["service"] != "N/A")].copy()
            if not _naive_port_df.empty:
                fig_sb_n = px.sunburst(
                    _naive_port_df,
                    path=["target", "severity", "service"],
                    values="composite_score",
                    color="severity",
                    color_discrete_map=SEV_COLORS,
                    title="Risk Hierarchy: Host → Severity → Service",
                )
                fig_sb_n.update_layout(
                    height=_CHART_H,
                    paper_bgcolor=CHART_BG,
                    font_color=FONT_COLOR,
                    margin=dict(t=50, b=20, l=20, r=20),
                    title_font=dict(family="Share Tech Mono", size=13),
                )
                st.plotly_chart(fig_sb_n, use_container_width=True)
            else:
                st.info("No port data available for sunburst chart.")

    else:
        # ── 9 CHARTS: 3 columns × 3 rows ─────────────────────────────────────
        st.markdown("#### Technical Deep-Dive")
        port_df = df[df["portid"] != "N/A"].copy()

        _CHART_H = 340  # uniform height keeps all rows equal

        # Pre-compute shared data frames used across rows
        # Risk tag distribution
        rt = port_df.groupby(["target", "risk_tag"]).size().reset_index(name="count") if not port_df.empty else pd.DataFrame()

        # Services exposed
        svc_c = pd.DataFrame()
        if not port_df.empty:
            svc_c = port_df["service"].value_counts().reset_index()
            svc_c.columns = ["Service", "Count"]

        # VT sub-score breakdown (melt)
        vt_cols = ["bd_vt_malicious", "bd_vt_suspicious", "bd_vt_outlinks",
                   "bd_vt_reputation", "bd_vt_stale"]
        vt_bd = df.groupby("target")[vt_cols].first().reset_index()
        vt_m  = vt_bd.melt(id_vars="target", var_name="Component", value_name="Score")
        vt_m["Component"] = vt_m["Component"].str.replace("bd_vt_", "VT: ").str.title()

        # Host-level agg for bubble chart
        host_agg = df.groupby("target").agg(
            exposure=("nmap_score",      "max"),
            threat  =("vt_score",        "max"),
            risk    =("composite_score", "max"),
            services=("service", lambda x: ", ".join(sorted(set(x) - {"N/A"}))),
            severity=("severity",        "first"),
        ).reset_index()

        # Avg risk per service
        svc_risk = pd.DataFrame()
        if not port_df.empty:
            svc_risk = (
                port_df[port_df["service"] != "N/A"]
                .groupby("service")["composite_score"]
                .mean()
                .reset_index()
            )
            svc_risk.columns = ["Service", "Avg Risk"]
            svc_risk = svc_risk.sort_values("Avg Risk", ascending=True)

        # Port score heatmap pivot
        heat = pd.DataFrame()
        if not port_df.empty:
            heat = port_df.pivot_table(
                index="service", columns="target",
                values="port_score", aggfunc="max"
            ).fillna(0)

        # Sunburst data
        _tech_sb_df = port_df[port_df["service"] != "N/A"].copy()

        # ── ROW 1 ─────────────────────────────────────────────────────────────
        t_r1c1, t_r1c2, t_r1c3 = st.columns(3)

        # [1][1] -- Port Risk Tag Distribution (stacked bar)
        with t_r1c1:
            if not rt.empty:
                fig = px.bar(
                    rt, x="target", y="count", color="risk_tag",
                    title="Port Risk Tag Distribution",
                    color_discrete_map={"high": "#ff4444", "medium": "#ff9900",
                                        "low": "#00d68f", "ok": "#00d4ff"},
                    barmode="stack", text="count",
                )
                fig.update_traces(textposition="inside")
                fig.update_layout(
                    height=_CHART_H,
                    paper_bgcolor=CHART_BG, plot_bgcolor=CHART_BG,
                    font_color=FONT_COLOR,
                    xaxis=dict(gridcolor=GRID_COL),
                    yaxis=dict(gridcolor=GRID_COL),
                    legend=dict(bgcolor=CHART_BG),
                    margin=dict(t=50, b=20, l=20, r=20),
                    title_font=dict(family="Share Tech Mono", size=12),
                )
                st.plotly_chart(fig, use_container_width=True)

        # [1][2] -- Services Exposed (horizontal bar)
        with t_r1c2:
            if not svc_c.empty:
                fig = px.bar(
                    svc_c, x="Count", y="Service", orientation="h",
                    title="Services Exposed (all targets)",
                    color="Count",
                    color_continuous_scale=["#00d68f", "#ffcc00", "#ff4444"],
                    text="Count",
                )
                fig.update_layout(
                    height=_CHART_H, showlegend=False,
                    paper_bgcolor=CHART_BG, plot_bgcolor=CHART_BG,
                    font_color=FONT_COLOR,
                    yaxis=dict(categoryorder="total ascending", gridcolor=GRID_COL),
                    xaxis=dict(gridcolor=GRID_COL),
                    margin=dict(t=50, b=20, l=20, r=20),
                    title_font=dict(family="Share Tech Mono", size=12),
                )
                st.plotly_chart(fig, use_container_width=True)

        # [1][3] -- VT Score Breakdown (stacked bar)
        with t_r1c3:
            fig = px.bar(
                vt_m, x="target", y="Score", color="Component",
                title="VT Score Breakdown per Target",
                color_discrete_sequence=["#ff4444", "#ff9900", "#ffcc00", "#00d4ff", "#8b949e"],
                barmode="stack", text="Score",
            )
            fig.update_traces(textposition="inside")
            fig.update_layout(
                height=_CHART_H,
                paper_bgcolor=CHART_BG, plot_bgcolor=CHART_BG,
                font_color=FONT_COLOR,
                xaxis=dict(gridcolor=GRID_COL),
                yaxis=dict(gridcolor=GRID_COL),
                legend=dict(bgcolor=CHART_BG),
                margin=dict(t=50, b=20, l=20, r=20),
                title_font=dict(family="Share Tech Mono", size=12),
            )
            st.plotly_chart(fig, use_container_width=True)

        # ── ROW 2 ─────────────────────────────────────────────────────────────
        t_r2c1, t_r2c2, t_r2c3 = st.columns(3)

        # [2][1] -- Composite Risk vs Open Ports (scatter)
        with t_r2c1:
            fig = px.scatter(
                target_summary, x="open_ports", y="composite_score",
                size="composite_score", color="severity",
                color_discrete_map=SEV_COLORS, size_max=50,
                hover_name="target", text="target",
                title="Composite Risk vs Open Ports",
                labels={"open_ports": "Open Ports",
                        "composite_score": "Composite Risk Score"},
            )
            fig.update_traces(textposition="top center",
                              marker=dict(line=dict(width=1, color="#30363d")))
            fig.update_layout(
                height=_CHART_H,
                paper_bgcolor=CHART_BG, plot_bgcolor=CHART_BG,
                font_color=FONT_COLOR,
                xaxis=dict(gridcolor=GRID_COL),
                yaxis=dict(gridcolor=GRID_COL, range=[-5, 110]),
                legend=dict(bgcolor=CHART_BG),
                margin=dict(t=50, b=20, l=20, r=20),
                title_font=dict(family="Share Tech Mono", size=12),
            )
            st.plotly_chart(fig, use_container_width=True)

        # [2][2] -- VT Score Breakdown (stacked bar, same as [1][3] but distinct colour sequence)
        with t_r2c2:
            fig = px.bar(
                vt_m, x="target", y="Score", color="Component",
                title="VT Component Detail",
                color_discrete_sequence=["#ff4444", "#ff9900", "#ffcc00", "#00d4ff", "#8b949e"],
                barmode="stack", text="Score",
            )
            fig.update_traces(textposition="inside")
            fig.update_layout(
                height=_CHART_H,
                paper_bgcolor=CHART_BG, plot_bgcolor=CHART_BG,
                font_color=FONT_COLOR,
                xaxis=dict(gridcolor=GRID_COL),
                yaxis=dict(gridcolor=GRID_COL),
                legend=dict(bgcolor=CHART_BG),
                margin=dict(t=50, b=20, l=20, r=20),
                title_font=dict(family="Share Tech Mono", size=12),
            )
            st.plotly_chart(fig, use_container_width=True)

        # [2][3] -- Risk Heatmap Bubble (exposure vs threat)
        with t_r2c3:
            if not host_agg.empty:
                fig_bub = px.scatter(
                    host_agg,
                    x="exposure", y="threat",
                    size="risk", size_max=50,
                    color="risk",
                    color_continuous_scale="RdYlGn_r",
                    text="target",
                    hover_data=["services", "severity"],
                    title="Exposure vs Threat Bubble",
                    labels={"exposure": "Exposure (Nmap)",
                            "threat":   "Threat (VT)"},
                )
                fig_bub.update_traces(textposition="top center")
                fig_bub.update_layout(
                    height=_CHART_H,
                    paper_bgcolor=CHART_BG, plot_bgcolor=CHART_BG,
                    font_color=FONT_COLOR,
                    xaxis=dict(gridcolor=GRID_COL),
                    yaxis=dict(gridcolor=GRID_COL),
                    coloraxis_colorbar_title="Risk",
                    margin=dict(t=50, b=20, l=20, r=20),
                    title_font=dict(family="Share Tech Mono", size=12),
                )
                st.plotly_chart(fig_bub, use_container_width=True)

        # ── ROW 3 ─────────────────────────────────────────────────────────────
        t_r3c1, t_r3c2, t_r3c3 = st.columns(3)

        # [3][1] -- Average Risk Score per Service (horizontal bar)
        with t_r3c1:
            if not svc_risk.empty:
                fig_hb = px.bar(
                    svc_risk,
                    x="Avg Risk", y="Service",
                    orientation="h",
                    color="Avg Risk",
                    color_continuous_scale="RdYlGn_r",
                    text="Avg Risk",
                    title="Avg Risk Score per Service",
                )
                fig_hb.update_traces(texttemplate="%{text:.1f}", textposition="outside")
                fig_hb.update_layout(
                    height=_CHART_H,
                    paper_bgcolor=CHART_BG, plot_bgcolor=CHART_BG,
                    font_color=FONT_COLOR,
                    coloraxis_showscale=False,
                    xaxis=dict(gridcolor=GRID_COL),
                    yaxis=dict(gridcolor=GRID_COL, categoryorder="total ascending"),
                    margin=dict(t=50, b=20, l=80, r=60),
                    title_font=dict(family="Share Tech Mono", size=12),
                )
                st.plotly_chart(fig_hb, use_container_width=True)

        # [3][2] -- Port Score Heatmap (service × target)
        with t_r3c2:
            if not heat.empty:
                fig = px.imshow(
                    heat,
                    color_continuous_scale=["#0d1117", "#ffcc00", "#ff4444"],
                    title="Port Score Heatmap (Service × Target)",
                    aspect="auto",
                )
                fig.update_layout(
                    height=_CHART_H,
                    paper_bgcolor=CHART_BG, plot_bgcolor=CHART_BG,
                    font_color=FONT_COLOR,
                    margin=dict(t=50, b=20, l=20, r=20),
                    title_font=dict(family="Share Tech Mono", size=12),
                )
                st.plotly_chart(fig, use_container_width=True)

        # [3][3] -- Risk Hierarchy Sunburst
        with t_r3c3:
            if not _tech_sb_df.empty:
                fig_sb_t = px.sunburst(
                    _tech_sb_df,
                    path=["target", "severity", "service"],
                    values="composite_score",
                    color="severity",
                    color_discrete_map=SEV_COLORS,
                    title="Risk Hierarchy: Host → Severity → Service",
                )
                fig_sb_t.update_layout(
                    height=_CHART_H,
                    paper_bgcolor=CHART_BG,
                    font_color=FONT_COLOR,
                    margin=dict(t=50, b=20, l=20, r=20),
                    title_font=dict(family="Share Tech Mono", size=12),
                )
                st.plotly_chart(fig_sb_t, use_container_width=True)
            else:
                st.info("No port data for sunburst.")

# ══════════════════════════════════════════════════════════════════════════════
# TAB 2 -- SCAN DATA
# ════════════════════════════════════════════════════════════════════════════


with tab2:
    st.subheader("Scan Results")

    if df.empty:
        st.info("No data yet -- run a scan.")
    else:
        st.caption(f"Showing {len(filt)} of {len(df)} rows after filters")

        if view_mode == "Naive User":
            naive_cols = ["target", "portid", "service", "state", "risk_tag",
                          "severity", "composite_score"]
            disp = filt[[c for c in naive_cols if c in filt.columns]].copy()
            disp.columns = ["Target", "Port", "Service", "State", "Risk Tag",
                             "Severity", "Risk Score"]
        else:
            tech_cols = ["target", "portid", "service", "state", "risk_tag",
                         "port_score", "composite_score", "nmap_score",
                         "vt_score", "severity", "findings"]
            disp = filt[[c for c in tech_cols if c in filt.columns]].copy()
            disp.columns = [c.replace("_", " ").title()
                            for c in tech_cols if c in filt.columns]

        st.write(disp.to_html(index=False), unsafe_allow_html=True)

    st.divider()
    st.subheader("Host Summary")
    if not target_summary.empty:
        ts_disp = target_summary.rename(columns={
            "target": "Target", "composite_score": "Risk Score",
            "severity": "Severity", "nmap_score": "Nmap Score",
            "vt_score": "VT Score", "open_ports": "Open Ports",
        })
        st.write(ts_disp.to_html(index=False), unsafe_allow_html=True)
# ══════════════════════════════════════════════════════════════════════════════
# TAB 3 -- THREAT INTEL
# ══════════════════════════════════════════════════════════════════════════════
with tab3:
    st.subheader("Threat Intelligence")

    if df.empty:
        st.info("No scan data -- run a scan first.")
    else:
        high_crit = filt[filt["severity"].isin(["CRITICAL", "HIGH"])].sort_values(
            "composite_score", ascending=False)
        med_risk  = filt[filt["severity"] == "MEDIUM"].sort_values(
            "composite_score", ascending=False)

        if high_crit.empty:
            st.success("No CRITICAL or HIGH severity hosts detected.")
        else:
            st.error(f"CRITICAL -- {len(high_crit)} high/critical entries across "
                     f"{high_crit['target'].nunique()} host(s). Immediate action required.")

        threat_cols = ["target", "portid", "service", "state", "risk_tag",
                       "composite_score", "severity"]

        with st.expander(f"Critical / High Risk Entries ({len(high_crit)})", expanded=True):
            if high_crit.empty:
                st.write("None found.")
            else:
                st.write(high_crit[[c for c in threat_cols if c in high_crit.columns]]
                         .to_html(index=False), unsafe_allow_html=True)

        with st.expander(f"Medium Risk Entries ({len(med_risk)})", expanded=False):
            if med_risk.empty:
                st.write("None found.")
            else:
                st.write(med_risk[[c for c in threat_cols if c in med_risk.columns]]
                         .to_html(index=False), unsafe_allow_html=True)

        st.divider()
        st.subheader("Per-Host Risk Breakdown")
        bd_df = df.groupby("target").agg(
            total_ports     =("portid",          lambda x: len([p for p in x if p != "N/A"])),
            high_crit_ports =("severity",        lambda x: x.isin(["HIGH", "CRITICAL"]).sum()),
            composite_score =("composite_score", "first"),
            severity        =("severity",        "first"),
            nmap_score      =("nmap_score",      "first"),
            vt_score        =("vt_score",        "first"),
            services        =("service",         lambda x: ", ".join(sorted(x.unique()))),
        ).reset_index().sort_values("composite_score", ascending=False)
        bd_df.columns = ["Target", "Total Ports", "High/Crit Ports", "Risk Score",
                          "Severity", "Nmap Score", "VT Score", "Services"]
        st.write(bd_df.to_html(index=False), unsafe_allow_html=True)

        if view_mode == "Technical User":
            st.divider()
            st.subheader("Findings Detail")
            for _, row in df.groupby("target")["findings"].first().reset_index().iterrows():
                with st.expander(f"{row['target']}"):
                    for f in row["findings"].split(" | "):
                        if f.strip():
                            st.write(f"- {f.strip()}")

        st.divider()
        st.subheader("Send Alert Email")

        if high_crit.empty:
            st.info("No critical entries -- email will confirm all-clear.")

        email_ready = bool(sender_email and app_password and recipient_email)
        if not email_ready:
            st.warning(
                "Email credentials missing. "
                "Add GMAIL_SENDER, GMAIL_PASSWORD, and GMAIL_RECIPIENT to your .env file."
            )

        send_btn = st.button(
            "Send Alert Email" if high_crit.empty
            else f"Send Alert Email ({len(high_crit)} high/critical entries)",
            type="primary", disabled=not email_ready, use_container_width=True,
        )
        if send_btn and email_ready:
            with st.spinner("Sending..."):
                result = send_alert_email(
                    sender_email, app_password, recipient_email,
                    high_crit, st.session_state.scan_time or "Unknown",
                )
            if result is True:
                st.success(f"Alert email sent to {recipient_email}!")
            else:
                st.error(f"Failed to send email: {result}")
                st.caption("Tip: verify your App Password has no spaces and 2-Step Verification is ON.")

# ══════════════════════════════════════════════════════════════════════════════
# TAB 4 -- EXPORT
# ══════════════════════════════════════════════════════════════════════════════
with tab4:
    st.subheader("Export Results")

    if df.empty:
        st.info("No data to export -- run a scan first.")
    else:
        ea, eb = st.columns(2)
        with ea:
            st.markdown("**Full Scan Results**")
            st.caption("All hosts and ports from the scan")
            st.download_button(
                "Download Full Results (CSV)",
                data=df.to_csv(index=False).encode("utf-8"),
                file_name="full_scan_results.csv",
                mime="text/csv",
                use_container_width=True,
            )
        with eb:
            st.markdown("**Filtered Results**")
            st.caption(f"Current filter -- {len(filt)} rows")
            st.download_button(
                "Download Filtered Results (CSV)",
                data=filt.to_csv(index=False).encode("utf-8"),
                file_name="filtered_scan_results.csv",
                mime="text/csv",
                use_container_width=True,
            )
        st.divider()
        st.markdown("**Host Summary Report**")
        st.download_button(
            "Download Host Summary (CSV)",
            data=target_summary.to_csv(index=False).encode("utf-8"),
            file_name="host_summary.csv",
            mime="text/csv",
        )

# ══════════════════════════════════════════════════════════════════════════════
# TAB 5 -- ABOUT KPIs
# ══════════════════════════════════════════════════════════════════════════════
with tab5:
    st.subheader("What Do These KPIs Mean?")

    if view_mode == "Naive User":
        st.markdown("""
**Targets Scanned** -- How many websites or servers were checked during the scan.

**Open Ports** -- Each open port is a potential entry point. Ports 80 (web) and 443 (secure web)
are normal. Ports like 21 (FTP) or 23 (Telnet) are risky because they transmit data unencrypted.

**Avg Risk Score** -- A 0-100 number combining network exposure and online reputation.
Think of it like a credit score for security; lower is safer.

**Peak Risk Score** -- The single highest score found across all targets.
If any host is high, take action immediately.

**High/Crit Hosts** -- Targets scoring above 60. These need urgent review.

**Avg VT Score** -- VirusTotal's threat signal. Zero means no antivirus engine flagged the host.
        """)
    else:
        st.markdown("""
**Composite Score** = `round(Nmap x 0.55 + VT x 0.45)`, clamped to [0, 100].

**Nmap Score** components:
- Per-port base from `NMAP_RISK_BASE`: high=40, medium=20, low=5
- +5 per open port (OPEN_PORT_PENALTY)
- -10 if SSL tunnel detected (SSL_BONUS)
- Averaged across all ports, then +15 for unpatched signal (UNPATCHED_PENALTY), +20 for EOL OS

**VT Score** components:
- (malicious / total) x 35 -- malicious engine hits
- (suspicious / total) x 10 -- suspicious engine hits
- outlinks x 15 -- malicious outbound links
- abs(reputation) / 10 -- negative reputation penalty
- +10 if last scan > 30 days old (stale penalty)

**Severity thresholds**: CRITICAL >= 80  |  HIGH >= 60  |  MEDIUM >= 40  |  LOW >= 20  |  INFO >= 0
        """)

        st.divider()
        st.markdown("**Score Constants Reference**")
        consts_df = pd.DataFrame([
            ("NMAP_RISK_BASE -- high",  40),
            ("NMAP_RISK_BASE -- medium", 20),
            ("NMAP_RISK_BASE -- low",    5),
            ("OPEN_PORT_PENALTY",        5),
            ("SSL_BONUS",              -10),
            ("UNPATCHED_PENALTY",       15),
            ("EOL_OS_PENALTY",          20),
            ("VT_MALICIOUS_WEIGHT",     35),
            ("VT_SUSPICIOUS_WEIGHT",    10),
            ("VT_OUTLINK_WEIGHT",       15),
            ("VT_REPUTATION_DIVISOR",   10),
            ("VT_STALE_PENALTY",        10),
            ("VT_STALE_DAYS",           30),
        ], columns=["Constant", "Value"])
        st.write(consts_df.to_html(index=False), unsafe_allow_html=True)

        st.divider()
        st.markdown("**VS Code Quick-Start**")
        st.code(
            "# 1. Install dependencies\n"
            "pip install streamlit plotly pandas python-dotenv\n\n"
            "# 2. Create .env in the project root\n"
            "VT_API_KEY=your_virustotal_api_key\n"
            "GMAIL_SENDER=you@gmail.com\n"
            "GMAIL_PASSWORD=xxxx xxxx xxxx xxxx\n"
            "GMAIL_RECIPIENT=alerts@example.com\n"
            "SCAN_TARGETS=examplescannerwebsite"
            "# 3. Run from the project root folder\n"
            "streamlit run dashboard.py",
            language="bash",
        )

# ══════════════════════════════════════════════════════════════════════════════
# TAB 6 -- HISTORY
# ══════════════════════════════════════════════════════════════════════════════
with tab6:
    st.subheader("Scan History")

    # ── Database availability guard ────────────────────────────────────────────
    if not DB_AVAILABLE:
        st.error(
            "History database is unavailable. "
            "Make sure `database.py` exists in the project root.\n\n"
            f"Error detail: {_db_err}"
        )
    else:
        history_df = load_history()

        if history_df.empty:
            st.info(
                "No scans saved yet. "
                "Run a live scan (click **Run Full Scan** in the sidebar) "
                "to start building your history."
            )
        else:
            # ── KPI row ───────────────────────────────────────────────────────
            st.markdown(
                '<div class="section-header">All-Time Statistics</div>',
                unsafe_allow_html=True,
            )
            hk1, hk2, hk3, hk4, hk5 = st.columns(5)
            _alltime_max  = float(history_df["max_risk_score"].max())
            _alltime_avg  = float(history_df["avg_risk_score"].mean())
            _total_crits  = int(history_df["critical_count"].sum())
            _total_highs  = int(history_df["high_count"].sum())
            _first_scan   = history_df["scan_time"].iloc[-1]   # oldest = last row (desc order)
            for _col, _lbl, _val, _sub, _var in [
                (hk1, "Total Scans",     len(history_df),             "runs saved",            ""),
                (hk2, "All-Time Peak",   f"{_alltime_max:.0f}",       "max composite score",   _variant("CRITICAL") if _alltime_max >= 80 else _variant("HIGH") if _alltime_max >= 60 else ""),
                (hk3, "Avg Risk (all)",  f"{_alltime_avg:.1f}",       "across all scan runs",  ""),
                (hk4, "Total Criticals", _total_crits,                "critical findings ever","critical" if _total_crits else "safe"),
                (hk5, "First Scan",      _first_scan[:10],            "date of earliest scan", ""),
            ]:
                with _col:
                    st.markdown(kpi_card(_lbl, _val, _sub, _var), unsafe_allow_html=True)

            st.divider()

            # ── Trend charts ──────────────────────────────────────────────────
            st.markdown('<div class="section-header">Risk Trend Over Time</div>',
                        unsafe_allow_html=True)

            # Reverse for chronological order in the chart
            trend_df = history_df.iloc[::-1].reset_index(drop=True)

            hc1, hc2 = st.columns(2)

            # Trend line: avg and max risk scores
            with hc1:
                fig_trend = go.Figure()
                fig_trend.add_trace(go.Scatter(
                    x=trend_df["scan_time"], y=trend_df["avg_risk_score"],
                    mode="lines+markers", name="Avg Risk",
                    line=dict(color="#00d4ff", width=2),
                    marker=dict(size=6),
                ))
                fig_trend.add_trace(go.Scatter(
                    x=trend_df["scan_time"], y=trend_df["max_risk_score"],
                    mode="lines+markers", name="Peak Risk",
                    line=dict(color="#ff4444", width=2, dash="dot"),
                    marker=dict(size=6),
                ))
                fig_trend.update_layout(
                    title="Risk Score Over Time",
                    height=320,
                    paper_bgcolor=CHART_BG, plot_bgcolor=CHART_BG,
                    font_color=FONT_COLOR,
                    xaxis=dict(gridcolor=GRID_COL, title="Scan Time"),
                    yaxis=dict(gridcolor=GRID_COL, range=[0, 105], title="Score"),
                    legend=dict(bgcolor=CHART_BG),
                    title_font=dict(family="Share Tech Mono", size=13),
                    margin=dict(t=50, b=20, l=20, r=20),
                )
                st.plotly_chart(fig_trend, use_container_width=True)

            # Severity trend: critical + high counts stacked bar
            with hc2:
                fig_sev = go.Figure()
                fig_sev.add_trace(go.Bar(
                    x=trend_df["scan_time"], y=trend_df["critical_count"],
                    name="Critical", marker_color="#ff4444",
                ))
                fig_sev.add_trace(go.Bar(
                    x=trend_df["scan_time"], y=trend_df["high_count"],
                    name="High", marker_color="#ff9900",
                ))
                fig_sev.update_layout(
                    barmode="stack",
                    title="Critical & High Findings per Scan",
                    height=320,
                    paper_bgcolor=CHART_BG, plot_bgcolor=CHART_BG,
                    font_color=FONT_COLOR,
                    xaxis=dict(gridcolor=GRID_COL, title="Scan Time"),
                    yaxis=dict(gridcolor=GRID_COL, title="Count"),
                    legend=dict(bgcolor=CHART_BG),
                    title_font=dict(family="Share Tech Mono", size=13),
                    margin=dict(t=50, b=20, l=20, r=20),
                )
                st.plotly_chart(fig_sev, use_container_width=True)

            st.divider()

            # ── History table ─────────────────────────────────────────────────
            st.markdown('<div class="section-header">Scan Log</div>',
                        unsafe_allow_html=True)

            disp_hist = history_df.rename(columns={
                "id":              "Scan ID",
                "scan_time":       "Date / Time",
                "targets":         "Targets",
                "total_hosts":     "Hosts",
                "total_ports":     "Ports",
                "critical_count":  "Critical",
                "high_count":      "High",
                "max_risk_score":  "Peak Score",
                "avg_risk_score":  "Avg Score",
            })
            st.dataframe(
                disp_hist,
                use_container_width=True,
                hide_index=True,
            )

            st.divider()

            # ── Drill into a past scan ────────────────────────────────────────
            st.markdown('<div class="section-header">Drill Into Past Scan</div>',
                        unsafe_allow_html=True)

            scan_options = {
                f"Scan #{row['id']}  —  {row['scan_time']}  ({row['targets']})": row["id"]
                for _, row in history_df.iterrows()
            }
            selected_label = st.selectbox(
                "Select a past scan to inspect:",
                options=list(scan_options.keys()),
                key="hist_drill_select",
            )
            selected_id = scan_options[selected_label]

            drill_df = load_scan_by_id(selected_id)

            if drill_df.empty:
                st.warning("No port-level data found for this scan.")
            else:
                st.caption(
                    f"Scan #{selected_id} — {len(drill_df)} port entries "
                    f"across {drill_df['target'].nunique() if 'target' in drill_df.columns else '?'} host(s)"
                )

                # Show simplified or full columns depending on mode
                if view_mode == "Naive User":
                    _show_cols = [c for c in
                                  ["target", "portid", "service", "state",
                                   "risk_tag", "severity", "composite_score"]
                                  if c in drill_df.columns]
                else:
                    _show_cols = [c for c in
                                  ["target", "portid", "service", "state", "risk_tag",
                                   "port_score", "composite_score", "nmap_score",
                                   "vt_score", "severity", "findings"]
                                  if c in drill_df.columns]

                st.dataframe(drill_df[_show_cols], use_container_width=True, hide_index=True)

                st.download_button(
                    label=f"⬇ Download Scan #{selected_id} as CSV",
                    data=drill_df.to_csv(index=False).encode("utf-8"),
                    file_name=f"cyberscan_history_{selected_id}.csv",
                    mime="text/csv",
                    use_container_width=True,
                )

            st.divider()

            # ── Delete a scan ─────────────────────────────────────────────────
            st.markdown('<div class="section-header">Delete a Scan Record</div>',
                        unsafe_allow_html=True)

            del_col1, del_col2 = st.columns([3, 1])
            with del_col1:
                del_label = st.selectbox(
                    "Choose a scan to delete:",
                    options=list(scan_options.keys()),
                    key="hist_del_select",
                )
                del_id = scan_options[del_label]
            with del_col2:
                st.write("")  # vertical spacing
                st.write("")
                if st.button(
                    f"🗑 Delete Scan #{del_id}",
                    type="primary",
                    use_container_width=True,
                    key="hist_del_btn",
                ):
                    delete_scan(del_id)
                    st.success(f"Scan #{del_id} deleted successfully.")
                    st.rerun()
