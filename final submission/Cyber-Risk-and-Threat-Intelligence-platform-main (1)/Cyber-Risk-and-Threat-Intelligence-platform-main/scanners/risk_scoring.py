
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
import json
from .nmap_scanner import scan_and_return_xml
from .vt_scanner import run_vt_scan
# Score values
NMAP_RISK_BASE = {"high": 40, "medium": 20, "low": 5}
OPEN_PORT_PENALTY = 5
SSL_BONUS = -10
UNPATCHED_PENALTY = 15
EOL_OS_PENALTY = 20
EOL_OS_KEYWORDS = ["windows xp", "windows 2000", "linux 2.4", "linux 2.6", "linux 4.0"]

# VT score values
VT_MALICIOUS_WEIGHT = 35
VT_SUSPICIOUS_WEIGHT = 10
VT_OUTLINK_WEIGHT = 15
VT_REPUTATION_DIVISOR = 10
VT_STALE_DAYS = 30
VT_STALE_PENALTY = 10

# Severity thresholds
SEVERITY = [(80, "CRITICAL"), (60, "HIGH"), (40, "MEDIUM"), (20, "LOW"), (0, "INFO")]


@dataclass
class PortRisk:
    portid: str
    service: str
    state: str
    risk_tag: Optional[str]
    risk_reason: Optional[str]
    score: int
    findings: list[str] = field(default_factory=list)


@dataclass
class RiskReport:
    target: str
    scan_time: str
    composite_score: int
    severity: str
    port_results: list[PortRisk]
    nmap_score: int
    vt_score: int
    findings: list[str]
    breakdown: dict


def clamp(val): return max(0, min(100, val))

def get_severity(score):
    for threshold, label in SEVERITY:
        if score >= threshold:
            return label
    return "INFO"


def score_nmap(nmap_report):
    findings = []
    port_results = []
    port_total = 0

    if nmap_report.get("status") != "up":
        return 0, [], ["Host is down — no ports scored."], {}

    for port in nmap_report.get("ports", []):
        score = 0
        port_findings = []
        risk_tag    = port.get("risk")
        risk_reason = port.get("risk_reason")
        state       = port.get("state")
        tunnel      = port.get("tunnel")
        svc         = port.get("service", "unknown")
        portid      = port.get("portid", "?")

        if risk_tag in NMAP_RISK_BASE:
            score += NMAP_RISK_BASE[risk_tag]
            port_findings.append(f"Port {portid}/{svc}: {risk_tag.upper()} — {risk_reason}")

        if state == "open":
            score += OPEN_PORT_PENALTY

        if tunnel == "ssl" and risk_tag:
            score += SSL_BONUS
            port_findings.append(f"Port {portid}/{svc}: SSL mitigates risk")

        port_total += score
        port_results.append(PortRisk(portid, svc, state, risk_tag, risk_reason, clamp(score), port_findings))
        findings.extend(port_findings)

    # Average port score
    avg = clamp(port_total // len(port_results)) if port_results else 0

    # Uptime check
    uptime_bonus = 0
    uptime = nmap_report.get("uptime", {})
    if uptime.get("unpatched_signal"):
        uptime_bonus = UNPATCHED_PENALTY
        findings.append(f"Host up {uptime.get('seconds', 0) // 86400} days with no reboot — possible missed patches")

    # EOL OS check
    eol_bonus = 0
    os_guess = (nmap_report.get("os_guess") or "").lower()
    for kw in EOL_OS_KEYWORDS:
        if kw in os_guess:
            eol_bonus = EOL_OS_PENALTY
            findings.append(f"OS '{nmap_report['os_guess']}' may be outdated")
            break

    nmap_score = clamp(avg + uptime_bonus + eol_bonus)
    return nmap_score, port_results, findings, {"port_avg": avg, "uptime": uptime_bonus, "eol_os": eol_bonus}


def score_vt(vt_data):
    findings = []

    if not vt_data:
        return 0, ["VT data unavailable"], {}

    stats        = vt_data.get("last_analysis_stats", {})
    malicious    = stats.get("malicious", 0)
    suspicious   = stats.get("suspicious", 0)
    total        = vt_data.get("total_agents", 1) or 1
    reputation   = vt_data.get("reputation", 0)
    outlinks     = vt_data.get("malicious_outlinks", 0)
    last_scan    = vt_data.get("last_analysis_date")

    mal_score = clamp(int((malicious / total) * VT_MALICIOUS_WEIGHT * total))
    sus_score = clamp(int((suspicious / total) * VT_SUSPICIOUS_WEIGHT * total))
    out_score = clamp(outlinks * VT_OUTLINK_WEIGHT)
    rep_score = clamp(abs(reputation) // VT_REPUTATION_DIVISOR) if reputation < 0 else 0

    #can be removed once we integrate the dashboard
    if malicious > 0:
        findings.append(f"VT: {malicious}/{total} engines flagged as malicious")
    if suspicious > 0:
        findings.append(f"VT: {suspicious}/{total} engines flagged as suspicious")
    if outlinks > 0:
        findings.append(f"VT: {outlinks} malicious outgoing link(s) found")
    if reputation < 0:
        findings.append(f"VT: Negative reputation ({reputation})")

    # Stale scan check
    stale_score = 0
    if last_scan:
        try:
            age = (datetime.utcnow() - datetime.utcfromtimestamp(last_scan)).days
            if age > VT_STALE_DAYS:
                stale_score = VT_STALE_PENALTY
                findings.append(f"VT: Last scan {age} days old — may be stale")
        except Exception:
            pass

    vt_score = clamp(mal_score + sus_score + out_score + rep_score + stale_score)
    return vt_score, findings, {"malicious": mal_score, "suspicious": sus_score, "outlinks": out_score, "reputation": rep_score, "stale": stale_score}


def calculate_risk(nmap_report, vt_data=None):
    nmap_score, port_results, nmap_findings, nmap_bd = score_nmap(nmap_report)
    vt_score, vt_findings, vt_bd                     = score_vt(vt_data)

    # Weighted composite score (nmap 55%, vt 45%)
    composite = clamp(int(nmap_score * 0.55 + vt_score * 0.45))

    return RiskReport(
        target          = nmap_report.get("target", "unknown"),
        scan_time       = datetime.utcnow().isoformat(timespec="seconds") + "Z",
        composite_score = composite,
        severity        = get_severity(composite),
        port_results    = port_results,
        nmap_score      = nmap_score,
        vt_score        = vt_score,
        findings        = nmap_findings + vt_findings or ["No significant risks detected."],
        breakdown       = {"nmap": nmap_bd, "vt": vt_bd, "composite": composite},
    )

#can be removed when integrated with dashboard
def print_report(report):
    print(f"\n{'='*55}")
    print(f"  Target   : {report.target}")
    print(f"  Severity : {report.severity}")
    print(f"  Score    : {report.composite_score}/100  (nmap={report.nmap_score}, vt={report.vt_score})")
    print(f"{'='*55}")
    print("\n  PORTS:")
    for p in report.port_results:
        tag = f"[{p.risk_tag.upper()}]" if p.risk_tag else "[OK]"
        print(f"    {tag:10} {p.portid}/{p.service}")
    print("\n  FINDINGS:")
    for i, f in enumerate(report.findings, 1):
        print(f"    {i}. {f}")
    print(f"\n{'='*55}\n")

def getScore(target):
    #make sure target url is base64 encoded
    _, nmap_report = scan_and_return_xml(target)
    vt_data        = run_vt_scan(target)
    report = calculate_risk(nmap_report, vt_data)
    return report.__dict__ #converting the report object into a dictionary.

