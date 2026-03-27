import subprocess
import xml.etree.ElementTree as ET
from xml.etree.ElementTree import Element, SubElement
from xml.dom import minidom
import os

SCAN_DIR = "./scans"
os.makedirs(SCAN_DIR, exist_ok=True)

DANGEROUS_SERVICES = {
    "ftp":     {"risk": "high",   "reason": "Cleartext credentials"},
    "telnet":  {"risk": "high",   "reason": "Unencrypted remote shell"},
    "http":    {"risk": "medium", "reason": "Unencrypted web traffic"},
    "smtp":    {"risk": "medium", "reason": "May relay spam / no auth"},
    "pop3":    {"risk": "medium", "reason": "Cleartext mail retrieval"},
    "imap":    {"risk": "medium", "reason": "Cleartext mail access"},
    "snmp":    {"risk": "high",   "reason": "Community string sniffing"},
    "rsh":     {"risk": "high",   "reason": "No authentication"},
    "rlogin":  {"risk": "high",   "reason": "No authentication"},
    "finger":  {"risk": "medium", "reason": "User enumeration"},
    "rpcbind": {"risk": "medium", "reason": "RPC exposure"},
    "vnc":     {"risk": "high",   "reason": "Often weakly auth'd remote desktop"},
    "ms-wbt-server": {"risk": "medium", "reason": "RDP brute-force target"},
}

DANGEROUS_PORT_COMBOS = {
    ("http",  "8080"): {"risk": "medium", "reason": "HTTP on alt port — often public-facing"},
    ("http",  "8000"): {"risk": "medium", "reason": "HTTP on dev port — may be unintentionally exposed"},
    ("ftp",   "21"):   {"risk": "high",   "reason": "FTP transmits credentials in plaintext"},
    ("telnet","23"):   {"risk": "high",   "reason": "Telnet is fully unencrypted"},
    ("smb",   "445"):  {"risk": "high",   "reason": "SMB — common ransomware/lateral movement vector"},
    ("smb",   "139"):  {"risk": "high",   "reason": "NetBIOS/SMB — legacy, frequently exploited"},
    ("rdp",   "3389"): {"risk": "high",   "reason": "RDP exposed — brute-force and CVE target"},
    ("vnc",   "5900"): {"risk": "high",   "reason": "VNC often has weak/no authentication"},
    ("redis", "6379"): {"risk": "high",   "reason": "Redis with no auth — full data exposure"},
    ("mysql", "3306"): {"risk": "high",   "reason": "Database exposed to internet"},
    ("mssql", "1433"): {"risk": "high",   "reason": "MSSQL exposed — credential brute-force risk"},
    ("postgresql","5432"): {"risk": "high","reason": "PostgreSQL exposed to internet"},
    ("mongodb","27017"):   {"risk": "high","reason": "MongoDB — historically misconfigured with no auth"},
    ("msrpc", "135"):  {"risk": "medium", "reason": "RPC endpoint mapper — Windows attack surface"},
    ("netbios-ns","137"): {"risk": "medium","reason": "NetBIOS name service — info disclosure risk"},
}


def run_nmap_scan(target: str) -> str:
    """
    Run a combined nmap scan:
      - -sT  : TCP connect scan (works without root)
      - -sV --version-intensity 5 : service/version detection
      - -O   : OS detection (requires root; gracefully skipped if unavailable)
      - -Pn  : treat host as up (no ping pre-check)
    Returns path to the XML output file.
    """
    xml_file = f"{SCAN_DIR}/{target}.xml"
    cmd = [
        "nmap",
        "-Pn",
        "-sT",
        "-O",
        "-sV", "--version-intensity", "5",
        "--script", "banner",          # grab banners where possible
        "-oX", xml_file,
        target,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"nmap failed: {result.stderr.strip()}")
    return xml_file


def parse_nmap_xml(xml_file: str) -> dict:
    """
    Parse enriched nmap XML and return a structured report dict:

      {
        "target":   <str>,
        "status":   "up" | "down",          # 1. host reachability
        "hostname": <str | None>,
        "address":  <str>,
        "addr_type": "ipv4" | "ipv6" | "mac",
        "uptime": {                          # 4. uptime / patch signal
            "seconds":    <int | None>,
            "last_boot":  <str | None>,
            "unpatched_signal": <bool>
        },
        "os_guess": <str | None>,
        "ports": [                           # per-port enrichments
          {
            "portid":    <str>,
            "protocol":  <str>,
            "state":     <str>,             # 2. open / filtered / closed
            "service":   <str>,
            "tunnel":    <str | None>,      # 3. "ssl" | None
            "product":   <str | None>,
            "version":   <str | None>,
            "conf":      <int | None>,      # 5. confidence 0-10
            "risk":      <str | None>,      # "high" | "medium" | None
            "risk_reason": <str | None>,
          },
          ...
        ]
      }

    Hosts that are down are returned with status="down" and an empty ports list.
    """
    root = ET.parse(xml_file).getroot()
    report = {}

    for host in root.findall("host"):
        # ── 1. Host status ────────────────────────────────────────────
        status_el = host.find("status")
        status     = status_el.get("state", "unknown") if status_el is not None else "unknown"

        # ── Address & hostname ────────────────────────────────────────
        addr_el   = host.find("address")
        address   = addr_el.get("addr",     "unknown") if addr_el is not None else "unknown"
        addr_type = addr_el.get("addrtype", "unknown") if addr_el is not None else "unknown"

        hostname_el = host.find(".//hostname")
        hostname    = hostname_el.get("name") if hostname_el is not None else None

        report["target"]    = hostname or address
        report["status"]    = status
        report["address"]   = address
        report["addr_type"] = addr_type
        report["hostname"]  = hostname

        # Skip further parsing if host is down
        if status != "up":
            report["uptime"]  = {}
            report["os_guess"] = None
            report["ports"]   = []
            return report

        # ── 4. Uptime ─────────────────────────────────────────────────
        uptime_el   = host.find(".//uptime")
        uptime_secs = None
        last_boot   = None
        if uptime_el is not None:
            raw = uptime_el.get("seconds")
            uptime_secs = int(raw) if raw and raw.isdigit() else None
            last_boot   = uptime_el.get("lastboot")   # e.g. "Thu Jun 15 08:22:01 2023"

        # Unpatched signal: if uptime > 90 days and no last_boot reboot clue
        unpatched_signal = bool(uptime_secs and uptime_secs > 90 * 86400)

        report["uptime"] = {
            "seconds":         uptime_secs,
            "last_boot":       last_boot,
            "unpatched_signal": unpatched_signal,
        }

        # ── OS guess ──────────────────────────────────────────────────
        os_match = host.find(".//osmatch")
        report["os_guess"] = os_match.get("name") if os_match is not None else None

        # ── Ports ─────────────────────────────────────────────────────
        ports = []
        for port in host.findall(".//port"):
            portid   = port.get("portid", "?")
            protocol = port.get("protocol", "tcp")

            # ── 2. Port state ─────────────────────────────────────────
            state_el = port.find("state")
            state    = state_el.get("state", "unknown") if state_el is not None else "unknown"

            # ── Service metadata ──────────────────────────────────────
            svc      = port.find("service")
            svc_name = "unknown"
            tunnel   = None   # 3. SSL tunnel flag
            product  = None
            version  = None
            conf     = None   # 5. confidence score

            if svc is not None:
                svc_name = svc.get("name",    "unknown")
                tunnel   = svc.get("tunnel",  None)          # 'ssl' or None
                product  = svc.get("product", None)
                version  = svc.get("version", None)
                raw_conf = svc.get("conf",    None)
                conf     = int(raw_conf) if raw_conf and raw_conf.isdigit() else None

            # ── Risk scoring ──────────────────────────────────────────
            risk        = None
            risk_reason = None

            # Combo check first (e.g. http on 8080)
            combo = DANGEROUS_PORT_COMBOS.get((svc_name, portid))
            if combo:
                risk        = combo["risk"]
                risk_reason = combo["reason"]
            elif svc_name in DANGEROUS_SERVICES:
                entry       = DANGEROUS_SERVICES[svc_name]
                risk        = entry["risk"]
                risk_reason = entry["reason"]

            # Upgrade risk if SSL wraps an otherwise plain service
            if tunnel == "ssl" and risk == "high":
                risk        = "medium"
                risk_reason = f"{risk_reason} (mitigated by SSL)"

            ports.append({
                "portid":      portid,
                "protocol":    protocol,
                "state":       state,
                "service":     svc_name,
                "tunnel":      tunnel,
                "product":     product,
                "version":     version,
                "conf":        conf,
                "risk":        risk,
                "risk_reason": risk_reason,
            })

        report["ports"] = ports
        return report   # one host per call; extend with a list if scanning ranges

    return {"status": "no_host_found", "ports": []}


# ── Convenience wrapper ───────────────────────────────────────────────────────

def scan_and_return_xml(target: str) -> tuple[str, dict]:
    """Run nmap scan on target and return (xml_file_path, parsed_report)."""
    xml_file = run_nmap_scan(target)
    report = parse_nmap_xml(xml_file)
    return xml_file, report

# ── Pretty printer ────────────────────────────────────────────────────────────

import xml.etree.ElementTree as ET
from xml.etree.ElementTree import Element, SubElement
from xml.dom import minidom

def report_to_xml(report: dict) -> str:
    """Write report to an XML file named <target>.xml and return the file path."""
    root = Element("report")

    # Basic info
    SubElement(root, "target").text   = str(report.get("target", ""))
    SubElement(root, "address").text  = str(report.get("address", ""))
    SubElement(root, "addrtype").text = str(report.get("addr_type", ""))
    SubElement(root, "hostname").text = str(report.get("hostname") or "")
    SubElement(root, "status").text   = str(report.get("status", ""))

    if report.get("status") != "up":
        SubElement(root, "note").text = "Host is unreachable — no port details available."
    else:
        # Uptime
        up = report.get("uptime", {})
        uptime_el = SubElement(root, "uptime")
        secs = up.get("seconds")
        SubElement(uptime_el, "days").text             = str(secs // 86400) if secs else "unknown"
        SubElement(uptime_el, "last_boot").text        = str(up.get("last_boot") or "unknown")
        SubElement(uptime_el, "unpatched_signal").text = str(up.get("unpatched_signal", False))

        # OS
        SubElement(root, "os_guess").text = str(report.get("os_guess") or "unknown")

        # Ports
        ports_el = SubElement(root, "ports")
        for p in report.get("ports", []):
            port_el = SubElement(ports_el, "port")
            SubElement(port_el, "portid").text      = str(p.get("portid", ""))
            SubElement(port_el, "protocol").text    = str(p.get("protocol", ""))
            SubElement(port_el, "state").text       = str(p.get("state", ""))
            SubElement(port_el, "service").text     = str(p.get("service", ""))
            SubElement(port_el, "tunnel").text      = str(p.get("tunnel") or "")
            SubElement(port_el, "product").text     = str(p.get("product") or "")
            SubElement(port_el, "version").text     = str(p.get("version") or "")
            SubElement(port_el, "conf").text        = str(p.get("conf") or "")
            SubElement(port_el, "risk").text        = str(p.get("risk") or "")
            SubElement(port_el, "risk_reason").text = str(p.get("risk_reason") or "")

    # Pretty-print and write
    xml_str   = minidom.parseString(ET.tostring(root, encoding="unicode")).toprettyxml(indent="  ")
    target    = report.get("target", "output")
    file_path = f"{SCAN_DIR}/{target}.xml"

    with open(file_path, "w") as f:
        f.write(xml_str)

    return file_path


# import subprocess
# import xml.etree.ElementTree as ET
# from xml.etree.ElementTree import Element, SubElement
# from xml.dom import minidom
# import os

# SCAN_DIR = "./scans"
# os.makedirs(SCAN_DIR, exist_ok=True)

# DANGEROUS_SERVICES = {
#     "ftp":     {"risk": "high",   "reason": "Cleartext credentials"},
#     "telnet":  {"risk": "high",   "reason": "Unencrypted remote shell"},
#     "http":    {"risk": "medium", "reason": "Unencrypted web traffic"},
#     "smtp":    {"risk": "medium", "reason": "May relay spam / no auth"},
#     "pop3":    {"risk": "medium", "reason": "Cleartext mail retrieval"},
#     "imap":    {"risk": "medium", "reason": "Cleartext mail access"},
#     "snmp":    {"risk": "high",   "reason": "Community string sniffing"},
#     "rsh":     {"risk": "high",   "reason": "No authentication"},
#     "rlogin":  {"risk": "high",   "reason": "No authentication"},
#     "finger":  {"risk": "medium", "reason": "User enumeration"},
#     "rpcbind": {"risk": "medium", "reason": "RPC exposure"},
#     "vnc":     {"risk": "high",   "reason": "Often weakly auth'd remote desktop"},
#     "ms-wbt-server": {"risk": "medium", "reason": "RDP brute-force target"},
# }

# DANGEROUS_PORT_COMBOS = {
#     ("http", "8080"): {"risk": "medium", "reason": "HTTP on alt port — often public-facing"},
#     ("http", "8000"): {"risk": "medium", "reason": "HTTP on dev port — may be unintentionally exposed"},
# }


# def run_nmap_scan(target: str) -> str:
#     """
#     Run a combined nmap scan:
#       - -sT  : TCP connect scan (works without root)
#       - -sV --version-intensity 5 : service/version detection
#       - -O   : OS detection (requires root; gracefully skipped if unavailable)
#       - -Pn  : treat host as up (no ping pre-check)
#     Returns path to the XML output file.
#     """
#     xml_file = f"{SCAN_DIR}/{target}.xml"
#     cmd = [
#         "nmap",
#         "-Pn",
#         "-sT",
#         "-O",
#         "-sV", "--version-intensity", "5",
#         "--script", "banner",          # grab banners where possible
#         "-oX", xml_file,
#         target,
#     ]
#     result = subprocess.run(cmd, capture_output=True, text=True)
#     if result.returncode != 0:
#         raise RuntimeError(f"nmap failed: {result.stderr.strip()}")
#     return xml_file


# def parse_nmap_xml(xml_file: str) -> dict:
#     """
#     Parse enriched nmap XML and return a structured report dict:

#       {
#         "target":   <str>,
#         "status":   "up" | "down",          # 1. host reachability
#         "hostname": <str | None>,
#         "address":  <str>,
#         "addr_type": "ipv4" | "ipv6" | "mac",
#         "uptime": {                          # 4. uptime / patch signal
#             "seconds":    <int | None>,
#             "last_boot":  <str | None>,
#             "unpatched_signal": <bool>
#         },
#         "os_guess": <str | None>,
#         "ports": [                           # per-port enrichments
#           {
#             "portid":    <str>,
#             "protocol":  <str>,
#             "state":     <str>,             # 2. open / filtered / closed
#             "service":   <str>,
#             "tunnel":    <str | None>,      # 3. "ssl" | None
#             "product":   <str | None>,
#             "version":   <str | None>,
#             "conf":      <int | None>,      # 5. confidence 0-10
#             "risk":      <str | None>,      # "high" | "medium" | None
#             "risk_reason": <str | None>,
#           },
#           ...
#         ]
#       }

#     Hosts that are down are returned with status="down" and an empty ports list.
#     """
#     root = ET.parse(xml_file).getroot()
#     report = {}

#     for host in root.findall("host"):
#         # ── 1. Host status ────────────────────────────────────────────
#         status_el = host.find("status")
#         status     = status_el.get("state", "unknown") if status_el is not None else "unknown"

#         # ── Address & hostname ────────────────────────────────────────
#         addr_el   = host.find("address")
#         address   = addr_el.get("addr",     "unknown") if addr_el is not None else "unknown"
#         addr_type = addr_el.get("addrtype", "unknown") if addr_el is not None else "unknown"

#         hostname_el = host.find(".//hostname")
#         hostname    = hostname_el.get("name") if hostname_el is not None else None

#         report["target"]    = hostname or address
#         report["status"]    = status
#         report["address"]   = address
#         report["addr_type"] = addr_type
#         report["hostname"]  = hostname

#         # Skip further parsing if host is down
#         if status != "up":
#             report["uptime"]  = {}
#             report["os_guess"] = None
#             report["ports"]   = []
#             return report

#         # ── 4. Uptime ─────────────────────────────────────────────────
#         uptime_el   = host.find(".//uptime")
#         uptime_secs = None
#         last_boot   = None
#         if uptime_el is not None:
#             raw = uptime_el.get("seconds")
#             uptime_secs = int(raw) if raw and raw.isdigit() else None
#             last_boot   = uptime_el.get("lastboot")   # e.g. "Thu Jun 15 08:22:01 2023"

#         # Unpatched signal: if uptime > 90 days and no last_boot reboot clue
#         unpatched_signal = bool(uptime_secs and uptime_secs > 90 * 86400)

#         report["uptime"] = {
#             "seconds":         uptime_secs,
#             "last_boot":       last_boot,
#             "unpatched_signal": unpatched_signal,
#         }

#         # ── OS guess ──────────────────────────────────────────────────
#         os_match = host.find(".//osmatch")
#         report["os_guess"] = os_match.get("name") if os_match is not None else None

#         # ── Ports ─────────────────────────────────────────────────────
#         ports = []
#         for port in host.findall(".//port"):
#             portid   = port.get("portid", "?")
#             protocol = port.get("protocol", "tcp")

#             # ── 2. Port state ─────────────────────────────────────────
#             state_el = port.find("state")
#             state    = state_el.get("state", "unknown") if state_el is not None else "unknown"

#             # ── Service metadata ──────────────────────────────────────
#             svc      = port.find("service")
#             svc_name = "unknown"
#             tunnel   = None   # 3. SSL tunnel flag
#             product  = None
#             version  = None
#             conf     = None   # 5. confidence score

#             if svc is not None:
#                 svc_name = svc.get("name",    "unknown")
#                 tunnel   = svc.get("tunnel",  None)          # 'ssl' or None
#                 product  = svc.get("product", None)
#                 version  = svc.get("version", None)
#                 raw_conf = svc.get("conf",    None)
#                 conf     = int(raw_conf) if raw_conf and raw_conf.isdigit() else None

#             # ── Risk scoring ──────────────────────────────────────────
#             risk        = None
#             risk_reason = None

#             # Combo check first (e.g. http on 8080)
#             combo = DANGEROUS_PORT_COMBOS.get((svc_name, portid))
#             if combo:
#                 risk        = combo["risk"]
#                 risk_reason = combo["reason"]
#             elif svc_name in DANGEROUS_SERVICES:
#                 entry       = DANGEROUS_SERVICES[svc_name]
#                 risk        = entry["risk"]
#                 risk_reason = entry["reason"]

#             # Upgrade risk if SSL wraps an otherwise plain service
#             if tunnel == "ssl" and risk == "high":
#                 risk        = "medium"
#                 risk_reason = f"{risk_reason} (mitigated by SSL)"

#             ports.append({
#                 "portid":      portid,
#                 "protocol":    protocol,
#                 "state":       state,
#                 "service":     svc_name,
#                 "tunnel":      tunnel,
#                 "product":     product,
#                 "version":     version,
#                 "conf":        conf,
#                 "risk":        risk,
#                 "risk_reason": risk_reason,
#             })

#         report["ports"] = ports
#         return report   # one host per call; extend with a list if scanning ranges

#     return {"status": "no_host_found", "ports": []}


# # ── Convenience wrapper ───────────────────────────────────────────────────────

# def scan_and_return_xml(target: str) -> tuple[str, dict]:
#     """Run nmap scan on target and return (xml_file_path, parsed_report)."""
#     xml_file = run_nmap_scan(target)
#     report = parse_nmap_xml(xml_file)
#     return xml_file, report

# # ── Pretty printer ────────────────────────────────────────────────────────────

# import xml.etree.ElementTree as ET
# from xml.etree.ElementTree import Element, SubElement
# from xml.dom import minidom

# def report_to_xml(report: dict) -> str:
#     """Write report to an XML file named <target>.xml and return the file path."""
#     root = Element("report")

#     # Basic info
#     SubElement(root, "target").text   = str(report.get("target", ""))
#     SubElement(root, "address").text  = str(report.get("address", ""))
#     SubElement(root, "addrtype").text = str(report.get("addr_type", ""))
#     SubElement(root, "hostname").text = str(report.get("hostname") or "")
#     SubElement(root, "status").text   = str(report.get("status", ""))

#     if report.get("status") != "up":
#         SubElement(root, "note").text = "Host is unreachable — no port details available."
#     else:
#         # Uptime
#         up = report.get("uptime", {})
#         uptime_el = SubElement(root, "uptime")
#         secs = up.get("seconds")
#         SubElement(uptime_el, "days").text             = str(secs // 86400) if secs else "unknown"
#         SubElement(uptime_el, "last_boot").text        = str(up.get("last_boot") or "unknown")
#         SubElement(uptime_el, "unpatched_signal").text = str(up.get("unpatched_signal", False))

#         # OS
#         SubElement(root, "os_guess").text = str(report.get("os_guess") or "unknown")

#         # Ports
#         ports_el = SubElement(root, "ports")
#         for p in report.get("ports", []):
#             port_el = SubElement(ports_el, "port")
#             SubElement(port_el, "portid").text      = str(p.get("portid", ""))
#             SubElement(port_el, "protocol").text    = str(p.get("protocol", ""))
#             SubElement(port_el, "state").text       = str(p.get("state", ""))
#             SubElement(port_el, "service").text     = str(p.get("service", ""))
#             SubElement(port_el, "tunnel").text      = str(p.get("tunnel") or "")
#             SubElement(port_el, "product").text     = str(p.get("product") or "")
#             SubElement(port_el, "version").text     = str(p.get("version") or "")
#             SubElement(port_el, "conf").text        = str(p.get("conf") or "")
#             SubElement(port_el, "risk").text        = str(p.get("risk") or "")
#             SubElement(port_el, "risk_reason").text = str(p.get("risk_reason") or "")

#     # Pretty-print and write
#     xml_str   = minidom.parseString(ET.tostring(root, encoding="unicode")).toprettyxml(indent="  ")
#     target    = report.get("target", "output")
#     file_path = f"{SCAN_DIR}/{target}.xml"

#     with open(file_path, "w") as f:
#         f.write(xml_str)

#     return file_path


# # ── Example usage ─────────────────────────────────────────────────────────────
# if __name__ == "__main__":
#     target = "scanme.nmap.org"
#     xml_file, report = scan_and_return_xml(target)  # ✅ Unpack the tuple
#     output_file = report_to_xml(report)
#     print(f"Report saved to: {output_file}")
