#!/usr/bin/env python3
"""
Yao Pentest — Report Emailer
Generates the combined HTML report and emails it to configured recipients.
"""
import argparse, json, os, sys, glob, re, smtplib, datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

BASE = os.path.dirname(os.path.abspath(__file__))

def find_latest_batch():
    def batch_ts(d):
        m = re.search(r"batch_(\d{8}_\d{6})", d)
        return m.group(1) if m else ""
    dirs = sorted(glob.glob(os.path.join(BASE, "batch_*")), key=batch_ts, reverse=True)
    for d in dirs:
        if os.path.exists(os.path.join(d, "batch_complete")):
            return d
    return None

def generate_report():
    """Generate the HTML export report from the latest batch."""
    sys.path.insert(0, BASE)
    try:
        import dashboard as db
        batch_dir = find_latest_batch()
        if not batch_dir:
            print("No completed batch found to email.")
            return None, None
        html = db.generate_export_report(batch_dir)
        return html, batch_dir
    except Exception as e:
        print(f"Error generating report: {e}")
        return None, None

def get_summary(batch_dir):
    """Get a text summary of findings for the email body."""
    try:
        import json as _json
        targets_file = os.path.join(BASE, "targets.json")
        targets = _json.load(open(targets_file))["targets"]
        cp_file = os.path.join(batch_dir, "checkpoint.json")
        cp = _json.load(open(cp_file)).get("completed", {}) if os.path.exists(cp_file) else {}
        if isinstance(cp, list): cp = {u: {"status":"complete"} for u in cp}

        total_c = total_h = total_m = total_l = 0
        lines = []
        for t in targets:
            url = t["url"]
            host = url.replace("https://","")
            safe = re.sub(r"[^a-zA-Z0-9_.-]", "_", host)
            scan_dirs = sorted(glob.glob(os.path.join(BASE, f"pentest_{safe}_*")),
                               key=os.path.getmtime, reverse=True)
            scan_dir = next((d for d in scan_dirs if os.path.exists(os.path.join(d,"summary.json"))), None)
            cp_entry = cp.get(url, {})
            cp_status = cp_entry.get("status","") if isinstance(cp_entry,dict) else ""

            if cp_status == "OFFLINE":
                lines.append(f"  ⚫ OFFLINE     {host}")
                continue
            if cp_status == "UNREACHABLE":
                lines.append(f"  ⬜ UNREACHABLE {host}")
                continue

            if scan_dir and os.path.exists(os.path.join(scan_dir,"summary.json")):
                s = _json.load(open(os.path.join(scan_dir,"summary.json")))
                b = s.get("findings_by_severity", {})
                c,h,m,l = b.get("CRITICAL",0),b.get("HIGH",0),b.get("MEDIUM",0),b.get("LOW",0)
                total_c+=c; total_h+=h; total_m+=m; total_l+=l
                nc,nh = c,h
                risk = nc*10+nh*5+m*2+l
                if nc>=2: g="F"
                elif nc==1: g="D"
                elif nh>=3: g="C"
                elif nh>=1: g="B"
                elif risk>0: g="B+"
                else: g="A"
                lines.append(f"  [{g}] {host:45}  CRIT:{c} HIGH:{h} MED:{m} LOW:{l}")

        date_str = datetime.datetime.now().strftime("%d %B %Y")
        summary = f"""Yao Security Assessment — Weekly Report
{date_str}

COMBINED TOTALS:
  Critical: {total_c}   High: {total_h}   Medium: {total_m}   Low: {total_l}

PER-TARGET RESULTS:
{"".join(chr(10)+ln for ln in lines)}

The full HTML report is attached.
See individual findings with DevOps remediation guidance in the report.

---
Grade scale: A = no HIGH/CRIT | B = 1-2 HIGH | C = 3+ HIGH | D = 1 CRIT | F = 2+ CRIT
Automated scan — findings require manual verification before remediation.
"""
        return summary, total_c, total_h
    except Exception as e:
        return f"Could not generate summary: {e}", 0, 0

def send_email(config, html, batch_dir, log_file):
    subject_template = config.get("subject", "Yao Security Scan — {date}")
    date_str = datetime.datetime.now().strftime("%d %b %Y")
    subject = subject_template.replace("{date}", date_str)

    summary_text, total_c, total_h = get_summary(batch_dir)

    # Add urgency flag to subject if critical findings
    if total_c > 0:
        subject = f"🚨 CRITICAL — {subject}"
    elif total_h > 0:
        subject = f"⚠️ {subject}"

    msg = MIMEMultipart("mixed")
    msg["From"]    = config["from"]
    msg["To"]      = ", ".join(config["to"]) if isinstance(config["to"], list) else config["to"]
    msg["Subject"] = subject

    # Plain text body
    msg.attach(MIMEText(summary_text, "plain"))

    # HTML report as attachment
    if html:
        fname = f"yao-pentest-{datetime.datetime.now().strftime('%Y%m%d')}.html"
        part = MIMEBase("application", "octet-stream")
        part.set_payload(html.encode("utf-8", errors="replace"))
        encoders.encode_base64(part)
        part.add_header("Content-Disposition", f'attachment; filename="{fname}"')
        msg.attach(part)

    # Connect and send
    host = config.get("smtp_host", "smtp.gmail.com")
    port = int(config.get("smtp_port", 587))
    user = config["username"]
    pwd  = config["password"]

    print(f"Connecting to {host}:{port}...")
    with smtplib.SMTP(host, port) as server:
        server.ehlo()
        if port == 587:
            server.starttls()
        server.login(user, pwd)
        recipients = config["to"] if isinstance(config["to"], list) else [config["to"]]
        server.sendmail(config["from"], recipients, msg.as_string())
    print(f"Report emailed to: {', '.join(recipients)}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--log",    default="")
    args = parser.parse_args()

    if not os.path.exists(args.config):
        print(f"ERROR: Config file not found: {args.config}")
        print("Copy email-config.example.json → email-config.json and fill in your details.")
        sys.exit(1)

    config = json.load(open(args.config))

    print("Generating report...")
    html, batch_dir = generate_report()
    if not batch_dir:
        print("No batch to report. Exiting.")
        sys.exit(0)

    print(f"Sending report from batch: {os.path.basename(batch_dir)}")
    try:
        send_email(config, html, batch_dir, args.log)
    except Exception as e:
        print(f"ERROR sending email: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
