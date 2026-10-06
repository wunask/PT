"""
JUICE-SHOP-AGENT: lightweight automated checks against an OWASP Juice Shop
instance you own/run (https://github.com/juice-shop/juice-shop).

Only point this at a Juice Shop instance you're authorized to test.

Usage:
    pip install requests
    python juice_shop_agent.py --target http://10.20.1.10:3000
    python juice_shop_agent.py --target http://10.20.1.10:3000 --log-dir /var/log/juiceshop-agent
    python juice_shop_agent.py --target http://10.20.1.10:3000 --loop-minutes 10

This checks a handful of Juice Shop's well-documented weaknesses at the
API level (no browser, so it can't catch the DOM-based XSS challenges,
which need a real browser/headless Chrome to render). For full coverage,
use the OWASP ZAP baseline scan set up alongside this (see README).

Checks:
  - SQL injection login bypass (classic ' OR 1=1-- against /rest/user/login)
  - Exposed /ftp directory listing (legacy files, coupon leaks)
  - Missing security headers
  - IDOR: fetching another user's basket by guessing/incrementing the id
  - Framework/version disclosure
"""

import argparse
import datetime
import io
import os
import time
import requests

TIMEOUT = 6


class Report:
    def __init__(self):
        self.findings = []

    def add(self, severity, title, detail):
        self.findings.append((severity, title, detail))

    def print_report(self, target):
        print("\n" + "=" * 70)
        print(f"JUICE-SHOP-AGENT REPORT for {target}")
        print("=" * 70)
        if not self.findings:
            print("No issues found.")
            return
        order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
        for sev, title, detail in sorted(self.findings, key=lambda f: order.get(f[0], 9)):
            print(f"\n[{sev}] {title}")
            print(f"    {detail}")
        print("\n" + "=" * 70)
        print(f"Total findings: {len(self.findings)}")


def check_login_sqli(base, report):
    url = f"{base}/rest/user/login"
    payload = {"email": "' OR 1=1--", "password": "anything"}
    try:
        r = requests.post(url, json=payload, timeout=TIMEOUT)
        if r.status_code == 200 and "authentication" in r.text.lower():
            report.add(
                "HIGH",
                "SQL injection login bypass (/rest/user/login)",
                "Logged in using a SQLi payload in the email field instead of "
                "valid credentials, confirming the login query is not safely "
                "parameterized.",
            )
    except requests.RequestException as e:
        report.add("INFO", "login endpoint unreachable", str(e))


def check_ftp_listing(base, report):
    try:
        r = requests.get(f"{base}/ftp", timeout=TIMEOUT)
        if r.status_code == 200 and ("Index of" in r.text or "<a href" in r.text):
            report.add(
                "MEDIUM",
                "Directory listing exposed (/ftp)",
                "The /ftp directory returns a browsable file listing, which can "
                "leak legacy or backup files not meant to be public.",
            )
    except requests.RequestException as e:
        report.add("INFO", "/ftp unreachable", str(e))


def check_security_headers(base, report):
    expected = [
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Strict-Transport-Security",
    ]
    try:
        r = requests.get(base, timeout=TIMEOUT)
        missing = [h for h in expected if h not in r.headers]
        if missing:
            report.add("LOW", "Missing security headers", f"Missing: {', '.join(missing)}")
        server = r.headers.get("X-Powered-By") or r.headers.get("Server")
        if server:
            report.add("INFO", "Framework/version disclosure", f"Header reveals: {server}")
    except requests.RequestException as e:
        report.add("INFO", "home page unreachable", str(e))


def check_basket_idor(base, report):
    # Register a throwaway account, log in, then try reading other basket IDs.
    import random
    rand = random.randint(100000, 999999)
    email = f"agent_test_{rand}@test.local"
    password = "AgentTest123!"
    try:
        requests.post(
            f"{base}/api/Users",
            json={"email": email, "password": password, "passwordRepeat": password, "securityAnswer": "n/a"},
            timeout=TIMEOUT,
        )
        login = requests.post(f"{base}/rest/user/login", json={"email": email, "password": password}, timeout=TIMEOUT)
        token = login.json().get("authentication", {}).get("token")
        if not token:
            return
        headers = {"Authorization": f"Bearer {token}"}
        hits = []
        for basket_id in range(1, 6):
            r = requests.get(f"{base}/rest/basket/{basket_id}", headers=headers, timeout=TIMEOUT)
            if r.status_code == 200 and '"data"' in r.text:
                hits.append(basket_id)
        if len(hits) > 1:
            report.add(
                "MEDIUM",
                "Possible IDOR on /rest/basket/<id>",
                f"Authenticated as a fresh test user but could read {len(hits)} "
                f"different basket IDs ({hits}) without an ownership check.",
            )
    except requests.RequestException as e:
        report.add("INFO", "basket IDOR check skipped (request failed)", str(e))
    except (ValueError, KeyError):
        pass


def run_once(base, log_dir=None):
    report = Report()
    print(f"[{datetime.datetime.now().isoformat(timespec='seconds')}] Scanning {base} ...")
    check_login_sqli(base, report)
    check_ftp_listing(base, report)
    check_security_headers(base, report)
    check_basket_idor(base, report)
    report.print_report(base)

    if log_dir:
        os.makedirs(log_dir, exist_ok=True)
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(log_dir, f"scan_{ts}.log")
        with open(path, "w") as fh:
            fh.write(f"JUICE-SHOP-AGENT REPORT for {base}\n")
            fh.write(f"Run at: {datetime.datetime.now().isoformat()}\n\n")
            for sev, title, detail in report.findings:
                fh.write(f"[{sev}] {title}\n    {detail}\n\n")
        print(f"Saved report to {path}")
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True, help="e.g. http://10.20.1.10:3000")
    parser.add_argument("--log-dir", default=None)
    parser.add_argument("--loop-minutes", type=int, default=0)
    args = parser.parse_args()
    base = args.target.rstrip("/")

    if args.loop_minutes and args.loop_minutes > 0:
        print(f"Running continuously every {args.loop_minutes} minute(s). Ctrl+C to stop.")
        while True:
            run_once(base, args.log_dir)
            time.sleep(args.loop_minutes * 60)
    else:
        run_once(base, args.log_dir)


if __name__ == "__main__":
    main()
