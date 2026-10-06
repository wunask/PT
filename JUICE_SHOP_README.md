# Attacking your existing Juice Shop instance every 10 minutes

Assumes Juice Shop is already running and reachable at
`http://10.20.1.10:3000` (its default port). If it's elsewhere, edit the
`--target` value in `juiceshop-agent.service` and the argument in
`zap-scan.service` accordingly.

You have two options below — use either, or both together.

## Option A: custom lightweight agent (`juice_shop_agent.py`)

Quick, API-level checks: SQLi login bypass, exposed `/ftp` listing,
missing security headers, basket IDOR. Can't see the DOM-based XSS
challenges (those need a real browser).

```bash
sudo mkdir -p /opt/pentest_lab /var/log/juiceshop-agent
sudo cp juice_shop_agent.py /opt/pentest_lab/
sudo pip3 install requests

sudo cp juiceshop-agent.service juiceshop-agent.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now juiceshop-agent.timer
```

Check it:
```bash
systemctl list-timers | grep juiceshop
journalctl -u juiceshop-agent.service -f
ls /var/log/juiceshop-agent/
```

## Option B: OWASP ZAP baseline scan (recommended, far more thorough)

ZAP is the standard open-source DAST tool and is specifically built to
scan apps like Juice Shop — it will find far more than a hand-written
script, including many of the XSS and client-side issues the custom
agent can't. Requires Docker.

```bash
sudo cp zap_scan.sh /opt/pentest_lab/
sudo chmod +x /opt/pentest_lab/zap_scan.sh
sudo mkdir -p /var/log/zap-reports
sudo chown pentest:pentest /var/log/zap-reports

sudo cp zap-scan.service zap-scan.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now zap-scan.timer
```

Check it:
```bash
systemctl list-timers | grep zap-scan
journalctl -u zap-scan.service -f
ls /var/log/zap-reports/    # open the .html files in a browser
```

Note: a full baseline scan can take a few minutes depending on the app;
if it regularly runs longer than 10 minutes, widen `OnUnitActiveSec` in
`zap-scan.timer` (e.g. to `15min`) so scans don't pile up.

## Which should I use?

- Just want quick, continuous proof of a couple of known weak points →
  Option A.
- Want a real, comprehensive vulnerability report (recommended) →
  Option B.
- Want both signal sources → run both timers; they log to separate
  directories.
