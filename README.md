## USE AT YOUR OWN RISK, THIS IS NOT FULLY TESTED
## As always, have backups, and firewall.

> Originally authored by [traviscw](https://github.com/traviscw/ua-monitor). Extended with PagerDuty support, a Python rewrite, auto alert mode, UA classification, change log deduplication, staleness re-arming, and a two-section daily digest by [True IP Solutions](https://github.com/true-ip-solutions).

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

# UA Monitor

A lightweight SIP device registration monitor for **VoIPmonitor** environments. Detects when a registered device's User Agent string or IP address changes and alerts your team via Slack, email, Microsoft Teams, or PagerDuty. Written in Python with a single persistent MySQL connection for fast, low-overhead cron execution.

---

## How It Works

VoIPmonitor passively captures SIP traffic and stores registration events in MySQL. UA Monitor queries that data every 5 minutes, compares each device's current registration against a known-state tracking table, and fires alerts when something changes.

```
voipmonitor.register_state  ──►  ua_monitor.device_ua  ──►  notify.py  ──►  Slack / Email / Teams / PagerDuty
     (live SIP data)               (known state)            (router)         (your choice)
```

Each alert is also written to a `change_log` table that deduplicates repeated notifications and drives a daily email digest. All activity is written to a local log file regardless of alert settings.

---

## Requirements

- VoIPmonitor server running Ubuntu/Debian
- MySQL/MariaDB (already present with VoIPmonitor)
- `sip-register = yes` in `/etc/voipmonitor.conf`
- Python 3.6+ and pip (`apt install python3 python3-pip`)
- PyMySQL (`pip3 install pymysql`) — installed automatically by the installer
- `curl` — used by the installer to download files
- A Slack webhook, email relay (sendmail/postfix), Teams webhook, or PagerDuty Events API v2 routing key

---

## Installation

### Option 1 — Automatic

Downloads all files from GitHub and walks you through configuration interactively:

```bash
curl -fsSL https://raw.githubusercontent.com/true-ip-solutions/ua-monitor/main/install.sh | sudo bash
```

You will be prompted for:
- MySQL root password (for one-time DB setup)
- UA Monitor DB password (a new password you choose)
- Notification provider (Slack / email / Teams / PagerDuty) and credentials
- Alert mode and mobile UA prefixes
- Digest recipient and sender email addresses
- Octet ignore count
- Whether to install cron jobs and the digest cron schedule

The script downloads all files, installs Python dependencies, writes the configuration file, sets permissions, runs the database setup, seeds the device table, and optionally installs cron jobs.

---

### Option 2 — Manual

#### 1. Run MySQL Setup

Update the password placeholder in `setup.sql`, then:

```bash
mysql -u root -p < setup.sql
```

#### 2. Install Python Dependencies

```bash
pip3 install pymysql
```

#### 3. Deploy Files

```bash
sudo mkdir -p /opt/ua_monitor
sudo cp check_ua.py notify.py cleanup.py digest.py suppress.conf /opt/ua_monitor/
```

#### 4. Create Configuration File

Copy `ua_monitor.conf.example` to `/opt/ua_monitor/ua_monitor.conf` and fill in your values:

```bash
sudo cp ua_monitor.conf.example /opt/ua_monitor/ua_monitor.conf
sudo chmod 600 /opt/ua_monitor/ua_monitor.conf
```

#### 5. Set Permissions

```bash
sudo chmod 700 /opt/ua_monitor/check_ua.py
sudo chmod 700 /opt/ua_monitor/notify.py
sudo chmod 700 /opt/ua_monitor/cleanup.py
sudo chmod 700 /opt/ua_monitor/digest.py
sudo chmod 600 /opt/ua_monitor/suppress.conf
sudo touch /var/log/ua_monitor.log
sudo chmod 640 /var/log/ua_monitor.log
```

#### 6. Seed the Database

```bash
sudo python3 /opt/ua_monitor/check_ua.py --seed
```

Verify:
```bash
mysql -u"ua_monitor" -p'yourpassword' -e "SELECT COUNT(*) FROM ua_monitor.device_ua;"
tail -20 /var/log/ua_monitor.log
```

#### 7. Test Run

```bash
sudo python3 /opt/ua_monitor/check_ua.py
```

#### 8. Enable Cron

```bash
sudo crontab -e
```

Add:
```
*/5 * * * * python3 /opt/ua_monitor/check_ua.py
0 3 * * 0 python3 /opt/ua_monitor/cleanup.py
0 7 * * * python3 /opt/ua_monitor/digest.py
```

---

## Files

| File | Description |
|---|---|
| `install.sh` | Automated installer — pulls from GitHub and configures everything |
| `check_ua.py` | Main monitoring script — runs on cron every 5 minutes |
| `notify.py` | Notification router and provider implementations (Slack, email, Teams, PagerDuty) |
| `cleanup.py` | Weekly cleanup — removes stale devices and ages out old change_log entries |
| `digest.py` | Daily HTML email digest of the change_log |
| `suppress.conf` | Suppression rules — devices/UAs to never alert on |
| `setup.sql` | MySQL setup — run once on fresh install |
| `ua_monitor.conf.example` | Reference configuration file with all options documented |

---

## Configuration

All settings live in `/opt/ua_monitor/ua_monitor.conf`. Changes take effect on the next cron run — no restart needed. The file should be `chmod 600` as it contains database credentials.

### [database]

| Key | Default | Description |
|---|---|---|
| `db_user` | `ua_monitor` | MySQL username |
| `db_pass` | *(required)* | MySQL password |
| `db_host` | `localhost` | MySQL host |

### [monitor]

| Key | Default | Description |
|---|---|---|
| `log_file` | `/var/log/ua_monitor.log` | Path to the log file |
| `suppress_conf` | `/opt/ua_monitor/suppress.conf` | Path to the suppression rules file |
| `lookback_minutes` | `6` | How far back to query `register_state` each run |
| `alert_mode` | `auto` | How changes are evaluated — see Alert Modes below |
| `ignore_octet_count` | `0` | How many trailing IP octets to ignore — see Octet Ignore below |
| `retention_days` | `90` | Days before an unseen device is removed from `device_ua` |

### [alert_rules]

| Key | Default | Description |
|---|---|---|
| `mobile_ua_prefixes` | *(empty)* | Comma-separated UA prefixes treated as mobile/softphone. Case-insensitive prefix match. Everything else is treated as hardware. |
| `change_log_staleness_hours` | `2` | Hours of inactivity before a change_log entry is considered stale and the next detection of that UA re-triggers an alert. See Alert Deduplication below. |

Example:
```ini
[alert_rules]
mobile_ua_prefixes = snapmobile,zoiper,groundwire,bria,linphone,ringotel
change_log_staleness_hours = 2
```

### [notify]

| Key | Options | Description |
|---|---|---|
| `provider` | `slack` `email` `teams` `pagerduty` | Which notification provider to use |

Add only the section that matches your provider.

**[slack]**
```ini
[slack]
webhook = https://hooks.slack.com/services/XXXX/XXXX/XXXX
```

**[email]**
```ini
[email]
to = admin@yourdomain.com
from = ua-monitor@yourdomain.com
```

**[teams]**
```ini
[teams]
webhook = https://outlook.office.com/webhook/XXXX
```

**[pagerduty]**
```ini
[pagerduty]
routing_key = your-32-char-integration-key
source =
severity_change = warning
```

### [digest]

| Key | Default | Description |
|---|---|---|
| `to` | *(required)* | Recipient email address |
| `from` | *(required)* | Sender email address |
| `subject` | `[UA Monitor] Daily Change Log Digest` | Email subject line |
| `smtp_host` | `localhost` | SMTP relay host |

---

## Alert Modes

Set via `alert_mode` in `[monitor]`.

| Mode | Behaviour |
|---|---|
| `auto` | Per-device classification based on UA type — **recommended** |
| `ua_only` | Alert only when the UA string changes |
| `ip_only` | Alert only when the IP address changes |
| `ua_and_ip` | Alert only when **both** UA and IP change together |
| `ua_or_ip` | Alert when **either** UA or IP changes |

### Auto Mode

`auto` applies different alert logic depending on whether the devices involved are classified as hardware or mobile/softphone:

| Old UA | New UA | Alert condition |
|---|---|---|
| Hardware | Hardware | Both UA **and** IP must change |
| Mobile | Mobile | UA must change |
| Hardware | Mobile (or vice versa) | Always alert (cross-category) |

UA classification is driven by `mobile_ua_prefixes` in `[alert_rules]`. Any UA not matching a prefix is treated as hardware. Unknown or blank UAs also default to hardware treatment.

This mode significantly reduces false positives from extensions registered to multiple devices while still catching cross-category changes that are the most common fraud indicator.

---

## Alert Deduplication

When an alert fires, both the old and new UA strings are written to a `change_log` table. On subsequent checks, if the same UA reappears on the same extension, the `hit_count` counter is incremented but no new alert is sent. A fresh alert only fires when a UA that is not in the change_log for that extension is detected.

Writing both directions (old → new and new → old) on first alert prevents oscillation — if a device flips back to its previous UA, that is also already in the log and will not re-alert.

**Staleness re-arming:** If a UA has not been seen for longer than `change_log_staleness_hours` (default: 2 hours), its change_log entry is treated as stale and the next detection fires a fresh alert. This covers the case where an extension is rekeyed after a breach — active flapping updates `last_seen` every 5 minutes, so a rekeyed extension's entries quickly become stale. When a stale entry is re-armed, the old row is deleted and recreated fresh so `first_seen` and `hit_count` reflect the new incident rather than accumulating from the previous one.

Change_log entries age out automatically after 30 days of inactivity (no new hits). Once aged out, the UA is treated as unknown again and will re-alert if it reappears.

---

## Daily Digest

`digest.py` sends an HTML email summarizing change_log activity. It is designed to run daily via cron and give your support team a list of extensions to follow up on.

**Default behavior (cron run):** Sends only entries whose `first_seen` is newer than the previous digest run. The timestamp is stored in `/opt/ua_monitor/last_digest.ts` and updated after each successful send.

**Full mode:** Sends all active change_log entries regardless of when they were first seen.

```bash
# New entries only (cron)
python3 /opt/ua_monitor/digest.py

# Full change log (manual trigger)
python3 /opt/ua_monitor/digest.py --full
```

The digest always sends, even if there are no new entries, so you have a daily confirmation that the system is running.

**Digest layout:** The email is split into two sections:

- **True UA changes** — extensions where the UA changed in one direction only, or underwent multiple distinct transitions (A→B→C). Each change is listed as its own row. These are the most immediately actionable items.
- **Flapping devices** — extensions oscillating between exactly two UAs (A↔B and B↔A). Flap pairs are collapsed into a single row to reduce noise. The combined hit count (both directions) is shown, and both detected IPs are displayed when they differ — diverging IPs on a flap row are a meaningful signal worth investigating. Column headers read "UA (A)" and "UA (B)" instead of "Previous UA" / "Detected UA" to reflect that direction is not meaningful for flaps.

Row highlighting applies to both sections based on hit count:
- **Yellow** — 5–9 hits (recurring change, likely misconfiguration or active oscillation)
- **Red** — 10 or more hits (persistent issue; prioritize for a support call)

---

## Suppression Rules

Edit `/opt/ua_monitor/suppress.conf`. Lines starting with `#` are comments. Changes take effect on the next cron run.

| Rule | Example | Effect |
|---|---|---|
| `DEVICE:` | `DEVICE:200@domain.com` | Ignore a specific extension |
| `DOMAIN:` | `DOMAIN:testdomain.com` | Ignore all devices on a domain |
| `IP:` | `IP:192.168.1.100` | Ignore a specific source IP |
| `UA:` | `UA:Polycom/4.0.1` | Ignore an exact UA string |
| `UA_PREFIX:` | `UA_PREFIX:Polycom/4` | Ignore any UA starting with prefix |
| `UA_CHANGE:` | `UA_CHANGE:UA One->UA Two` | Ignore an exact UA-to-UA transition |
| `UA_CHANGE_PREFIX:` | `UA_CHANGE_PREFIX:App/1.8->App/1.9` | Ignore version bumps within the same app |

Suppressed devices still have their `device_ua` record updated — they simply never trigger alerts or change_log entries.

---

## Octet Ignore

Set via `ignore_octet_count` in `[monitor]`. Useful when devices on a subnet roam between IPs within the same range and you do not want those IP-only changes to contribute to alert decisions.

| Setting | Behaviour |
|---|---|
| `0` | All IP changes are compared *(default)* |
| `1` | Ignores last octet — `192.168.1.x` changes silenced |
| `2` | Ignores last two octets — `192.168.x.x` changes silenced |
| `3` | Ignores last three octets — `192.x.x.x` changes silenced |

---

## PagerDuty Service Setup

Before running the installer you need an Integration Key from PagerDuty:

1. Log in to PagerDuty and go to **Services** in the top navigation.
2. Select an existing service to receive UA Monitor alerts, or create a new one (e.g. "VoIP Infrastructure").
3. Open the **Integrations** tab and click **Add an integration**.
4. Search for **Events API v2**, select it, and click **Add**.
5. Expand the integration and copy the **Integration Key** (32-character alphanumeric string).
6. Paste that key when the installer prompts for the PagerDuty routing key, or set `routing_key` in `[pagerduty]` in `ua_monitor.conf`.

Alerts are sent to `https://events.pagerduty.com/v2/enqueue` using Python's standard `urllib` library — no additional packages beyond PyMySQL are required.

---

## Useful Commands

```bash
# Seed or reseed the tracking database (scans last 24 hours, no alerts)
sudo python3 /opt/ua_monitor/check_ua.py --seed

# Run once manually and check output
sudo python3 /opt/ua_monitor/check_ua.py

# Send today's new digest entries
sudo python3 /opt/ua_monitor/digest.py

# Send full change log digest
sudo python3 /opt/ua_monitor/digest.py --full

# Watch the log live
tail -f /var/log/ua_monitor.log

# Check device count
mysql -u"ua_monitor" -p'yourpassword' -e "
    SELECT COUNT(*) AS devices, MIN(last_seen) AS oldest, MAX(last_seen) AS newest
    FROM ua_monitor.device_ua;"

# Inspect change log
mysql -u"ua_monitor" -p'yourpassword' -e "
    SELECT from_num, domain, detected_ua, hit_count, first_seen, last_seen
    FROM ua_monitor.change_log
    ORDER BY hit_count DESC;" ua_monitor

# Run weekly cleanup manually
sudo python3 /opt/ua_monitor/cleanup.py
```

---

## Log Reference

| Prefix | Meaning |
|---|---|
| `NEW:` | First time this device has been seen — recorded, no alert |
| `SEED:` | Device recorded during a `--seed` run |
| `CHANGE (auto):` | Change detected and alert sent — auto mode |
| `CHANGE (ua_and_ip):` | Change detected and alert sent — ua_and_ip mode |
| `DEDUP:` | Change detected but UA already in change_log — counter incremented, no alert |
| `STALE REARM:` | UA found in change_log but entry is stale (last_seen > staleness threshold) — entry deleted, fresh alert fired |
| `SILENT (auto):` | Change detected but filtered by alert mode logic |
| `SUPPRESSED:` | Change matched a rule in `suppress.conf` |
| `OCTET CHANGE IGNORED:` | IP changed within the ignored octet range |
| `CLEANUP:` | Weekly stale device removal ran |
