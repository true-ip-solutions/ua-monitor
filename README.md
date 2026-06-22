## USE AT YOUR OWN RISK, THIS IS NOT FULLY TESTED
## As always, have backups, and firewall. 

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

# UA Monitor

A lightweight SIP device registration monitor for **VoIPmonitor** environments. Detects when a registered device's User Agent string or IP address changes and alerts your team — via Slack, email, Microsoft Teams, or PagerDuty. Written in Python with a single persistent MySQL connection for fast, low-overhead cron execution.

---

## How It Works

VoIPmonitor passively captures SIP traffic and stores registration events in MySQL. UA Monitor queries that data every 5 minutes, compares each device's current registration against a known-state tracking table, and fires alerts when something changes.

```
voipmonitor.register_state  ──►  ua_monitor.device_ua  ──►  notify.py  ──►  Slack / Email / Teams / PagerDuty
     (live SIP data)               (known state)            (router)         (your choice)
```

All changes are written to the tracking database and a local log file regardless of alert settings.

---

## Requirements

- VoIPmonitor server running Ubuntu/Debian
- MySQL/MariaDB (already present with VoIPmonitor)
- `sip-register = yes` in `/etc/voipmonitor.conf`
- Python 3.6+ and pip (`apt install python3 python3-pip`)
- PyMySQL (`pip3 install pymysql`) — installed automatically by the installer
- `curl` (already present) — used by the installer to download files
- A Slack webhook, email (sendmail/postfix), Teams webhook, or PagerDuty Events API v2 routing key

---

## Installation

### Option 1 — Automatic

Downloads all files from GitHub and walks you through configuration interactively:

```bash
curl -fsSL https://raw.githubusercontent.com/traviscw/ua-monitor/main/install.sh | sudo bash
```

You will be prompted for:
- MySQL root password
- UA Monitor DB password (a new password you choose)
- Notification provider (Slack / email / Teams / PagerDuty) and credentials
- Alert mode, digest frequency, and octet ignore settings

The script will download all files, install Python dependencies, configure credentials, set permissions, run the database setup, seed the device table, and optionally install cron jobs — all in one shot.

---

### Option 2 — Manual

#### 1. Run MySQL Setup

Update the password in `setup.sql` first, then:

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
sudo cp check_ua.py notify.py cleanup.py suppress.conf /opt/ua_monitor/
```

#### 4. Set Credentials

Edit `check_ua.py`:
```python
DB_PASS = "yourpassword"
```

Edit `notify.py` — set your provider and credentials:
```python
NOTIFY_PROVIDER = "slack"   # slack | email | teams | pagerduty

# Slack
SLACK_WEBHOOK = "https://hooks.slack.com/services/XXXX/XXXX/XXXX"

# Email
EMAIL_TO   = "admin@yourdomain.com"
EMAIL_FROM = "ua-monitor@yourdomain.com"

# Teams
TEAMS_WEBHOOK = "https://outlook.office.com/webhook/XXXX"

# PagerDuty
PD_ROUTING_KEY     = "your-32-char-integration-key"
PD_SEVERITY_CHANGE = "warning"    # critical | error | warning | info
```

Edit `cleanup.py`:
```python
DB_PASS = "yourpassword"
```

#### 5. Set Permissions

```bash
sudo chmod 700 /opt/ua_monitor/check_ua.py
sudo chmod 700 /opt/ua_monitor/notify.py
sudo chmod 700 /opt/ua_monitor/cleanup.py
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
```

---

## Files

| File | Description |
|---|---|
| `install.sh` | Automated installer — pulls from GitHub and configures everything |
| `check_ua.py` | Main monitoring script — runs on cron every 5 minutes |
| `notify.py` | Notification router and provider implementations (Slack, email, Teams, PagerDuty) |
| `cleanup.py` | Weekly stale device removal |
| `suppress.conf` | Suppression rules |
| `setup.sql` | MySQL setup — run once on fresh install |

---

## Configuration

### check_ua.py

| Setting | Options | Description |
|---|---|---|
| `ALERT_MODE` | `ua_only` `ip_only` `ua_and_ip` `ua_or_ip` | What triggers an alert |
| `NEW_DEVICE_DIGEST` | `every_run` `30min` `hourly` `daily` | How often to send new device summary |
| `IGNORE_OCTET_COUNT` | `0` `1` `2` `3` | How many IP octets to ignore when comparing |

### notify.py

| Setting | Options | Description |
|---|---|---|
| `NOTIFY_PROVIDER` | `slack` `email` `teams` `pagerduty` | Which notification provider to use |

### Alert Modes

| Mode | Behaviour |
|---|---|
| `ua_only` | Alert only when the UA string changes |
| `ip_only` | Alert only when the IP address changes |
| `ua_and_ip` | Alert only when **both** UA and IP change together |
| `ua_or_ip` | Alert when **either** changes *(default)* |

### Octet Ignore

| Setting | Behaviour |
|---|---|
| `0` | All IP changes alert *(default)* |
| `1` | Ignores last octet — `192.168.1.x` changes ignored |
| `2` | Ignores last two octets — `192.168.x.x` changes ignored |
| `3` | Ignores last three octets — `192.x.x.x` changes ignored |

### New Device Digest

| Setting | Behaviour |
|---|---|
| `every_run` | Sends at the end of every 5-minute cron run |
| `30min` | Batches new devices and sends every 30 minutes |
| `hourly` | Batches new devices and sends every hour |
| `daily` | Batches new devices and sends once a day |

### PagerDuty (notify.py)

| Setting | Default | Description |
|---|---|---|
| `PD_ROUTING_KEY` | *(required)* | Integration Key from your PagerDuty service's Events API v2 integration |
| `PD_SOURCE` | hostname | Source field in PagerDuty incidents — leave empty to auto-detect from `hostname` |
| `PD_SEVERITY_CHANGE` | `warning` | Severity for UA/IP change alerts (`critical` / `error` / `warning` / `info`) |
| `PD_SEVERITY_NEW_DEVICE` | `info` | Severity for new device digest alerts |

Each cron run that detects changes creates a new, distinct PagerDuty incident (no deduplication). If you prefer to deduplicate repeated change alerts into a single open incident, set a static `dedup_key` in the `_pd_changes` function inside `notify.py`.

---

## PagerDuty Service Setup

Before running the installer you need an Integration Key from PagerDuty. Here is how to get one:

1. Log in to PagerDuty and go to **Services** in the top navigation.
2. Select an existing service to receive UA Monitor alerts, or create a new one (e.g. "VoIP Infrastructure").
3. Open the **Integrations** tab on that service and click **Add an integration**.
4. Search for **Events API v2** and select it, then click **Add**.
5. Click the integration name to expand it and copy the **Integration Key** (a 32-character alphanumeric string).
6. Paste that key when the installer prompts for the PagerDuty routing key, or set `PD_ROUTING_KEY` manually in `notify.py`.

Alerts are sent to `https://events.pagerduty.com/v2/enqueue` using Python's standard `urllib` library — no additional packages beyond PyMySQL are required.

---

## Suppression Rules

Edit `/opt/ua_monitor/suppress.conf`. Changes take effect on the next cron run — no restart needed.

| Rule | Example | Effect |
|---|---|---|
| `DEVICE:` | `DEVICE:200@domain.com` | Ignore a specific device |
| `DOMAIN:` | `DOMAIN:testdomain.com` | Ignore all devices on a domain |
| `IP:` | `IP:192.168.1.100` | Ignore a specific source IP |
| `UA:` | `UA:Mobile321` | Ignore an exact UA string |
| `UA_PREFIX:` | `UA_PREFIX:Mobile/1.0` | Ignore any UA starting with prefix |
| `UA_CHANGE:` | `UA_CHANGE:UA One->UA Two` | Ignore an exact UA-to-UA change |
| `UA_CHANGE_PREFIX:` | `UA_CHANGE_PREFIX:App/1.8->App/1.9` | Ignore version bumps within the same app |

---

## Alerts

### 🔴 Change Alert
All UA/IP changes detected in a single cron run are batched into **one** message per run, rather than one message per device.

### 🟢 New Device Digest
New devices are queued and sent as a single batched table on the configured digest schedule.

---

## Useful Commands

```bash
# Seed or reseed the tracking database
sudo python3 /opt/ua_monitor/check_ua.py --seed

# Watch the log live
tail -f /var/log/ua_monitor.log

# Check device count
mysql -u"ua_monitor" -p'yourpassword' -e "
    SELECT COUNT(*) AS devices, MIN(last_seen) AS oldest, MAX(last_seen) AS newest
    FROM ua_monitor.device_ua;"

# Check new device queue
mysql -u"ua_monitor" -p'yourpassword' -e "
    SELECT COUNT(*) AS queued FROM ua_monitor.new_device_queue;" ua_monitor

# Check last digest sent
mysql -u"ua_monitor" -p'yourpassword' -e "
    SELECT MAX(sent_at) AS last_digest FROM ua_monitor.digest_log;" ua_monitor
```

---

## Log Reference

| Prefix | Meaning |
|---|---|
| `NEW:` | First time this device has been seen |
| `SEED:` | Device recorded during a `--seed` run |
| `CHANGE:` | UA or IP changed — alert sent |
| `SILENT:` | Change detected but filtered by `ALERT_MODE` |
| `SUPPRESSED:` | Change matched a rule in `suppress.conf` |
| `OCTET CHANGE IGNORED:` | IP changed within the ignored octet range |
| `DIGEST:` | New device digest was sent |
| `CLEANUP:` | Weekly stale device removal ran |
