#!/usr/bin/env python3
# /opt/ua_monitor/digest.py
#
# UA Monitor — daily change log digest.
# Default: sends only entries new since the last digest run.
# Full mode: sends all entries currently in the change_log.
#
# Usage:
#   python3 /opt/ua_monitor/digest.py          # new entries only (cron)
#   python3 /opt/ua_monitor/digest.py --full   # full change_log

import sys
import smtplib
import configparser
from datetime import datetime
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

import pymysql
import pymysql.cursors

# -----------------------------------------------------------------------
# Configuration — read from /opt/ua_monitor/ua_monitor.conf
# -----------------------------------------------------------------------

_cfg = configparser.ConfigParser()
_cfg.read("/opt/ua_monitor/ua_monitor.conf")

def _get(section, key, fallback=''):
    return _cfg.get(section, key, fallback=fallback)

DB_USER     = _get('database', 'db_user', 'ua_monitor')
DB_PASS     = _get('database', 'db_pass')
DB_HOST     = _get('database', 'db_host', 'localhost')

DIGEST_TO      = _get('digest', 'to')
DIGEST_FROM    = _get('digest', 'from')
DIGEST_SUBJECT = _get('digest', 'subject', '[UA Monitor] Daily Change Log Digest')
DIGEST_SMTP    = _get('digest', 'smtp_host', 'localhost')

TIMESTAMP_FILE = Path('/opt/ua_monitor/last_digest.ts')

# -----------------------------------------------------------------------
# Timestamp helpers
# -----------------------------------------------------------------------

def read_last_digest_ts():
    """Returns the last digest datetime, or None if file doesn't exist."""
    if not TIMESTAMP_FILE.exists():
        return None
    try:
        ts = TIMESTAMP_FILE.read_text().strip()
        return datetime.fromisoformat(ts)
    except Exception:
        return None

def write_last_digest_ts(dt):
    TIMESTAMP_FILE.write_text(dt.isoformat())

# -----------------------------------------------------------------------
# Database
# -----------------------------------------------------------------------

def get_connection():
    return pymysql.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASS,
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True
    )

def fetch_change_log(conn, since=None):
    """
    Fetch change_log entries.
    If since is provided, only returns entries with first_seen > since.
    Always sorted hit_count DESC, last_seen DESC.
    """
    with conn.cursor() as cur:
        if since:
            cur.execute("""
                SELECT
                    from_num, domain, old_ua, detected_ua,
                    detected_ip, first_seen, last_seen, hit_count
                FROM ua_monitor.change_log
                WHERE first_seen > %s
                ORDER BY hit_count DESC, last_seen DESC
            """, (since,))
        else:
            cur.execute("""
                SELECT
                    from_num, domain, old_ua, detected_ua,
                    detected_ip, first_seen, last_seen, hit_count
                FROM ua_monitor.change_log
                ORDER BY hit_count DESC, last_seen DESC
            """)
        return cur.fetchall()

# -----------------------------------------------------------------------
# HTML email builder
# -----------------------------------------------------------------------

def build_html(rows, generated_at, full_mode, since=None):
    count = len(rows)

    if full_mode:
        heading = "UA Monitor — Full Change Log Digest"
        subtitle = f"Generated: {generated_at} &nbsp;|&nbsp; Total entries: <strong>{count}</strong>"
    else:
        since_str = since.strftime('%Y-%m-%d %H:%M') if since else 'beginning'
        heading = "UA Monitor — Daily Change Log Digest"
        subtitle = (
            f"Generated: {generated_at} &nbsp;|&nbsp; "
            f"New since: {since_str} &nbsp;|&nbsp; "
            f"New entries: <strong>{count}</strong>"
        )

    if count == 0:
        table_body = """
        <tr>
            <td colspan="7" style="text-align:center; color:#888; padding:20px;">
                No new entries since last digest.
            </td>
        </tr>"""
    else:
        table_body = ""
        for row in rows:
            first_seen = row['first_seen']
            last_seen  = row['last_seen']
            if hasattr(first_seen, 'strftime'):
                first_seen = first_seen.strftime('%Y-%m-%d %H:%M')
            if hasattr(last_seen, 'strftime'):
                last_seen = last_seen.strftime('%Y-%m-%d %H:%M')

            device = f"{row['from_num']}@{row['domain']}"
            old_ua = row['old_ua'] or ''
            new_ua = row['detected_ua'] or ''
            ip     = row['detected_ip'] or ''
            hits   = row['hit_count']

            if hits >= 10:
                row_style = 'background:#fff3cd;'
            elif hits >= 5:
                row_style = 'background:#fff8e1;'
            else:
                row_style = ''

            table_body += f"""
            <tr style="{row_style}">
                <td style="padding:6px 10px; border-bottom:1px solid #eee; font-weight:bold;">{device}</td>
                <td style="padding:6px 10px; border-bottom:1px solid #eee;">{old_ua}</td>
                <td style="padding:6px 10px; border-bottom:1px solid #eee;">{new_ua}</td>
                <td style="padding:6px 10px; border-bottom:1px solid #eee;">{ip}</td>
                <td style="padding:6px 10px; border-bottom:1px solid #eee;">{first_seen}</td>
                <td style="padding:6px 10px; border-bottom:1px solid #eee;">{last_seen}</td>
                <td style="padding:6px 10px; border-bottom:1px solid #eee; text-align:center; font-weight:bold;">{hits}</td>
            </tr>"""

    footer_note = (
        "Full digest — all active change_log entries shown."
        if full_mode else
        "Only entries new since the last digest run are shown. "
        "Run <code>digest.py --full</code> for the complete change log."
    )

    html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  body {{ font-family: Arial, sans-serif; font-size: 13px; color: #333; }}
  h2   {{ color: #c0392b; }}
  table {{ border-collapse: collapse; width: 100%; max-width: 1100px; }}
  th   {{ background:#2c3e50; color:#fff; padding:8px 10px; text-align:left; }}
  tr:hover td {{ background:#f0f7ff; }}
  .footer {{ color:#999; font-size:11px; margin-top:16px; }}
</style>
</head>
<body>
<h2>{heading}</h2>
<p>{subtitle}</p>

<table>
  <thead>
    <tr>
      <th>Device</th>
      <th>Previous UA</th>
      <th>Detected UA</th>
      <th>Detected IP</th>
      <th>First Seen</th>
      <th>Last Seen</th>
      <th>Hits</th>
    </tr>
  </thead>
  <tbody>
    {table_body}
  </tbody>
</table>

<p class="footer">
  Entries age out after 30 days of inactivity.<br>
  High-hit entries (5+) are highlighted yellow; entries with 10+ hits are amber.<br>
  {footer_note}<br>
  Contact support to investigate recurring or unexpected UA changes.
</p>
</body>
</html>"""

    return html

# -----------------------------------------------------------------------
# Send
# -----------------------------------------------------------------------

def send_digest(html, generated_at, count, full_mode):
    if not DIGEST_TO or not DIGEST_FROM:
        print("ERROR: digest 'to' and 'from' must be set in ua_monitor.conf [digest] section")
        return False

    if full_mode:
        subject = f"[UA Monitor] Full Change Log Digest ({count} entries)"
    elif count > 0:
        subject = f"{DIGEST_SUBJECT} ({count} new)"
    else:
        subject = f"{DIGEST_SUBJECT} (no new entries)"

    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From']    = DIGEST_FROM
    msg['To']      = DIGEST_TO
    msg.attach(MIMEText(html, 'html'))

    try:
        with smtplib.SMTP(DIGEST_SMTP) as s:
            s.sendmail(DIGEST_FROM, [DIGEST_TO], msg.as_string())
        mode_label = "full" if full_mode else "daily"
        print(f"Digest sent ({mode_label}): {count} entries -> {DIGEST_TO}")
        return True
    except Exception as e:
        print(f"ERROR sending digest: {e}")
        return False

# -----------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------

def main():
    full_mode = '--full' in sys.argv

    if full_mode:
        since = None
        print("Full mode — sending complete change log")
    else:
        since = read_last_digest_ts()
        if since:
            print(f"Daily mode — fetching entries since {since}")
        else:
            print("Daily mode — no previous run found, sending all entries")

    now = datetime.now()

    conn = get_connection()
    try:
        rows = fetch_change_log(conn, since=since)
    finally:
        conn.close()

    generated_at = now.strftime('%Y-%m-%d %H:%M:%S')
    html = build_html(rows, generated_at, full_mode, since=since)
    ok = send_digest(html, generated_at, len(rows), full_mode)

    # Only advance the timestamp on a successful daily run
    if ok and not full_mode:
        write_last_digest_ts(now)


if __name__ == '__main__':
    main()
