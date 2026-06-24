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

CHANGE_LOG_STALENESS_HOURS = int(_get('alert_rules', 'change_log_staleness_hours', '2'))

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
# Flap detection
# -----------------------------------------------------------------------

def classify_rows(rows):
    """
    Splits rows into true changes and flapping pairs.

    A flap pair: exactly two rows for the same device where old_ua and
    detected_ua are mirrors of each other (A->B and B->A). These are collapsed
    into a single digest row with combined hit counts and both IPs shown when
    they differ.

    Everything else — single rows, 3+ rows, or non-mirroring pairs — is treated
    as a true change and listed individually.

    Returns (true_changes, flap_pairs) each sorted by hit_count DESC.
    """
    from collections import defaultdict
    device_rows = defaultdict(list)
    for row in rows:
        key = (row['from_num'], row['domain'])
        device_rows[key].append(row)

    true_changes = []
    flap_pairs   = []

    for (from_num, domain), drows in device_rows.items():
        if len(drows) == 2:
            r0, r1 = drows[0], drows[1]
            is_mirror = (
                r0['old_ua'] == r1['detected_ua'] and
                r0['detected_ua'] == r1['old_ua']
            )
            if is_mirror:
                hits = (r0['hit_count'] or 0) + (r1['hit_count'] or 0)
                ip_a = r0['detected_ip'] or ''
                ip_b = r1['detected_ip'] or ''
                combined_ip = ip_a if ip_a == ip_b else ' / '.join(filter(None, [ip_a, ip_b]))
                fs = [x['first_seen'] for x in (r0, r1) if x['first_seen']]
                ls = [x['last_seen']  for x in (r0, r1) if x['last_seen']]
                flap_pairs.append({
                    'from_num':    from_num,
                    'domain':      domain,
                    'ua_a':        r0['old_ua'] or '',
                    'ua_b':        r0['detected_ua'] or '',
                    'detected_ip': combined_ip,
                    'first_seen':  min(fs) if fs else None,
                    'last_seen':   max(ls) if ls else None,
                    'hit_count':   hits,
                })
                continue
        true_changes.extend(drows)

    true_changes.sort(key=lambda r: -(r['hit_count'] or 0))
    flap_pairs.sort(key=lambda r: -r['hit_count'])
    return true_changes, flap_pairs

# -----------------------------------------------------------------------
# HTML email builder
# -----------------------------------------------------------------------

_TD = 'style="padding:6px 10px; border-bottom:1px solid #eee;'
_TD_BOLD = _TD + ' font-weight:bold;"'
_TD_CTR  = _TD + ' text-align:center; font-weight:bold;"'
_TD_END  = _TD + '"'

def _row_style(hits):
    if hits >= 10:
        return 'background:#FCEBEB; color:#3a1a1a;'
    if hits >= 5:
        return 'background:#fff8e1; color:#3a2e00;'
    return ''

def _fmt_ts(ts):
    if ts and hasattr(ts, 'strftime'):
        return ts.strftime('%Y-%m-%d %H:%M')
    return ts or ''

def _build_true_changes_table(rows):
    if not rows:
        return (
            '<tr><td colspan="7" style="text-align:center;color:#888;padding:20px;">'
            'No true UA changes in this period.</td></tr>'
        )
    body = ''
    for row in rows:
        device = f"{row['from_num']}@{row['domain']}"
        rs = _row_style(row['hit_count'] or 0)
        body += f"""
        <tr style="{rs}">
            <td {_TD_BOLD}>{device}</td>
            <td {_TD_END}>{row['old_ua'] or ''}</td>
            <td {_TD_END}>{row['detected_ua'] or ''}</td>
            <td {_TD_END}>{row['detected_ip'] or ''}</td>
            <td {_TD_END}>{_fmt_ts(row['first_seen'])}</td>
            <td {_TD_END}>{_fmt_ts(row['last_seen'])}</td>
            <td {_TD_CTR}>{row['hit_count']}</td>
        </tr>"""
    return body

def _build_flap_table(flap_pairs):
    if not flap_pairs:
        return (
            '<tr><td colspan="7" style="text-align:center;color:#888;padding:20px;">'
            'No flapping devices in this period.</td></tr>'
        )
    body = ''
    for fp in flap_pairs:
        device = f"{fp['from_num']}@{fp['domain']}"
        rs = _row_style(fp['hit_count'])
        body += f"""
        <tr style="{rs}">
            <td {_TD_BOLD}>{device}</td>
            <td {_TD_END}>{fp['ua_a']}</td>
            <td {_TD_END}>{fp['ua_b']}</td>
            <td {_TD_END}>{fp['detected_ip']}</td>
            <td {_TD_END}>{_fmt_ts(fp['first_seen'])}</td>
            <td {_TD_END}>{_fmt_ts(fp['last_seen'])}</td>
            <td {_TD_CTR}>{fp['hit_count']}</td>
        </tr>"""
    return body

def build_html(rows, generated_at, full_mode, since=None):
    true_changes, flap_pairs = classify_rows(rows)
    raw_count  = len(rows)
    tc_count   = len(true_changes)
    flap_count = len(flap_pairs)

    if full_mode:
        heading = "UA Monitor — Full Change Log Digest"
        subtitle = (
            f"Generated: {generated_at} &nbsp;|&nbsp; "
            f"Total entries: <strong>{raw_count}</strong> &nbsp;|&nbsp; "
            f"True changes: <strong>{tc_count}</strong> &nbsp;|&nbsp; "
            f"Flapping devices: <strong>{flap_count}</strong> "
            f"({raw_count - tc_count} raw entries collapsed)"
        )
    else:
        since_str = since.strftime('%Y-%m-%d %H:%M') if since else 'beginning'
        heading = "UA Monitor — Daily Change Log Digest"
        subtitle = (
            f"Generated: {generated_at} &nbsp;|&nbsp; "
            f"New since: {since_str} &nbsp;|&nbsp; "
            f"New entries: <strong>{raw_count}</strong> &nbsp;|&nbsp; "
            f"True changes: <strong>{tc_count}</strong> &nbsp;|&nbsp; "
            f"Flapping devices: <strong>{flap_count}</strong>"
        )

    th_style  = 'style="background:#2c3e50; color:#fff; padding:8px 10px; text-align:left;"'
    th_style_ctr = 'style="background:#2c3e50; color:#fff; padding:8px 10px; text-align:center;"'
    section_hdr = (
        'style="display:inline-block; font-size:12px; font-weight:bold; '
        'letter-spacing:0.04em; text-transform:uppercase; '
        'background:#2c3e50; color:#fff; padding:5px 12px; '
        'margin:20px 0 0; border-radius:4px 4px 0 0;"'
    )

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
  body  {{ font-family: Arial, sans-serif; font-size: 13px; color: #333; }}
  h2    {{ color: #c0392b; }}
  table {{ border-collapse: collapse; width: 100%; max-width: 1100px; }}
  th    {{ padding: 8px 10px; text-align: left; }}
  .footer {{ color:#999; font-size:11px; margin-top:16px; }}
</style>
</head>
<body>
<h2>{heading}</h2>
<p>{subtitle}</p>

<p {section_hdr}>True UA changes</p>
<table>
  <thead>
    <tr>
      <th {th_style}>Device</th>
      <th {th_style}>Previous UA</th>
      <th {th_style}>Detected UA</th>
      <th {th_style}>Detected IP</th>
      <th {th_style}>First Seen</th>
      <th {th_style}>Last Seen</th>
      <th {th_style_ctr}>Hits</th>
    </tr>
  </thead>
  <tbody>
    {_build_true_changes_table(true_changes)}
  </tbody>
</table>

<p {section_hdr}>Flapping devices</p>
<table>
  <thead>
    <tr>
      <th {th_style}>Device</th>
      <th {th_style}>UA (A)</th>
      <th {th_style}>UA (B)</th>
      <th {th_style}>IPs seen</th>
      <th {th_style}>First Seen</th>
      <th {th_style}>Last Seen</th>
      <th {th_style_ctr}>Hits</th>
    </tr>
  </thead>
  <tbody>
    {_build_flap_table(flap_pairs)}
  </tbody>
</table>

<p class="footer">
  Flapping devices oscillate between two UAs; hit counts reflect both directions combined.<br>
  Entries age out after 30 days of inactivity. A re-alert fires if the same UA reappears
  after more than {CHANGE_LOG_STALENESS_HOURS}h of inactivity (staleness threshold).<br>
  Row highlighting: red = 10+ hits, yellow = 5&ndash;9 hits.<br>
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
