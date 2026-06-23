#!/usr/bin/env python3
# /opt/ua_monitor/check_ua.py
#
# UA Monitor — main monitoring script.
# Queries VoIPmonitor's register_state table for UA/IP changes and fires alerts.
# Run every 5 minutes via cron.

import sys
import logging
import configparser
from datetime import datetime
from pathlib import Path

import pymysql
import pymysql.cursors

# -----------------------------------------------------------------------
# Configuration — read from /opt/ua_monitor/ua_monitor.conf
# -----------------------------------------------------------------------

_cfg = configparser.ConfigParser()
_cfg.read("/opt/ua_monitor/ua_monitor.conf")

def _get(section, key, fallback=''):
    return _cfg.get(section, key, fallback=fallback)

DB_USER            = _get('database', 'db_user',       'ua_monitor')
DB_PASS            = _get('database', 'db_pass')
DB_HOST            = _get('database', 'db_host',       'localhost')
LOG_FILE           = _get('monitor',  'log_file',      '/var/log/ua_monitor.log')
SUPPRESS_CONF      = _get('monitor',  'suppress_conf', '/opt/ua_monitor/suppress.conf')
LOOKBACK_MINUTES   = int(_get('monitor', 'lookback_minutes',   '6'))
ALERT_MODE         = _get('monitor',  'alert_mode',         'auto')
IGNORE_OCTET_COUNT = int(_get('monitor', 'ignore_octet_count', '0'))

# Comma-separated UA prefixes treated as mobile/softphone (case-insensitive).
# Everything else is treated as hardware. Unknown UAs default to hardware
# treatment (stricter/safer).
_raw_prefixes      = _get('alert_rules', 'mobile_ua_prefixes', '')
MOBILE_UA_PREFIXES = [p.strip() for p in _raw_prefixes.split(',') if p.strip()]

# -----------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------

logging.basicConfig(
    filename=LOG_FILE,
    format="[%(asctime)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=logging.INFO
)

def log(msg):
    logging.info(msg)

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

# -----------------------------------------------------------------------
# Suppression rules
# -----------------------------------------------------------------------

def load_suppress_rules():
    path = Path(SUPPRESS_CONF)
    if not path.exists():
        return []
    rules = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith('#'):
            rules.append(line)
    return rules

def should_suppress(rules, from_num, domain, device_ip, old_ua, new_ua):
    device_key = f"{from_num}@{domain}"
    for rule in rules:
        if rule.startswith('DEVICE:'):
            if device_key == rule[7:]:
                log(f"SUPPRESSED (device match: {device_key})")
                return True
        elif rule.startswith('DOMAIN:'):
            if domain == rule[7:]:
                log(f"SUPPRESSED (domain match: {domain})")
                return True
        elif rule.startswith('IP:'):
            if device_ip == rule[3:]:
                log(f"SUPPRESSED (whitelisted IP {device_ip})")
                return True
        elif rule.startswith('UA:'):
            ua = rule[3:]
            if old_ua == ua or new_ua == ua:
                log(f"SUPPRESSED (UA match: {ua})")
                return True
        elif rule.startswith('UA_PREFIX:'):
            prefix = rule[10:]
            if old_ua.startswith(prefix) or new_ua.startswith(prefix):
                log(f"SUPPRESSED (UA prefix match: {prefix})")
                return True
        elif rule.startswith('UA_CHANGE:'):
            pair = rule[10:]
            if '->' in pair:
                from_ua, to_ua = pair.split('->', 1)
                if old_ua == from_ua and new_ua == to_ua:
                    log(f"SUPPRESSED (UA change: {from_ua} -> {to_ua})")
                    return True
        elif rule.startswith('UA_CHANGE_PREFIX:'):
            pair = rule[17:]
            if '->' in pair:
                from_prefix, to_prefix = pair.split('->', 1)
                if old_ua.startswith(from_prefix) and new_ua.startswith(to_prefix):
                    log(f"SUPPRESSED (UA change prefix match: {from_prefix} -> {to_prefix})")
                    return True
    return False

# -----------------------------------------------------------------------
# UA classification and alert mode
# -----------------------------------------------------------------------

def is_mobile(ua):
    """Returns True if the UA string matches a known mobile/softphone prefix."""
    if not ua or ua == 'NONE':
        return False
    ua_lower = ua.lower()
    return any(ua_lower.startswith(p.lower()) for p in MOBILE_UA_PREFIXES)

def should_alert(ip_changed, ua_changed, old_ua, new_ua):
    """
    Determine whether a detected change should trigger a notification.

    alert_mode = auto (recommended):
      - Both hardware:      alert only when both UA and IP changed (ua_and_ip)
      - Both mobile:        alert only when UA changed (ua_only)
      - Cross-category:     always alert (hardware<->mobile transition)

    alert_mode = ua_only | ip_only | ua_and_ip | ua_or_ip:
      - Global override applied uniformly to all devices.
    """
    if ALERT_MODE != 'auto':
        if ALERT_MODE == 'ua_only':
            return ua_changed
        elif ALERT_MODE == 'ip_only':
            return ip_changed
        elif ALERT_MODE == 'ua_and_ip':
            return ip_changed and ua_changed
        else:  # ua_or_ip
            return ip_changed or ua_changed

    old_mobile = is_mobile(old_ua)
    new_mobile = is_mobile(new_ua)

    if old_mobile != new_mobile:
        return True              # cross-category: always alert
    if old_mobile and new_mobile:
        return ua_changed        # both mobile: ua_only
    return ip_changed and ua_changed  # both hardware: ua_and_ip

# -----------------------------------------------------------------------
# Subnet helpers
# -----------------------------------------------------------------------

def same_subnet(ip1, ip2):
    if IGNORE_OCTET_COUNT == 0:
        return False
    n = 4 - IGNORE_OCTET_COUNT
    return '.'.join(ip1.split('.')[:n]) == '.'.join(ip2.split('.')[:n])

# -----------------------------------------------------------------------
# SQL — change detection
# -----------------------------------------------------------------------

CHANGE_QUERY = """
SELECT
    rs.from_num,
    rs.to_domain,
    INET_NTOA(rs.sipcallerip) AS device_ip,
    cu.ua AS current_ua,
    COALESCE(d.last_ua, 'NONE') AS known_ua,
    COALESCE(d.contact_ip, 'NONE') AS known_ip,
    CASE WHEN d.from_num IS NULL THEN 'new' ELSE 'changed' END AS change_type
FROM (
    SELECT r1.from_num, r1.to_domain,
           MAX(r1.sipcallerip) AS sipcallerip,
           MAX(r1.ua_id) AS ua_id
    FROM voipmonitor.register_state r1
    INNER JOIN (
        SELECT from_num, to_domain, MAX(created_at) AS max_created
        FROM voipmonitor.register_state
        WHERE state = 1
          AND created_at >= NOW() - INTERVAL %s MINUTE
        GROUP BY from_num, to_domain
    ) r2 ON r1.from_num = r2.from_num
         AND r1.to_domain = r2.to_domain
         AND r1.created_at = r2.max_created
    WHERE r1.state = 1
    GROUP BY r1.from_num, r1.to_domain
) rs
LEFT JOIN voipmonitor.cdr_ua cu ON cu.id = rs.ua_id
LEFT JOIN ua_monitor.device_ua d
       ON d.from_num = rs.from_num
      AND d.domain = rs.to_domain
WHERE cu.ua IS NOT NULL
  AND (
      d.from_num IS NULL
      OR d.last_ua  != cu.ua
      OR d.contact_ip != INET_NTOA(rs.sipcallerip)
  )
"""

def get_changes(conn, lookback):
    with conn.cursor() as cur:
        cur.execute(CHANGE_QUERY, (lookback,))
        return cur.fetchall()

# -----------------------------------------------------------------------
# SQL — active registrations (batched)
# -----------------------------------------------------------------------

def get_active_registrations_batch(conn, device_pairs):
    if not device_pairs:
        return {}
    placeholders = ', '.join(['(%s, %s)'] * len(device_pairs))
    query = f"""
        SELECT
            rs.from_num,
            rs.to_domain,
            INET_NTOA(rs.sipcallerip) AS ip,
            cu.ua,
            MAX(rs.created_at) AS last_seen
        FROM voipmonitor.register_state rs
        LEFT JOIN voipmonitor.cdr_ua cu ON cu.id = rs.ua_id
        WHERE (rs.from_num, rs.to_domain) IN ({placeholders})
          AND rs.state = 1
          AND rs.created_at >= NOW() - INTERVAL 60 MINUTE
        GROUP BY rs.from_num, rs.to_domain, INET_NTOA(rs.sipcallerip), cu.ua
        ORDER BY rs.from_num, rs.to_domain, last_seen DESC
    """
    params = [val for pair in device_pairs for val in pair]
    with conn.cursor() as cur:
        cur.execute(query, params)
        rows = cur.fetchall()
    result = {}
    for row in rows:
        key = (row['from_num'], row['to_domain'])
        result.setdefault(key, []).append(row)
    return result

# -----------------------------------------------------------------------
# SQL — device state writes
# -----------------------------------------------------------------------

UPSERT_SQL = """
    INSERT INTO ua_monitor.device_ua
        (from_num, domain, contact_ip, last_ua, first_seen, last_seen)
    VALUES (%s, %s, %s, %s, NOW(), NOW())
    ON DUPLICATE KEY UPDATE
        contact_ip = VALUES(contact_ip),
        last_ua    = VALUES(last_ua),
        last_seen  = NOW()
"""

def upsert_devices_batch(conn, rows):
    """rows: list of (from_num, domain, contact_ip, last_ua)"""
    if not rows:
        return
    with conn.cursor() as cur:
        cur.executemany(UPSERT_SQL, rows)

def update_last_seen_bulk(conn, lookback):
    with conn.cursor() as cur:
        cur.execute("""
            UPDATE ua_monitor.device_ua d
            INNER JOIN (
                SELECT rs.from_num, rs.to_domain
                FROM voipmonitor.register_state rs
                WHERE rs.state = 1
                  AND rs.created_at >= NOW() - INTERVAL %s MINUTE
                GROUP BY rs.from_num, rs.to_domain
            ) rs ON rs.from_num = d.from_num
                AND rs.to_domain = d.domain
            SET d.last_seen = NOW()
        """, (lookback,))

# -----------------------------------------------------------------------
# SQL — change log (deduplication)
# -----------------------------------------------------------------------

def in_change_log(conn, from_num, domain, detected_ua):
    """Returns True if this UA has already been notified for this extension."""
    with conn.cursor() as cur:
        cur.execute("""
            SELECT id FROM ua_monitor.change_log
            WHERE from_num = %s AND domain = %s AND detected_ua = %s
        """, (from_num, domain, detected_ua))
        return cur.fetchone() is not None

def upsert_change_log(conn, entries):
    """
    entries: list of (from_num, domain, old_ua, detected_ua, detected_ip)
    Inserts new entries or increments hit_count on duplicates.
    """
    if not entries:
        return
    sql = """
        INSERT INTO ua_monitor.change_log
            (from_num, domain, old_ua, detected_ua, detected_ip,
             first_seen, last_seen, hit_count)
        VALUES (%s, %s, %s, %s, %s, NOW(), NOW(), 1)
        ON DUPLICATE KEY UPDATE
            last_seen = NOW(),
            hit_count = hit_count + 1
    """
    with conn.cursor() as cur:
        cur.executemany(sql, entries)

# -----------------------------------------------------------------------
# Notification
# -----------------------------------------------------------------------

def send_notification(count, data):
    try:
        sys.path.insert(0, '/opt/ua_monitor')
        import notify
        return notify.send(count, data)
    except Exception as e:
        log(f"NOTIFY ERROR: {e}")
        return False

# -----------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------

def main():
    seed_mode = '--seed' in sys.argv
    lookback  = 1440 if seed_mode else LOOKBACK_MINUTES

    if seed_mode:
        print("Seed mode enabled — scanning last 24 hours, notifications suppressed")

    suppress_rules = load_suppress_rules()
    conn = get_connection()

    try:
        changes = get_changes(conn, lookback)

        if not changes:
            print("No changes detected.")
            return

        # ---------------------------------------------------------------
        # Seed mode — upsert everything, no alerts
        # ---------------------------------------------------------------
        if seed_mode:
            upsert_devices_batch(conn, [
                (r['from_num'], r['to_domain'], r['device_ip'], r['current_ua'])
                for r in changes
            ])
            for r in changes:
                log(f"SEED: {r['from_num']}@{r['to_domain']} @ {r['device_ip']} | UA: {r['current_ua']}")
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) AS cnt FROM ua_monitor.device_ua")
                total = cur.fetchone()['cnt']
            print(f"Seed complete — {total} devices recorded in tracking table")
            return

        # ---------------------------------------------------------------
        # Normal mode
        # ---------------------------------------------------------------
        new_devices     = [r for r in changes if r['change_type'] == 'new']
        changed_devices = [r for r in changes if r['change_type'] == 'changed']

        # New devices — upsert only, no notification
        if new_devices:
            upsert_devices_batch(conn, [
                (r['from_num'], r['to_domain'], r['device_ip'], r['current_ua'])
                for r in new_devices
            ])
            for r in new_devices:
                log(f"NEW: {r['from_num']}@{r['to_domain']} @ {r['device_ip']} | UA: {r['current_ua']}")

        # Fetch active registrations for all changed devices in one query
        device_pairs = [(r['from_num'], r['to_domain']) for r in changed_devices]
        active_regs_map = get_active_registrations_batch(conn, device_pairs)

        alert_list        = []
        all_upserts       = []
        change_log_entries = []

        for r in changed_devices:
            from_num   = r['from_num']
            domain     = r['to_domain']
            device_ip  = r['device_ip']
            current_ua = r['current_ua']
            known_ua   = r['known_ua']
            known_ip   = r['known_ip']

            ip_changed = False
            ua_changed = (current_ua != known_ua)

            if known_ip != device_ip:
                if IGNORE_OCTET_COUNT > 0 and same_subnet(known_ip, device_ip):
                    log(f"OCTET CHANGE IGNORED (last {IGNORE_OCTET_COUNT} octet(s)): "
                        f"{from_num}@{domain} | IP: {known_ip} -> {device_ip}")
                else:
                    ip_changed = True

            all_upserts.append((from_num, domain, device_ip, current_ua))

            if should_suppress(suppress_rules, from_num, domain, device_ip, known_ua, current_ua):
                pass  # upsert still queued; no alert
            elif should_alert(ip_changed, ua_changed, known_ua, current_ua):
                what = []
                if ip_changed:
                    what.append(f"IP: {known_ip} -> {device_ip}")
                if ua_changed:
                    what.append(f"UA: {known_ua} -> {current_ua}")
                log(f"CHANGE ({ALERT_MODE}): {from_num}@{domain} | {' | '.join(what)}")

                active_regs = active_regs_map.get((from_num, domain), [])

                already_notified = in_change_log(conn, from_num, domain, current_ua)

                if not already_notified:
                    alert_list.append({
                        'device':      f"{from_num}@{domain}",
                        'old_ip':      known_ip,
                        'new_ip':      device_ip,
                        'old_ua':      known_ua,
                        'new_ua':      current_ua,
                        'active_regs': active_regs,
                    })
                    # Record both directions so oscillation reverse is also silenced
                    change_log_entries.append(
                        (from_num, domain, known_ua,   current_ua, device_ip))
                    change_log_entries.append(
                        (from_num, domain, current_ua, known_ua,   known_ip))
                else:
                    # Already notified — increment counter only
                    change_log_entries.append(
                        (from_num, domain, known_ua, current_ua, device_ip))
                    log(f"DEDUP: {from_num}@{domain} | {current_ua} (already in change log)")
            else:
                log(f"SILENT ({ALERT_MODE}): {from_num}@{domain} @ {device_ip} | UA: {current_ua}")

        # Batch writes
        upsert_devices_batch(conn, all_upserts)
        upsert_change_log(conn, change_log_entries)

        # Send all new alerts as a single notification
        if alert_list:
            send_notification(len(alert_list), {
                'changes':     alert_list,
                'detected_at': datetime.now().strftime('%c'),
            })

        # Bulk last-seen refresh for all currently registered devices
        update_last_seen_bulk(conn, lookback)

    finally:
        conn.close()


if __name__ == '__main__':
    main()
