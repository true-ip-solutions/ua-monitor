#!/usr/bin/env python3
# /opt/ua_monitor/cleanup.py
#
# UA Monitor — weekly cleanup script.
# Removes stale devices and trims log tables.
# Run weekly via cron:
#   0 3 * * 0 /opt/ua_monitor/cleanup.py

import logging
import configparser

import pymysql
import pymysql.cursors

# -----------------------------------------------------------------------
# Configuration — read from /opt/ua_monitor/ua_monitor.conf
# -----------------------------------------------------------------------

_cfg = configparser.ConfigParser()
_cfg.read("/opt/ua_monitor/ua_monitor.conf")

def _get(section, key, fallback=''):
    return _cfg.get(section, key, fallback=fallback)

DB_USER        = _get('database', 'db_user',       'ua_monitor')
DB_PASS        = _get('database', 'db_pass')
DB_HOST        = _get('database', 'db_host',       'localhost')
LOG_FILE       = _get('monitor',  'log_file',      '/var/log/ua_monitor.log')
RETENTION_DAYS = int(_get('monitor', 'retention_days', '90'))

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
# Main
# -----------------------------------------------------------------------

def main():
    conn = pymysql.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASS,
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True
    )

    try:
        with conn.cursor() as cur:
            cur.execute("""
                DELETE FROM ua_monitor.device_ua
                WHERE last_seen < NOW() - INTERVAL %s DAY
            """, (RETENTION_DAYS,))
            deleted = cur.rowcount

        with conn.cursor() as cur:
            cur.execute("""
                DELETE FROM ua_monitor.digest_log
                WHERE sent_at < NOW() - INTERVAL %s DAY
            """, (RETENTION_DAYS,))

        msg = f"CLEANUP: Removed {deleted} stale devices (not seen in {RETENTION_DAYS} days)"
        log(msg)
        print(msg)

    finally:
        conn.close()


if __name__ == '__main__':
    main()
