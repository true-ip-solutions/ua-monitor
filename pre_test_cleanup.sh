#!/bin/bash
# pre_test_cleanup.sh
#
# Removes remnants of a prior ua-monitor installation so a clean test
# can be run from scratch.
#
# What this script does:
#   1. Removes old bash scripts from INSTALL_DIR (if any remain)
#   2. Removes ua_monitor cron entries
#   3. Truncates ua_monitor DB tables (device_ua, change_log)
#   4. Clears the log file and digest timestamp
#
# It does NOT touch the Python scripts (.py files), suppress.conf,
# or ua_monitor.conf.
#
# Usage:
#   sudo bash pre_test_cleanup.sh

INSTALL_DIR="/opt/ua_monitor"
LOG="/var/log/ua_monitor.log"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

ok()   { echo -e "${GREEN}  ✓ $*${NC}"; }
warn() { echo -e "${YELLOW}  ! $*${NC}"; }
err()  { echo -e "${RED}  ✗ $*${NC}"; exit 1; }

echo ""
echo "========================================"
echo "  UA Monitor — Pre-Test Cleanup"
echo "========================================"
echo ""

[ "$EUID" -ne 0 ] && err "Please run as root: sudo bash pre_test_cleanup.sh"

# -----------------------------------------------------------------------
# DB credentials
# -----------------------------------------------------------------------

echo -e "${YELLOW}UA Monitor DB password (needed to truncate tracking tables):${NC}"
read -rsp "  > " DB_PASS < /dev/tty
echo ""

# -----------------------------------------------------------------------
# 1. Remove old bash scripts
# -----------------------------------------------------------------------

OLD_FILES=(
    check_ua.sh
    notify.sh
    notify_slack.sh
    notify_email.sh
    notify_teams.sh
    notify_pagerduty.sh
    cleanup.sh
    query.sql
)

for f in "${OLD_FILES[@]}"; do
    target="${INSTALL_DIR}/${f}"
    if [ -f "$target" ]; then
        rm -f "$target"
        ok "Removed $f"
    fi
done

# -----------------------------------------------------------------------
# 2. Remove cron entries that reference the old bash scripts
# -----------------------------------------------------------------------

CURRENT_CRON=$(crontab -l 2>/dev/null)

if echo "$CURRENT_CRON" | grep -q "ua_monitor"; then
    # Remove any ua_monitor cron lines
    NEW_CRON=$(echo "$CURRENT_CRON" | grep -v "ua_monitor")
    if [ -z "$NEW_CRON" ]; then
        crontab -r 2>/dev/null
    else
        echo "$NEW_CRON" | crontab -
    fi
    ok "Removed ua_monitor cron entries"
else
    warn "No ua_monitor cron entries found — skipping"
fi

# -----------------------------------------------------------------------
# 3. Truncate DB tables
# -----------------------------------------------------------------------

mysql -u"ua_monitor" -p"${DB_PASS}" ua_monitor 2>/dev/null <<'SQL'
TRUNCATE TABLE device_ua;
TRUNCATE TABLE change_log;
SQL

if [ $? -eq 0 ]; then
    ok "Truncated ua_monitor tables (device_ua, change_log)"
else
    warn "DB truncate failed — check password or run manually:"
    warn "  mysql -u'ua_monitor' -p'yourpassword' ua_monitor -e 'TRUNCATE TABLE device_ua; TRUNCATE TABLE change_log;'"
fi

# -----------------------------------------------------------------------
# 4. Clear log file
# -----------------------------------------------------------------------

if [ -f "$LOG" ]; then
    > "$LOG"
    ok "Cleared $LOG"
fi

# Clear digest timestamp so next digest run treats everything as new
DIGEST_TS="/opt/ua_monitor/last_digest.ts"
if [ -f "$DIGEST_TS" ]; then
    rm -f "$DIGEST_TS"
    ok "Removed digest timestamp ($DIGEST_TS)"
fi

# -----------------------------------------------------------------------
# Done
# -----------------------------------------------------------------------

echo ""
echo "========================================"
echo -e "${GREEN}  Cleanup complete. Ready for a clean test run.${NC}"
echo "========================================"
echo ""
echo "  Next steps:"
echo "    1. Confirm Python scripts are in ${INSTALL_DIR}:"
echo "       ls -la ${INSTALL_DIR}/*.py"
echo "    2. Seed the DB:"
echo "       python3 ${INSTALL_DIR}/check_ua.py --seed"
echo "    3. Run once and verify output:"
echo "       python3 ${INSTALL_DIR}/check_ua.py"
echo "    4. Check the log:"
echo "       tail -f ${LOG}"
echo ""
