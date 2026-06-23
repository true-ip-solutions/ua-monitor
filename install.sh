#!/bin/bash
# UA Monitor Installer
# Pulls latest files from GitHub and configures the system

GITHUB_REPO="${GITHUB_REPO:-https://raw.githubusercontent.com/traviscw/ua-monitor/main}"
INSTALL_DIR="/opt/ua_monitor"
LOG="/var/log/ua_monitor.log"

# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

ok()   { echo -e "${GREEN}  ✓ $*${NC}"; }
warn() { echo -e "${YELLOW}  ! $*${NC}"; }
err()  { echo -e "${RED}  ✗ $*${NC}"; exit 1; }
ask()  { echo -e "\n${YELLOW}$*${NC}"; }

# -----------------------------------------------------------------------
# Checks
# -----------------------------------------------------------------------

echo ""
echo "========================================"
echo "  UA Monitor Installer"
echo "========================================"
echo ""

[ "$EUID" -ne 0 ] && err "Please run as root: sudo bash install.sh"

command -v mysql   &>/dev/null || err "mysql client not found — is VoIPmonitor installed?"
command -v curl    &>/dev/null || err "curl not found — please install: apt install curl"
command -v python3 &>/dev/null || err "python3 not found — please install: apt install python3 python3-pip"

# Ensure pip is available
if ! python3 -m pip --version &>/dev/null; then
    warn "pip not found — attempting to install..."
    apt-get install -y python3-pip &>/dev/null || err "Failed to install python3-pip — please install manually"
fi

ok "Prerequisites OK"

# -----------------------------------------------------------------------
# Gather config
# -----------------------------------------------------------------------

ask "MySQL root password (for one-time DB setup):"
read -rsp "  > " MYSQL_ROOT_PASS < /dev/tty
echo ""

ask "UA Monitor DB password (will be set for the ua_monitor MySQL user):"
read -rsp "  > " DB_PASS < /dev/tty
echo ""

ask "Notification provider (slack / email / teams / pagerduty) [slack]:"
read -r NOTIFY_PROVIDER < /dev/tty
NOTIFY_PROVIDER="${NOTIFY_PROVIDER:-slack}"

case "$NOTIFY_PROVIDER" in
    slack)
        ask "Slack webhook URL:"
        read -r SLACK_WEBHOOK < /dev/tty
        [[ "$SLACK_WEBHOOK" == https://hooks.slack.com/* ]] || warn "Webhook URL looks unusual — double check it"
        ;;
    email)
        ask "Email address to send alerts to:"
        read -r EMAIL_TO < /dev/tty
        ask "Email address to send alerts from:"
        read -r EMAIL_FROM < /dev/tty
        ;;
    teams)
        ask "Microsoft Teams webhook URL:"
        read -r TEAMS_WEBHOOK < /dev/tty
        ;;
    pagerduty)
        ask "PagerDuty Events API v2 routing key (Integration Key from your PagerDuty service):"
        read -r PD_ROUTING_KEY < /dev/tty
        [ -z "$PD_ROUTING_KEY" ] && err "Routing key cannot be empty"
        ask "Alert severity for device changes (critical / error / warning / info) [warning]:"
        read -r PD_SEVERITY_CHANGE < /dev/tty
        PD_SEVERITY_CHANGE="${PD_SEVERITY_CHANGE:-warning}"
        case "$PD_SEVERITY_CHANGE" in
            critical|error|warning|info) ;;
            *) err "Invalid severity: $PD_SEVERITY_CHANGE — must be critical, error, warning, or info" ;;
        esac
        ;;
    *)
        err "Unknown provider: $NOTIFY_PROVIDER — must be slack, email, teams, or pagerduty"
        ;;
esac

ask "Alert mode (auto / ua_only / ip_only / ua_and_ip / ua_or_ip) [auto]:"
read -r ALERT_MODE < /dev/tty
ALERT_MODE="${ALERT_MODE:-auto}"

ask "Ignore IP octet count (0-3, 0 = disabled) [0]:"
read -r IGNORE_OCTET_COUNT < /dev/tty
IGNORE_OCTET_COUNT="${IGNORE_OCTET_COUNT:-0}"

ask "Mobile UA prefixes for auto mode (comma-separated, e.g. snapmobile,zoiper,groundwire) []:"
read -r MOBILE_UA_PREFIXES < /dev/tty

ask "Digest recipient email address:"
read -r DIGEST_TO < /dev/tty

ask "Digest sender email address:"
read -r DIGEST_FROM < /dev/tty

ask "Digest email subject [[UA Monitor] Daily Change Log Digest]:"
read -r DIGEST_SUBJECT < /dev/tty
DIGEST_SUBJECT="${DIGEST_SUBJECT:-[UA Monitor] Daily Change Log Digest}"

echo ""
echo "========================================"
echo "  Installing..."
echo "========================================"

# -----------------------------------------------------------------------
# Download files
# -----------------------------------------------------------------------

mkdir -p "$INSTALL_DIR"

FILES=(check_ua.py notify.py cleanup.py digest.py suppress.conf)

for f in "${FILES[@]}"; do
    curl -fsSL "${GITHUB_REPO}/${f}" -o "${INSTALL_DIR}/${f}" \
        || err "Failed to download ${f} from GitHub"
    ok "Downloaded $f"
done

# -----------------------------------------------------------------------
# Install Python dependencies
# -----------------------------------------------------------------------

python3 -m pip install --quiet pymysql \
    || err "Failed to install pymysql — check pip and network connectivity"
ok "Python dependencies installed"

# -----------------------------------------------------------------------
# Write configuration file
# -----------------------------------------------------------------------

# Only write if one doesn't already exist (preserve credentials on reinstall)
if [ -f "${INSTALL_DIR}/ua_monitor.conf" ]; then
    warn "ua_monitor.conf already exists — skipping (credentials preserved)"
else
    cat > "${INSTALL_DIR}/ua_monitor.conf" << EOF
[database]
db_user = ua_monitor
db_pass = ${DB_PASS}
db_host = localhost

[monitor]
log_file = ${LOG}
suppress_conf = ${INSTALL_DIR}/suppress.conf
lookback_minutes = 6
alert_mode = ${ALERT_MODE}
ignore_octet_count = ${IGNORE_OCTET_COUNT}
retention_days = 90

[alert_rules]
mobile_ua_prefixes = ${MOBILE_UA_PREFIXES}

[notify]
provider = ${NOTIFY_PROVIDER}
EOF

    case "$NOTIFY_PROVIDER" in
        slack)
            cat >> "${INSTALL_DIR}/ua_monitor.conf" << EOF

[slack]
webhook = ${SLACK_WEBHOOK}
EOF
            ;;
        email)
            cat >> "${INSTALL_DIR}/ua_monitor.conf" << EOF

[email]
to = ${EMAIL_TO}
from = ${EMAIL_FROM}
EOF
            ;;
        teams)
            cat >> "${INSTALL_DIR}/ua_monitor.conf" << EOF

[teams]
webhook = ${TEAMS_WEBHOOK}
EOF
            ;;
        pagerduty)
            cat >> "${INSTALL_DIR}/ua_monitor.conf" << EOF

[pagerduty]
routing_key = ${PD_ROUTING_KEY}
source =
severity_change = ${PD_SEVERITY_CHANGE}
EOF
            ;;
    esac

    cat >> "${INSTALL_DIR}/ua_monitor.conf" << EOF

[digest]
to = ${DIGEST_TO}
from = ${DIGEST_FROM}
subject = ${DIGEST_SUBJECT}
smtp_host = localhost
EOF

    ok "Configuration written"
fi

# -----------------------------------------------------------------------
# Permissions
# -----------------------------------------------------------------------

chmod 700 "${INSTALL_DIR}/check_ua.py"
chmod 700 "${INSTALL_DIR}/notify.py"
chmod 700 "${INSTALL_DIR}/cleanup.py"
chmod 700 "${INSTALL_DIR}/digest.py"
chmod 600 "${INSTALL_DIR}/suppress.conf"
chmod 600 "${INSTALL_DIR}/ua_monitor.conf"

touch "$LOG"
chmod 640 "$LOG"

ok "Permissions set"

# -----------------------------------------------------------------------
# Database setup
# -----------------------------------------------------------------------

# Download and apply setup.sql
curl -fsSL "${GITHUB_REPO}/setup.sql" -o /tmp/ua_monitor_setup.sql \
    || err "Failed to download setup.sql from GitHub"

# Substitute password placeholder
sed -i "s|yourpassword|${DB_PASS}|g" /tmp/ua_monitor_setup.sql

mysql -u root -p"${MYSQL_ROOT_PASS}" < /tmp/ua_monitor_setup.sql 2>/dev/null \
    || err "Database setup failed — check your MySQL root password"

rm -f /tmp/ua_monitor_setup.sql
ok "Database configured"

# -----------------------------------------------------------------------
# Seed
# -----------------------------------------------------------------------

echo ""
echo "  Seeding device database (scanning last 24 hours)..."
python3 "${INSTALL_DIR}/check_ua.py" --seed
ok "Seed complete"

# -----------------------------------------------------------------------
# Cron
# -----------------------------------------------------------------------

echo ""
ask "Install cron jobs? (y/n) [y]:"
read -r INSTALL_CRON < /dev/tty
INSTALL_CRON="${INSTALL_CRON:-y}"

if [[ "$INSTALL_CRON" =~ ^[Yy]$ ]]; then
    # Check if cron entries already exist
    crontab -l 2>/dev/null | grep -q "ua_monitor" && warn "Cron entries already exist — skipping" || {
        (crontab -l 2>/dev/null; echo "*/5 * * * * python3 ${INSTALL_DIR}/check_ua.py") | crontab -
        (crontab -l 2>/dev/null; echo "0 3 * * 0 python3 ${INSTALL_DIR}/cleanup.py") | crontab -
        ok "Monitor and cleanup cron jobs installed"
    }

    ask "Install daily digest cron job? (y/n) [y]:"
    read -r INSTALL_DIGEST_CRON < /dev/tty
    INSTALL_DIGEST_CRON="${INSTALL_DIGEST_CRON:-y}"

    if [[ "$INSTALL_DIGEST_CRON" =~ ^[Yy]$ ]]; then
        ask "Digest cron schedule (cron expression) [0 7 * * *] (7am daily):"
        read -r DIGEST_CRON < /dev/tty
        DIGEST_CRON="${DIGEST_CRON:-0 7 * * *}"
        (crontab -l 2>/dev/null; echo "${DIGEST_CRON} python3 ${INSTALL_DIR}/digest.py") | crontab -
        ok "Digest cron job installed ($DIGEST_CRON)"
    fi
fi

# -----------------------------------------------------------------------
# Done
# -----------------------------------------------------------------------

echo ""
echo "========================================"
echo -e "${GREEN}  UA Monitor installed successfully!${NC}"
echo "========================================"
echo ""
echo "  Install dir:  $INSTALL_DIR"
echo "  Log file:     $LOG"
echo "  Provider:     $NOTIFY_PROVIDER"
echo "  Alert mode:   $ALERT_MODE"
echo "  Digest to:    $DIGEST_TO"
echo ""
echo "  Useful commands:"
echo "    tail -f $LOG"
echo "    python3 ${INSTALL_DIR}/check_ua.py"
echo "    python3 ${INSTALL_DIR}/digest.py   (manual digest trigger)"
echo ""
