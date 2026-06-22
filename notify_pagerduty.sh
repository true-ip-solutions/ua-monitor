#!/bin/bash
# /opt/ua_monitor/notify_pagerduty.sh
# PagerDuty Events API v2 notification handler

PD_ROUTING_KEY="XXXX"
PD_SOURCE=""                        # leave empty to auto-detect from hostname
PD_SEVERITY_CHANGE="warning"        # critical | error | warning | info
PD_SEVERITY_NEW_DEVICE="info"       # critical | error | warning | info
PD_API_URL="https://events.pagerduty.com/v2/enqueue"

send_pagerduty() {
    local payload="$1"
    curl -s -o /dev/null -w "%{http_code}" -X POST "$PD_API_URL" \
        -H 'Content-Type: application/json' \
        -d "$payload" | grep -q "^202$"
}

# Escape a string for safe embedding in a JSON value field.
# Uses bash substitution so actual newlines are converted to \n rather
# than being dropped by sed's line-by-line processing.
json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\t'/\\t}"
    s="${s//$'\n'/\\n}"
    printf '%s' "$s"
}

# -----------------------------------------------------------------------
# changes <count> <alertfile>
# Reads structured alert blocks from the temp file and triggers one
# PagerDuty incident summarising all changes in this cron run.
# No dedup key: each run creates a distinct incident.
# -----------------------------------------------------------------------
notify_changes() {
    local count="$1"
    local alertfile="$2"
    local detected_at
    detected_at=$(date)
    local source="${PD_SOURCE:-$(hostname)}"
    local details=""

    local device="" old_ip="" new_ip="" old_ua="" new_ua=""
    local in_regs=false in_alert=false

    while IFS= read -r line; do
        case "$line" in
            ALERT_START)
                in_alert=true
                device="" old_ip="" new_ip="" old_ua="" new_ua="" in_regs=false
                ;;
            ALERT_END)
                in_alert=false
                details="${details}Device: ${device} | IP: ${old_ip} -> ${new_ip} | UA: ${old_ua} -> ${new_ua}"$'\n'
                ;;
            REGS_START) in_regs=true ;;
            REGS_END)   in_regs=false ;;
            *)
                if [ "$in_alert" = true ] && [ "$in_regs" = false ]; then
                    case "$line" in
                        device=*)  device="${line#device=}" ;;
                        old_ip=*)  old_ip="${line#old_ip=}" ;;
                        new_ip=*)  new_ip="${line#new_ip=}" ;;
                        old_ua=*)  old_ua="${line#old_ua=}" ;;
                        new_ua=*)  new_ua="${line#new_ua=}" ;;
                    esac
                fi
                ;;
        esac
    done < "$alertfile"

    local esc_details esc_source esc_detected
    esc_details=$(json_escape "$details")
    esc_source=$(json_escape "$source")
    esc_detected=$(json_escape "$detected_at")

    local payload
    payload=$(cat <<EOF
{
    "routing_key": "${PD_ROUTING_KEY}",
    "event_action": "trigger",
    "payload": {
        "summary": "UA Monitor: ${count} Device Change(s) Detected",
        "source": "${esc_source}",
        "severity": "${PD_SEVERITY_CHANGE}",
        "custom_details": {
            "detected_at": "${esc_detected}",
            "changes": "${esc_details}"
        }
    }
}
EOF
)
    send_pagerduty "$payload"
}

# -----------------------------------------------------------------------
# new_device_digest <count> <entriesfile>
# Triggers a PagerDuty incident for new device registrations.
# -----------------------------------------------------------------------
notify_new_device_digest() {
    local count="$1"
    local entriesfile="$2"
    local detected_at
    detected_at=$(date)
    local source="${PD_SOURCE:-$(hostname)}"

    local raw_entries
    raw_entries=$(cat "$entriesfile")

    local esc_entries esc_source esc_detected
    esc_entries=$(json_escape "$raw_entries")
    esc_source=$(json_escape "$source")
    esc_detected=$(json_escape "$detected_at")

    local payload
    payload=$(cat <<EOF
{
    "routing_key": "${PD_ROUTING_KEY}",
    "event_action": "trigger",
    "payload": {
        "summary": "UA Monitor: ${count} New Device Registration(s)",
        "source": "${esc_source}",
        "severity": "${PD_SEVERITY_NEW_DEVICE}",
        "custom_details": {
            "detected_at": "${esc_detected}",
            "devices": "${esc_entries}"
        }
    }
}
EOF
)
    send_pagerduty "$payload"
}

# -----------------------------------------------------------------------
# Router
# -----------------------------------------------------------------------
case "$1" in
    changes)
        notify_changes "$2" "$3" ;;
    new_device_digest)
        notify_new_device_digest "$2" "$3" ;;
    *)
        echo "Unknown notification type: $1"
        exit 1
        ;;
esac
