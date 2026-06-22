#!/bin/bash
# /opt/ua_monitor/notify.sh
# Notification router — set NOTIFY_PROVIDER to your platform

NOTIFY_PROVIDER="slack"   # slack | email | teams | pagerduty

NOTIFY_DIR="/opt/ua_monitor"

case "$NOTIFY_PROVIDER" in
    slack)
        "$NOTIFY_DIR/notify_slack.sh" "$@" ;;
    email)
        "$NOTIFY_DIR/notify_email.sh" "$@" ;;
    teams)
        "$NOTIFY_DIR/notify_teams.sh" "$@" ;;
    pagerduty)
        "$NOTIFY_DIR/notify_pagerduty.sh" "$@" ;;
    *)
        echo "Unknown NOTIFY_PROVIDER: $NOTIFY_PROVIDER" ;;
esac
