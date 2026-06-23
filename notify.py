#!/usr/bin/env python3
# /opt/ua_monitor/notify.py
#
# Notification router and provider implementations.
# Called as a module from check_ua.py — not run directly.
# Provider and credentials are read from /opt/ua_monitor/ua_monitor.conf.

import smtplib
import json
import configparser
import urllib.request
import urllib.error
from email.mime.text import MIMEText
from datetime import datetime

# -----------------------------------------------------------------------
# Configuration — read from /opt/ua_monitor/ua_monitor.conf
# -----------------------------------------------------------------------

_cfg = configparser.ConfigParser()
_cfg.read("/opt/ua_monitor/ua_monitor.conf")

def _get(section, key, fallback=''):
    return _cfg.get(section, key, fallback=fallback)

NOTIFY_PROVIDER        = _get('notify',    'provider',           'slack')

SLACK_WEBHOOK          = _get('slack',     'webhook')

EMAIL_TO               = _get('email',     'to')
EMAIL_FROM             = _get('email',     'from')

TEAMS_WEBHOOK          = _get('teams',     'webhook')

PD_ROUTING_KEY         = _get('pagerduty', 'routing_key')
PD_SOURCE              = _get('pagerduty', 'source')
PD_SEVERITY_CHANGE     = _get('pagerduty', 'severity_change', 'warning')
PD_API_URL             = "https://events.pagerduty.com/v2/enqueue"

# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------

def _http_post(url, payload, expect_status=200):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data,
        headers={'Content-Type': 'application/json'},
        method='POST'
    )
    try:
        resp = urllib.request.urlopen(req)
        return resp.status == expect_status
    except urllib.error.HTTPError as e:
        return e.code == expect_status

def _fmt_regs(active_regs):
    if not active_regs:
        return "  None found in last 60 minutes"
    lines = []
    for reg in active_regs:
        last_seen = reg.get('last_seen', '')
        if hasattr(last_seen, 'strftime'):
            last_seen = last_seen.strftime('%Y-%m-%d %H:%M:%S')
        lines.append(f"  • {reg.get('ip','')} | {reg.get('ua','')} | seen: {last_seen}")
    return "\n".join(lines)

# -----------------------------------------------------------------------
# Slack
# -----------------------------------------------------------------------

def _slack_changes(count, data):
    detected_at = data.get('detected_at', datetime.now().strftime('%c'))
    body = ""
    for change in data.get('changes', []):
        body += f"*Device:* {change['device']}\n"
        body += f"*IP:* {change['old_ip']} → {change['new_ip']}\n"
        body += f"*UA (old):* {change['old_ua']}\n"
        body += f"*UA (new):* {change['new_ua']}\n"
        regs = _fmt_regs(change.get('active_regs', []))
        body += f"*Active registrations:*\n{regs}\n"
        body += "─" * 29 + "\n"

    payload = {
        "text": f":warning: *{count} Device Change(s) Detected*",
        "attachments": [{
            "color": "danger",
            "footer": detected_at,
            "text": body,
        }]
    }
    return _http_post(SLACK_WEBHOOK, payload)


# -----------------------------------------------------------------------
# Email
# -----------------------------------------------------------------------

def _email_changes(count, data):
    detected_at = data.get('detected_at', datetime.now().strftime('%c'))
    body = f"{count} device change(s) detected at {detected_at}\n\n"
    for change in data.get('changes', []):
        body += f"Device:   {change['device']}\n"
        body += f"IP:       {change['old_ip']} -> {change['new_ip']}\n"
        body += f"UA (old): {change['old_ua']}\n"
        body += f"UA (new): {change['new_ua']}\n"
        regs = _fmt_regs(change.get('active_regs', []))
        body += f"Active registrations:\n{regs}\n"
        body += "---\n\n"

    msg = MIMEText(body)
    msg['Subject'] = f"[UA Monitor] {count} Device Change(s) Detected"
    msg['From']    = EMAIL_FROM
    msg['To']      = EMAIL_TO
    try:
        with smtplib.SMTP('localhost') as s:
            s.sendmail(EMAIL_FROM, [EMAIL_TO], msg.as_string())
        return True
    except Exception:
        return False


# -----------------------------------------------------------------------
# Microsoft Teams
# -----------------------------------------------------------------------

def _teams_changes(count, data):
    detected_at = data.get('detected_at', datetime.now().strftime('%c'))
    facts = []
    for change in data.get('changes', []):
        facts.append({
            "name":  change['device'],
            "value": f"IP: {change['old_ip']} → {change['new_ip']} | UA: {change['old_ua']} → {change['new_ua']}"
        })

    payload = {
        "@type":       "MessageCard",
        "@context":    "http://schema.org/extensions",
        "themeColor":  "FF0000",
        "summary":     f"{count} Device Change(s) Detected",
        "sections": [{
            "activityTitle":    f"⚠️ {count} Device Change(s) Detected",
            "activitySubtitle": detected_at,
            "facts":            facts,
        }]
    }
    return _http_post(TEAMS_WEBHOOK, payload)


# -----------------------------------------------------------------------
# PagerDuty
# -----------------------------------------------------------------------

def _pd_source():
    if PD_SOURCE:
        return PD_SOURCE
    import socket
    return socket.gethostname()

def _pd_changes(count, data):
    detected_at = data.get('detected_at', datetime.now().strftime('%c'))
    blocks = []
    for i, change in enumerate(data.get('changes', []), 1):
        blocks.append(
            f"[{i}] {change['device']}\n"
            f"     IP  : {change['old_ip']} -> {change['new_ip']}\n"
            f"     FROM: {change['old_ua']}\n"
            f"     TO  : {change['new_ua']}"
        )

    payload = {
        "routing_key":  PD_ROUTING_KEY,
        "event_action": "trigger",
        "payload": {
            "summary":  f"UA Monitor: {count} Device Change(s) Detected",
            "source":   _pd_source(),
            "severity": PD_SEVERITY_CHANGE,
            "custom_details": {
                "detected_at": detected_at,
                "changes":     "\n\n".join(blocks),
            }
        }
    }
    return _http_post(PD_API_URL, payload, expect_status=202)


# -----------------------------------------------------------------------
# Public interface
# -----------------------------------------------------------------------

def send(count, data):
    """
    Called by check_ua.py.
    count: int — number of changes
    data:  dict with 'changes' list and 'detected_at' string
    Returns True on success, False on failure.
    """
    handlers = {
        'slack':     _slack_changes,
        'email':     _email_changes,
        'teams':     _teams_changes,
        'pagerduty': _pd_changes,
    }

    fn = handlers.get(NOTIFY_PROVIDER)
    if not fn:
        print(f"Unknown NOTIFY_PROVIDER: {NOTIFY_PROVIDER}")
        return False

    return fn(count, data)
