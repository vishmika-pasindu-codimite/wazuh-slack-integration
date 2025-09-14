# Copyright (C) 2025, Pasindu-Vishmika-Codimite.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

import json
import os
import sys
import re

# Exit error codes
ERR_NO_REQUEST_MODULE = 1
ERR_BAD_ARGUMENTS = 2
ERR_FILE_NOT_FOUND = 6
ERR_INVALID_JSON = 7

try:
    import requests
except Exception:
    print("No module 'requests' found. Install: pip install requests")
    sys.exit(ERR_NO_REQUEST_MODULE)

# ossec.conf configuration structure
#  <integration>
#      <name>custom-slack_forti_sec</name>
#      <hook_url>https://hooks.slack.com/services/XXXXXX_CHANGE_YOUR_WEBHOOK_URL_HERE_XXXXXXXX</hook_url>
#      <alert_format>json</alert_format>
#      <rule_id>2501,81620,81622</rule_id><!-- SysEvent, Virus, VPN  -->
#  </integration>

# Global vars
debug_enabled = False
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
json_alert = {}
json_options = {}

# Log path
LOG_FILE = f'{pwd}/logs/integrations.log'

# Constants
ALERT_INDEX = 1
WEBHOOK_INDEX = 3


def main(args):
    global debug_enabled
    try:
        # Read arguments
        bad_arguments: bool = False
        if len(args) >= 4:
            msg = '{0} {1} {2} {3} {4}'.format(
                args[1], args[2], args[3], args[4] if len(args) > 4 else '', args[5] if len(args) > 5 else ''
            )
            debug_enabled = len(args) > 4 and args[4] == 'debug'
        else:
            msg = '# ERROR: Wrong arguments'
            bad_arguments = True

        # Logging the call
        with open(LOG_FILE, 'a') as f:
            f.write(msg + '\n')

        if bad_arguments:
            debug('# ERROR: Exiting, bad arguments. Inputted: %s' % args)
            sys.exit(ERR_BAD_ARGUMENTS)

        # Core function
        process_args(args)

    except Exception as e:
        debug(str(e))
        raise


def process_args(args) -> None:
    """This is the core function, creates a message with all valid fields
    and overwrite or add with the optional fields

    Parameters
    ----------
    args : list[str]
        The argument list from main call
    """
    debug('# Running Slack script')

    # Read args
    alert_file_location: str = args[ALERT_INDEX]
    webhook: str = args[WEBHOOK_INDEX]
    options_file_location: str = ''

    # Look for options file location
    for idx in range(4, len(args)):
        if args[idx][-7:] == 'options':
            options_file_location = args[idx]
            break

    # Load options. Parse JSON object.
    json_options = get_json_options(options_file_location)
    debug(f"# Opening options file at '{options_file_location}' with '{json_options}'")

    # Load alert. Parse JSON object.
    json_alert = get_json_alert(alert_file_location)
    debug(f"# Opening alert file at '{alert_file_location}' with '{json_alert}'")

    debug('# Generating message')
    msg: any = generate_msg(json_alert, json_options)

    if not len(msg):
        debug('# ERROR: Empty message')
        raise Exception

    debug(f'# Sending message {msg} to Slack server')
    send_msg(msg, webhook)


def debug(msg: str) -> None:
    """Log the message in the log file with the timestamp, if debug flag
    is enabled

    Parameters
    ----------
    msg : str
        The message to be logged.
    """
    if debug_enabled:
        print(msg)
        with open(LOG_FILE, 'a') as f:
            f.write(msg + '\n')


def generate_msg(alert: any, options: any) -> any:
    """Generate a Block Kit JSON message for Slack"""

    rule_id = int(alert['rule']['id'])
    blocks = []

    if rule_id == 2501:
        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": "⚠️ FortiGate System Event", "emoji": True}},
            {"type": "section", "fields": [
                {"type": "mrkdwn", "text": f"*Message:*\n{alert['rule']['description']}"},
                {"type": "mrkdwn", "text": f"*Fired Times:*\n{alert['rule'].get('firedtimes', 'N/A')}"}
            ]},
            {"type": "section", "fields": [
                {"type": "mrkdwn", "text": f"*Rule ID from Wazuh:*\n{alert['rule']['id']}"},
                {"type": "mrkdwn", "text": f"*Timestamp:*\n{alert.get('timestamp', 'N/A')}"}
            ]}
        ]
    elif rule_id == 81620:
         blocks = [
                {"type": "header", "text": {"type": "plain_text", "text": ":microbe: Security Event: Virus Detected & Blocked", "emoji": True}},
                {"type": "section", "fields": [
                    {"type": "mrkdwn", "text": f"*Message:*\n{alert['data']['msg']}"},
                    {"type": "mrkdwn", "text": f"*Device ID:*\n{alert['data'].get('devid', 'N/A')}"}
                ]},
                {"type": "section", "fields": [
                    {"type": "mrkdwn", "text": f"*Log Time:*\n{alert['data'].get('time', 'N/A')}"},
                    {"type": "mrkdwn", "text": f"*Timestamp:*\n{alert.get('timestamp', 'N/A')}"}
                ]},
                {"type": "section", "fields": [
                    {"type": "mrkdwn", "text": f"*Source IP:*\n{alert['data'].get('srcip', 'N/A')}"},
                    {"type": "mrkdwn", "text": f"*Destination IP:*\n{alert['data'].get('dstip', 'N/A')}"}
                ]},
                {"type": "section", "fields": [
                    {"type": "mrkdwn", "text": f"*Service:*\n{alert['data'].get('service', 'N/A')}"},
                    {"type": "mrkdwn", "text": f"*Virus Type:*\n{alert['data'].get('virus', 'N/A')}"}
                ]},
                {"type": "section", "fields": [
                    {"type": "mrkdwn", "text": f"*Log ID:*\n{alert['data'].get('logid', 'N/A')}"},
                    {"type": "mrkdwn", "text": f"*Rule ID from Wazuh:*\n{alert['rule']['id']}"}
                ]}
            ]
    elif rule_id == 81622:
        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": "🔒 FortiGate VPN Event", "emoji": True}},
            {"type": "section", "fields": [
                {"type": "mrkdwn", "text": f"*Message:*\n{alert['data']['msg']}"},
                {"type": "mrkdwn", "text": f"*Device ID:*\n{alert['data'].get('devid', 'N/A')}"}
            ]},
            {"type": "section", "fields": [
                {"type": "mrkdwn", "text": f"*Time:*\n{alert['data'].get('time', 'N/A')}"},
                {"type": "mrkdwn", "text": f"*Timestamp:*\n{alert.get('timestamp', 'N/A')}"}
            ]},
            {"type": "section", "fields": [
                {"type": "mrkdwn", "text": f"*Remote IP:*\n{alert['data'].get('remip', 'N/A')}"},
                {"type": "mrkdwn", "text": f"*Tunnel ID:*\n{alert['data'].get('tunnelid', 'N/A')}"}
                
            ]},
            {"type": "section", "fields": [
                {"type": "mrkdwn", "text": f"*Log ID:*\n{alert['data'].get('logid', 'N/A')}"},
                {"type": "mrkdwn", "text": f"*Rule ID from Wazuh:*\n{alert['rule']['id']}"}
            ]}
        ]

    msg = {"blocks": blocks}
    return json.dumps(msg)


def send_msg(msg: str, url: str) -> None:
    """Send the message to the API

    Parameters
    ----------
    msg : str
        JSON message.
    url: str
        URL of the API.
    """
    headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8'}
    res = requests.post(url, data=msg, headers=headers, timeout=10)
    debug('# Response received: %s' % res.json)


def get_json_alert(file_location: str) -> any:
    """Read JSON alert object from file

    Parameters
    ----------
    file_location : str
        Path to the JSON file location.

    Returns
    -------
    dict: any
        The JSON object read it.

    Raises
    ------
    FileNotFoundError
        If no JSON file is found.
    JSONDecodeError
        If no valid JSON file are used
    """
    try:
        with open(file_location) as alert_file:
            return json.load(alert_file)
    except FileNotFoundError:
        debug("# JSON file for alert %s doesn't exist" % file_location)
        sys.exit(ERR_FILE_NOT_FOUND)
    except json.decoder.JSONDecodeError as e:
        debug('Failed getting JSON alert. Error: %s' % e)
        sys.exit(ERR_INVALID_JSON)


def get_json_options(file_location: str) -> any:
    """Read JSON options object from file

    Parameters
    ----------
    file_location : str
        Path to the JSON file location.

    Returns
    -------
    dict: any
        The JSON object read it.

    Raises
    ------
    JSONDecodeError
        If no valid JSON file are used
    """
    try:
        with open(file_location) as options_file:
            return json.load(options_file)
    except FileNotFoundError:
        debug("# JSON file for options %s doesn't exist" % file_location)
    except BaseException as e:
        debug('Failed getting JSON options. Error: %s' % e)
        sys.exit(ERR_INVALID_JSON)


if __name__ == '__main__':
    main(sys.argv)
