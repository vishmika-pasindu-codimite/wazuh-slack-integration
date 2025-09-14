# Wazuh Slack Integration

This repository contains custom integrations for sending Wazuh alerts to Slack, specifically designed for FortiGate security events.

## 🚀 Quick Installation (Recommended)

### All-in-One ACS Integration

For the best experience, use the **All-in-One ACS (Authentication, Configuration, Security)** integration that handles all FortiGate events in a single, comprehensive solution.

#### 1. Navigate to the integrations directory

```bash
cd /var/ossec/integrations/
```

#### 2. Download the All-in-One ACS files

```bash
curl -L -o custom-slack_forti_acs.py https://raw.githubusercontent.com/vishmika-pasindu-codimite/wazuh-slack-integration/main/custom-slack_forti_acs.py
curl -L -o custom-slack_forti_acs https://raw.githubusercontent.com/vishmika-pasindu-codimite/wazuh-slack-integration/main/custom-slack_forti_acs
```

#### 3. Set proper permissions and ownership

```bash
chmod 750 custom-slack_forti_acs.py
chmod 750 custom-slack_forti_acs
chown root:wazuh custom-slack_forti_acs.py
chown root:wazuh custom-slack_forti_acs
```

#### 4. Configure in ossec.conf

Add the following integration block to your `/var/ossec/etc/ossec.conf`:

```xml
<integration>
    <name>custom-slack_forti_acs</name>
    <hook_url>https://hooks.slack.com/services/YOUR_WEBHOOK_URL_HERE</hook_url>
    <alert_format>json</alert_format>
    <rule_id>81606,81616,81626,81612,2501,81620,81622</rule_id><!-- FailedLogin, Logout, Login, ConfigChange, SysEvent, Virus, VPN -->
</integration>
```

## 📋 Alternative Installation (Individual Components)

If you prefer to use separate integrations for different event types, you can install the individual components:

### 1. Navigate to the integrations directory

```bash
cd /var/ossec/integrations/
```

### 2. Download individual integration files

Download the Python scripts:

```bash
curl -L -o custom-slack_forti_auth.py https://raw.githubusercontent.com/vishmika-pasindu-codimite/wazuh-slack-integration/main/seperated/custom-slack_forti_auth.py
curl -L -o custom-slack_forti_conf.py https://raw.githubusercontent.com/vishmika-pasindu-codimite/wazuh-slack-integration/main/seperated/custom-slack_forti_conf.py
curl -L -o custom-slack_forti_sec.py https://raw.githubusercontent.com/vishmika-pasindu-codimite/wazuh-slack-integration/main/seperated/custom-slack_forti_sec.py
```

Download the configuration files:

```bash
curl -L -o custom-slack_forti_auth https://raw.githubusercontent.com/vishmika-pasindu-codimite/wazuh-slack-integration/main/seperated/custom-slack_forti_auth
curl -L -o custom-slack_forti_conf https://raw.githubusercontent.com/vishmika-pasindu-codimite/wazuh-slack-integration/main/seperated/custom-slack_forti_conf
curl -L -o custom-slack_forti_sec https://raw.githubusercontent.com/vishmika-pasindu-codimite/wazuh-slack-integration/main/seperated/custom-slack_forti_sec
```

### 3. Set proper permissions and ownership

Set permissions for Python scripts:

```bash
chmod 750 custom-slack_forti_auth.py
chmod 750 custom-slack_forti_conf.py
chmod 750 custom-slack_forti_sec.py
```

Set permissions for configuration files:

```bash
chmod 750 custom-slack_forti_auth
chmod 750 custom-slack_forti_conf
chmod 750 custom-slack_forti_sec
```

Set ownership for all files:

```bash
chown root:wazuh custom-slack_forti_auth.py
chown root:wazuh custom-slack_forti_conf.py
chown root:wazuh custom-slack_forti_sec.py
chown root:wazuh custom-slack_forti_auth
chown root:wazuh custom-slack_forti_conf
chown root:wazuh custom-slack_forti_sec
```

## 🔄 Final Steps (Required for Both Methods)

### Restart Wazuh Manager

```bash
systemctl restart wazuh-manager
```

or

```bash
/var/ossec/bin/wazuh-control restart
```

### Verify Integration (Optional)

Check the Wazuh logs for Slack integration activity:

```bash
cat /var/ossec/logs/ossec.log | grep -i "slack"
```

## 📁 Files Description

### All-in-One ACS (Recommended)

- `custom-slack_forti_acs.py` & `custom-slack_forti_acs` - **Complete integration handling all FortiGate events:**
  - 🔐 Authentication events (login failures, successful logins, logouts)
  - ⚙️ Configuration changes
  - 🛡️ Security events (virus detection, VPN events, system events)

### Individual Components (Optional)

- `custom-slack_forti_auth.py` & `custom-slack_forti_auth` - Integration for FortiGate authentication events only
- `custom-slack_forti_conf.py` & `custom-slack_forti_conf` - Integration for FortiGate configuration events only
- `custom-slack_forti_sec.py` & `custom-slack_forti_sec` - Integration for FortiGate security events only

## 🎯 Supported FortiGate Events

The integrations support the following Wazuh rule IDs for FortiGate events:

- **81606** - Failed Login attempts
- **81616** - User logout events
- **81626** - Successful login events
- **81612** - Configuration changes
- **2501** - System events
- **81620** - Virus detection and blocking
- **81622** - VPN-related events

## 🔧 Configuration

Replace `YOUR_WEBHOOK_URL_HERE` in the ossec.conf configuration with your actual Slack webhook URL. You can create a webhook URL by:

1. Going to your Slack workspace
2. Navigate to Apps → Incoming Webhooks
3. Create a new webhook for your desired channel
4. Copy the webhook URL

## 📝 License

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License (version 2) as published by the FSF - Free Software Foundation.

Copyright (C) 2025, Pasindu-Vishmika-Codimite.
