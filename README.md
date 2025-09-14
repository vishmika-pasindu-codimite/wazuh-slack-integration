# Wazuh Slack Integration

This repository contains custom integrations for sending Wazuh alerts to Slack, specifically designed for FortiGate security events.

## Installation

To install these integrations on your Wazuh server, follow these steps:

### 1. Navigate to the integrations directory

```bash
cd /var/ossec/integrations/
```

### 2. Download the integration files

Download the Python scripts:

```bash
curl -L -o custom-slack_forti_auth.py https://raw.githubusercontent.com/vishmika-pasindu-codimite/wazuh-slack-integration/main/custom-slack_forti_auth.py
curl -L -o custom-slack_forti_conf.py https://raw.githubusercontent.com/vishmika-pasindu-codimite/wazuh-slack-integration/main/custom-slack_forti_conf.py
curl -L -o custom-slack_forti_sec.py https://raw.githubusercontent.com/vishmika-pasindu-codimite/wazuh-slack-integration/main/custom-slack_forti_sec.py
```

Download the configuration files:

```bash
curl -L -o custom-slack_forti_auth https://raw.githubusercontent.com/vishmika-pasindu-codimite/wazuh-slack-integration/main/custom-slack_forti_auth
curl -L -o custom-slack_forti_conf https://raw.githubusercontent.com/vishmika-pasindu-codimite/wazuh-slack-integration/main/custom-slack_forti_conf
curl -L -o custom-slack_forti_sec https://raw.githubusercontent.com/vishmika-pasindu-codimite/wazuh-slack-integration/main/custom-slack_forti_sec
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

### 4. Restart Wazuh Manager

```bash
systemctl restart wazuh-manager
```
or 
```bash
/var/ossec/bin/wazuh-control restart
```

### 5. Verify integration (Optional)

Check the Wazuh logs for Slack integration activity:

```bash
cat /var/ossec/logs/ossec.log | grep -i "slack"
```

## Files Description

- `custom-slack_forti_auth.py` & `custom-slack_forti_auth` - Integration for FortiGate authentication events
- `custom-slack_forti_conf.py` & `custom-slack_forti_conf` - Integration for FortiGate configuration events  
- `custom-slack_forti_sec.py` & `custom-slack_forti_sec` - Integration for FortiGate security events

Each integration consists of a Python script that handles the alert processing and a configuration file that defines the integration parameters.