# Linux ISO 2700x Baseline Auditor

A lightweight, read-only Linux auditing script designed to quickly identify configuration gaps aligned with ISO 27001 / 27017 / 27018 security controls.

This tool **does not change anything on the system** — it only inspects, reports, and recommends fixes.

## 🔍 Features

- SSH hardening checks (root login, password auth)
- Public-facing ports discovery (ss / netstat)
- Routing table validation
- Auditd detection and rule inspection
- Syslog / journald logging checks
- File permissions audit (world-writable files, home dir permissions)
- Time sync detection (systemd-timesyncd / chronyd / ntpd)
- Automatic update configuration check
- LUKS encryption detection
- CSV export of all findings
- Summarized hardening recommendations at the end

## 📄 Output

The script generates:
- **Readable terminal output**
- **A structured CSV file** containing:
  - category  
  - item  
  - status  
  - severity  
  - detail  
  - recommendation  

Example command:
```bash
sudo ./iso_audit.sh audit.csv
```

## 🚀 Usage

```bash
chmod +x iso_audit.sh
sudo ./iso_audit.sh
```

Or specify your own CSV name:

```bash
sudo ./iso_audit.sh /tmp/server_audit.csv
```

## 📁 What This Script Does *Not* Do

- Does **not** modify system configuration  
- Does **not** change firewall rules  
- Does **not** enforce password policies  
- Does **not** add/remove users or services  

Kept intentionally safe and read‑only.

## 📦 Recommended Use Cases

- Baseline compliance checks  
- DevOps / SecOps server onboarding  
- Cloud VM hygiene verification  
- ISO27001 internal audits  
- Hardening validation in production or staging  
