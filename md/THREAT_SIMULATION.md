# Advanced Threat Actor Simulation

## Overview

`advanced_threat` is a comprehensive C program that simulates a sophisticated multi-stage cyber attack for malware analysis training and detection testing. It demonstrates realistic threat actor behaviors across the entire attack lifecycle.

## Attack Stages

### Stage 1: Reconnaissance
**Objective:** Gather system and network information

**Activities:**
- System information collection (uname)
- User and group enumeration
- Network interface discovery
- Sensitive file location
- Privilege level assessment

**IOCs Generated:**
- Access to `/etc/passwd`, `/etc/shadow`
- Network configuration queries
- SSH key searches
- Sudo capability checks

### Stage 2: Establish Foothold
**Objective:** Deploy payloads and establish persistence

**Activities:**
- Create hidden directories (`/var/tmp/.hidden_sys`)
- Deploy fake binary (`update_daemon`)
- Create systemd service (`system-update.service`)
- Install cron jobs
- Modify `.bashrc` for persistence

**IOCs Generated:**
- `/var/tmp/.hidden_sys/` directory
- `/var/tmp/.systemd-private/` directory
- `update_daemon` binary (fake ELF)
- Systemd service file
- Cron entries with `@reboot`
- Modified shell profiles

### Stage 3: Privilege Escalation
**Objective:** Attempt to gain elevated privileges

**Activities:**
- SUID binary enumeration
- Sudoers file access attempts
- Writable system path discovery
- Shadow file access attempts
- Capability enumeration

**IOCs Generated:**
- SUID binary searches
- `/etc/sudoers` access attempts
- `/etc/shadow` read attempts
- System directory write tests

### Stage 4: Data Collection
**Objective:** Collect and stage sensitive data for exfiltration

**Activities:**
- Network configuration collection
- User account enumeration
- Process listing
- Package inventory
- SSH key discovery
- Credential file searches

**Files Created:**
- `/tmp/.cache_data/network_config.txt`
- `/tmp/.cache_data/user_accounts.txt`
- `/tmp/.cache_data/processes.txt`
- `/tmp/.cache_data/packages.txt`
- `/tmp/.cache_data/manifest.txt`

**Search Patterns:**
- `*.key`, `*.pem`, `*.p12`, `*.pfx`
- `*password*`, `*credential*`
- `*.conf` files
- SSH private keys

### Stage 5: Anti-Forensics
**Objective:** Cover tracks and evade detection

**Activities:**
- File timestamp manipulation (backdating to 2023-01-01)
- Log file access attempts
- Process name masquerading (as `[kworker/0:1]`)
- Bash history clearing attempts
- Temporary file cleanup

**Techniques:**
- Timestamp stomping
- Log manipulation
- Process hiding
- History clearing
- Artifact deletion

### Stage 6: Command & Control
**Objective:** Simulate C2 communication

**Activities:**
- DNS queries to C2 domains
- HTTP beacon transmission
- Command reception simulation
- Data exfiltration preparation

**C2 Domains (Simulated):**
- `update.systemd-services.com`
- `cdn.security-updates.net`
- `api.cloud-analytics.org`

**Commands Received:**
- `COLLECT_CREDS`
- `LATERAL_MOVE`
- `EXFILTRATE_DATA`
- `MAINTAIN_PERSISTENCE`

## Usage

### Compilation
```bash
# Using Makefile
make advanced_threat

# Manual compilation
gcc -Wall -Wextra -O2 -o advanced_threat advanced_threat.c
```

### Execution
```bash
# Run the simulation
./advanced_threat

# Run with ltrace for behavioral analysis
ltrace-full ./advanced_threat

# Run with strace for system call analysis
strace -o strace.txt -ff -tt ./advanced_threat
```

### In Container
```bash
# Build container
docker-compose build

# Run container
docker-compose up -d

# Execute simulation
docker exec -it linux_malware_container /usr/local/bin/advanced_threat

# Or enter container
docker exec -it linux_malware_container bash
advanced_threat
```

## Analysis Workflow

### 1. Run Behavioral Analysis
```bash
ltrace-full ./advanced_threat
cat /tmp/ltrace_analysis/ltrace_behavior_*.txt
```

### 2. Review Generated Artifacts
```bash
# Check created directories
ls -la /var/tmp/.hidden_sys/
ls -la /var/tmp/.systemd-private/
ls -la /tmp/.cache_data/

# Review activity log
cat /var/tmp/.hidden_sys/activity.log

# Check persistence mechanisms
cat /tmp/system-update.service
cat /tmp/malware_cron
grep "update_daemon" ~/.bashrc
```

### 3. Extract IOCs
```bash
# From behavioral analysis
grep "IOC" /tmp/ltrace_analysis/ltrace_behavior_*.txt

# From activity log
cat /var/tmp/.hidden_sys/activity.log

# File system artifacts
find /var/tmp -name ".*" -type d
find /tmp -name ".*" -type d
```

### 4. Test Detection Rules
```bash
# Check for hidden directories
find /var/tmp /tmp -name ".*" -type d

# Check for suspicious systemd services
systemctl list-unit-files | grep -v "^[a-z]"

# Check for unusual cron jobs
crontab -l | grep -E "@reboot|/var/tmp|/tmp"

# Check for modified shell profiles
grep -r "update_daemon" /home/*/.bashrc /root/.bashrc 2>/dev/null
```

## MITRE ATT&CK Mapping

| Stage | Tactic | Techniques |
|-------|--------|------------|
| Reconnaissance | Discovery | T1082 (System Info), T1033 (System Owner), T1016 (Network Config), T1087 (Account Discovery) |
| Foothold | Persistence | T1543.002 (Systemd Service), T1053.003 (Cron), T1546.004 (Unix Shell Config) |
| Foothold | Execution | T1059.004 (Unix Shell), T1106 (Native API) |
| Privilege Escalation | Privilege Escalation | T1548 (Abuse Elevation Control), T1068 (Exploitation) |
| Data Collection | Collection | T1005 (Data from Local System), T1119 (Automated Collection) |
| Data Collection | Credential Access | T1552.001 (Credentials in Files), T1552.004 (Private Keys) |
| Anti-Forensics | Defense Evasion | T1070.006 (Timestomp), T1070.003 (Clear Command History), T1036 (Masquerading) |
| C2 | Command and Control | T1071.001 (Web Protocols), T1071.004 (DNS), T1573 (Encrypted Channel) |

## Detection Opportunities

### File System
```bash
# Hidden directories in /var/tmp
auditctl -w /var/tmp -p wa -k suspicious_tmp

# Systemd service creation
auditctl -w /etc/systemd/system -p wa -k systemd_persistence

# Cron modifications
auditctl -w /var/spool/cron -p wa -k cron_persistence
```

### Network
```bash
# DNS queries to suspicious domains
tcpdump -i any -n 'udp port 53' | grep -E "systemd-services|security-updates|cloud-analytics"

# Unusual outbound connections
ss -tulpn | grep -v "127.0.0.1"
```

### Process
```bash
# Processes with suspicious names
ps aux | grep -E "\[kworker\]|update_daemon"

# Processes running from /tmp or /var/tmp
lsof | grep -E "/tmp|/var/tmp"
```

### Logs
```bash
# Check for timestamp anomalies
find /var/tmp /tmp -type f -newermt "2023-01-01" ! -newermt "2023-01-02"

# Check auth.log for suspicious activity
grep -E "shadow|sudoers|SUID" /var/log/auth.log
```

## Cleanup

### Manual Cleanup
```bash
# Remove malware directories
rm -rf /var/tmp/.hidden_sys
rm -rf /var/tmp/.systemd-private
rm -rf /tmp/.cache_data

# Remove persistence mechanisms
rm -f /tmp/system-update.service
rm -f /tmp/malware_cron

# Clean shell profile
sed -i '/update_daemon/d' ~/.bashrc

# Remove binary
rm -f /var/tmp/.hidden_sys/update_daemon
```

### Automated Cleanup Script
```bash
#!/bin/bash
# cleanup_threat.sh

echo "[*] Cleaning up threat simulation artifacts..."

# Directories
rm -rf /var/tmp/.hidden_sys
rm -rf /var/tmp/.systemd-private
rm -rf /tmp/.cache_data

# Files
rm -f /tmp/system-update.service
rm -f /tmp/malware_cron

# Shell profiles
for user_home in /home/*; do
    if [ -f "$user_home/.bashrc" ]; then
        sed -i '/update_daemon/d' "$user_home/.bashrc"
    fi
done

echo "[✓] Cleanup complete"
```

## Comparison with thug_simulator

| Feature | thug_simulator | advanced_threat |
|---------|----------------|-----------------|
| Language | Binary (pre-compiled) | C source code |
| Stages | 6 (scripted) | 6 (programmatic) |
| Persistence | Systemd, cron, .bashrc | Systemd, cron, .bashrc |
| Data Collection | Shell commands | Direct file operations |
| Anti-Forensics | Script deletion | Timestamp manipulation, log clearing |
| C2 Simulation | No | Yes (DNS, HTTP beacon) |
| Logging | File-based | Comprehensive activity log |
| Customization | Limited | Full source available |

## Educational Value

This simulation is valuable for:

1. **Malware Analysts** - Practice identifying attack patterns
2. **SOC Analysts** - Test detection rules and SIEM queries
3. **Incident Responders** - Train on artifact collection
4. **Security Engineers** - Validate security controls
5. **Red Teams** - Understand defensive perspectives
6. **Blue Teams** - Develop detection capabilities

## Safety Notes

⚠️ **IMPORTANT:**
- Only run in isolated environments (containers, VMs)
- Never run on production systems
- Understand each stage before execution
- Review generated artifacts
- Clean up after analysis
- Use for educational purposes only

## Integration with Analysis Tools

### With ltrace
```bash
ltrace-full ./advanced_threat
# Generates behavioral analysis report
```

### With strace
```bash
strace -o strace.txt -ff -tt -T ./advanced_threat
# Captures system calls
```

### With auditd
```bash
# Start monitoring
auditctl -w /var/tmp -p wa -k threat_sim
auditctl -w /etc/systemd/system -p wa -k threat_sim

# Run simulation
./advanced_threat

# Review audit logs
ausearch -k threat_sim
```

### With process monitoring
```bash
# Terminal 1: Start monitoring
./start-monitoring.sh

# Terminal 2: Run simulation
./advanced_threat

# Review monitoring output
```

## Output Example

```
╔══════════════════════════════════════════════════════╗
║     ADVANCED THREAT ACTOR SIMULATION v2.0           ║
║     Multi-Stage Attack Chain Demonstration          ║
║     FOR EDUCATIONAL PURPOSES ONLY                    ║
╚══════════════════════════════════════════════════════╝

[!] WARNING: This program simulates malicious behavior
[!] WARNING: Only run in isolated analysis environments

[RECON] Starting system reconnaissance...
  [+] System: Linux 5.15.0 x86_64
  [+] Current user: analyst (UID: 1000)
  [+] Primary group: analyst (GID: 1000)
  [+] Gathering network configuration...
      IP: 172.17.0.2/16
  [+] Searching for sensitive files...
      [FOUND] /etc/passwd (readable)

[FOOTHOLD] Establishing persistence mechanisms...
  [+] Creating hidden directories...
  [+] Deploying payload binary...
      Payload deployed: /var/tmp/.hidden_sys/update_daemon (1016 bytes)
  [+] Creating systemd persistence...
  [+] Setting up cron persistence...
  [+] Attempting shell profile modification...
      Modified: /home/analyst/.bashrc

... [additional stages] ...

========================================
  THREAT SIMULATION COMPLETE
========================================

Artifacts Created:
  - /var/tmp/.hidden_sys (malware directory)
  - /var/tmp/.systemd-private (persistence directory)
  - /tmp/.cache_data (exfiltration staging)
  - /var/tmp/.hidden_sys/activity.log (activity log)
  - Modified: ~/.bashrc

IOCs Generated:
  - Binary: /var/tmp/.hidden_sys/update_daemon
  - Service: system-update.service
  - Cron job: malware_cron
  - C2 domains: update.systemd-services.com

[*] Analysis tip: Run 'ltrace-full ./advanced_threat' for detailed behavioral analysis
```

## Further Reading

- `BEHAVIOR_ANALYSIS.md` - Behavioral analysis documentation
- `QUICK_REFERENCE.md` - Quick reference for analysis
- `CONTAINER_USAGE.md` - Container-specific instructions
- MITRE ATT&CK Framework - https://attack.mitre.org/
