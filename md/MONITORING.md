# Malware Analysis Monitoring Guide

This container includes **Sysmon for Linux** and **auditd** for comprehensive malware behavior monitoring.

## Monitoring Components

### 1. Sysmon for Linux
- **Configuration**: `/etc/sysmon/sysmon-config.xml`
- **Logs**: `/var/log/syslog` (filter with `grep sysmon`)
- **Monitors**:
  - Process creation (especially from `/tmp`, `/var/tmp`, `/dev/shm`)
  - Network connections
  - File creation in suspicious locations
  - Commands containing: wget, curl, nc, base64, chmod +x, etc.

### 2. Auditd
- **Configuration**: `/etc/audit/rules.d/malware.rules`
- **Logs**: `/var/log/audit/audit.log`
- **Monitors**:
  - Execution from temporary directories
  - Persistence mechanisms (systemd, cron)
  - SSH access and configuration changes
  - Network configuration modifications
  - User/group modifications
  - Kernel module loading
  - File deletion
  - Process execution
  - Network activity
  - Privilege escalation attempts

## Usage

### Starting the Container
```bash
./linux_malware_analysis_container.sh <malware_sample>
```

The monitoring services will start automatically.

### Viewing Logs

#### Sysmon Logs
```bash
# View all Sysmon events
grep sysmon /var/log/syslog

# View process creation events
grep "ProcessCreate" /var/log/syslog

# View network connections
grep "NetworkConnect" /var/log/syslog

# View file creation
grep "FileCreate" /var/log/syslog
```

#### Auditd Logs
```bash
# Search by key (tag)
ausearch -k malware_execution
ausearch -k persistence
ausearch -k network_activity
ausearch -k privilege_escalation

# Search by time
ausearch -ts today
ausearch -ts recent

# Search for specific file
ausearch -f /tmp/

# View all audit rules
auditctl -l

# Real-time monitoring
tail -f /var/log/audit/audit.log
```

### Common Analysis Workflow

1. **Start the container with malware sample**:
   ```bash
   ./linux_malware_analysis_container.sh suspicious_binary
   ```

2. **Execute the malware** (monitoring is already running):
   ```bash
   ./suspicious_binary
   ```

3. **Review Sysmon logs** for high-level behavior:
   ```bash
   grep sysmon /var/log/syslog | tail -50
   ```

4. **Review auditd logs** for detailed syscall activity:
   ```bash
   ausearch -k malware_execution
   ausearch -k persistence
   ausearch -k network_activity
   ```

5. **Check for specific indicators**:
   ```bash
   # Files created in /tmp or /var/tmp
   ausearch -k malware_execution | grep -E "/tmp|/var/tmp"
   
   # Network connections
   ausearch -k network_activity
   
   # Persistence mechanisms
   ausearch -k persistence
   ```

## Customizing Rules

### Sysmon Configuration
Edit `/etc/sysmon/sysmon-config.xml` and reload:
```bash
/opt/sysmon/sysmon -c /etc/sysmon/sysmon-config.xml
```

### Auditd Rules
Edit `/etc/audit/rules.d/malware.rules` and reload:
```bash
auditctl -R /etc/audit/rules.d/malware.rules
```

## Exporting Logs

Before exiting the container, copy logs to the host:
```bash
# From inside the container
cp /var/log/syslog /home/app/syslog.txt
cp /var/log/audit/audit.log /home/app/audit.log

# Or from the host (in another terminal)
podman cp <container_name>:/var/log/syslog ./syslog.txt
podman cp <container_name>:/var/log/audit/audit.log ./audit.log
```

## Troubleshooting

### Sysmon not running
```bash
# Check if Sysmon is installed
ls -la /opt/sysmon/sysmon

# Manually start Sysmon
/opt/sysmon/sysmon -accepteula -i /etc/sysmon/sysmon-config.xml

# Check Sysmon status
pgrep -a sysmon
```

### Auditd not running
```bash
# Start auditd
service auditd start

# Check status
service auditd status

# Load rules manually
auditctl -R /etc/audit/rules.d/malware.rules
```

## Key Indicators to Look For

1. **Process Execution**: Unusual processes from `/tmp`, `/var/tmp`, `/dev/shm`
2. **Persistence**: Files created in `/etc/systemd/system/`, `/etc/cron.d/`
3. **Network Activity**: Outbound connections, especially from suspicious processes
4. **File Operations**: Creation of hidden files, scripts, binaries
5. **Privilege Escalation**: setuid/setgid calls, sudo usage
6. **SSH Activity**: Changes to `.ssh/` directories, `authorized_keys`
