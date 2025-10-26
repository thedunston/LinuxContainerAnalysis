# Behavioral Analysis with ltrace

## Overview
The behavioral analysis parser maps low-level library calls to high-level malicious behaviors and attack tactics, providing insight into what the malware is actually trying to accomplish.

## What It Analyzes

Based on the simulated attack in `linux_commands.sh`, the parser identifies:

### Attack Phases
1. **Initial Access** - SSH brute force attack
2. **Discovery** - System reconnaissance
3. **Execution** - Payload deployment
4. **Persistence** - Survival mechanisms
5. **Privilege Escalation** - Gaining higher privileges
6. **Defense Evasion** - Covering tracks

### Tactics Detected

#### 1. DISCOVERY (System Reconnaissance)
Maps library calls to reconnaissance activities:
- **config.dat** → System information (uname -a)
- **network.dat** → Network configuration (ip a show)
- **data.txt** → DNS configuration (resolv.conf)
- **connections.dat** → Active connections (ss -anop)
- **accounts.dat** → User accounts (/etc/passwd)
- **userlist.dat** → Password hashes (/etc/shadow)
- **services.dat** → Running services (systemctl)
- **cronjobs.dat** → Scheduled tasks (crontab)
- **packages.dat** → Installed software (dpkg)
- **autorun.dat** → Startup scripts (rc.local)
- **startup.dat** → User init files (.bashrc)

#### 2. PERSISTENCE
Identifies persistence mechanisms:
- Systemd service creation (`thuglyfe.service`)
- Cron job installation
- Shell profile modification (`.bashrc`)
- Reboot persistence (`@reboot`)

#### 3. PRIVILEGE ESCALATION
Detects privilege escalation attempts:
- New user account creation (`useradd`)
- Privileged user creation (`sudoadmin`)
- Adding user to sudo group
- Shadow file access (requires root)

#### 4. DEFENSE EVASION
Identifies evasion techniques:
- Deleting dropper scripts
- Masquerading as system updates
- Using Windows service names on Linux (`svchost`)
- Operating in temporary directories

#### 5. EXECUTION
Tracks code execution:
- Process creation (`fork`)
- Shell command execution
- Setting execute permissions
- Binary deployment

#### 6. CREDENTIAL ACCESS
Monitors credential theft:
- Password file access
- Shadow file access
- Hardcoded passwords
- Password-related operations

#### 7. INITIAL ACCESS
Identifies entry vectors:
- SSH brute force patterns
- Failed login attempts
- Successful authentication
- Auth log manipulation

#### 8. IMPACT
System modifications:
- Binary deployment (ELF files)
- Malware directory creation
- Fake update directories

## Usage

### Run Complete Analysis
```bash
./ltrace-full.sh ./thug_simulator
```

This produces three outputs:
1. **Raw ltrace output** - Complete trace data
2. **Technical analysis** - Categorized function calls
3. **Behavioral analysis** - Attack tactics and techniques

### View Behavioral Report
```bash
cat /tmp/ltrace_analysis/ltrace_behavior_*.txt
```

### Search for Specific Tactics
```bash
# View attack phases
grep "Phase" /tmp/ltrace_analysis/ltrace_behavior_*.txt

# View persistence mechanisms
grep -A 10 "PERSISTENCE" /tmp/ltrace_analysis/ltrace_behavior_*.txt

# View IOCs
grep -A 20 "INDICATORS OF COMPROMISE" /tmp/ltrace_analysis/ltrace_behavior_*.txt
```

### Run Behavioral Parser Only
```bash
python3 parse-ltrace-behavior.py ltrace_raw_output.txt my_behavior_report.txt
```

## Report Structure

### 1. Executive Summary
- Total behavioral indicators
- Tactics employed
- High-level overview

### 2. Tactics Overview
- List of all tactics with indicator counts
- Quick reference for what was detected

### 3. Attack Chain Analysis
- Chronological narrative of the attack
- Organized by phases
- Shows progression from initial access to impact

### 4. Detailed Behavioral Analysis
- Per-tactic breakdown
- Specific techniques used
- Evidence from library calls
- Timestamps and function details

### 5. File Operations Summary
- Files created
- Files written/modified
- Files made executable
- Files deleted

### 6. Indicators of Compromise (IOCs)
- File system IOCs
- Process IOCs
- Network IOCs
- Ready for threat hunting

### 7. Detection and Mitigation
- Detection rules for SIEM/EDR
- Step-by-step mitigation instructions
- Remediation commands

## Example Output Snippets

### Attack Chain
```
### Phase 1: Initial Access
Attacker gains initial foothold via SSH brute force
--------------------------------------------------------------------------------

▸ SSH Brute Force Attack
  Occurrences: 50
  Example 1: [16:10:06] fprintf(...sshd[10001]: Failed password...)
  Example 2: [16:10:06] fprintf(...sshd[10002]: Failed password...)
  Example 3: [16:10:06] fprintf(...sshd[10023]: Accepted password...)
```

### Behavioral Indicators
```
### PERSISTENCE: Establish Persistence Mechanisms
--------------------------------------------------------------------------------
Total Indicators: 8

▸ Systemd Service Creation
  Count: 3
  Evidence:
    [16:10:07] fopen("/etc/systemd/system/thuglyfe.service", "wb") = 0x...
    [16:10:07] fprintf(...[Unit]...) = 42
    [16:10:07] fprintf(...ExecStart=/var/tmp/SecurityUpdate/svchost...) = 56
```

### IOCs
```
### File System IOCs:
  • /var/tmp/thuglyfe/thuglyfe.log
  • /var/tmp/SecurityUpdate/svchost
  • /var/tmp/asefa.sh
  • /etc/systemd/system/thuglyfe.service
  • /var/tmp/config.dat
  • /var/tmp/accounts.dat
  • /var/tmp/userlist.dat
```

## Mapping to MITRE ATT&CK

The behavioral analysis aligns with MITRE ATT&CK framework:

| Our Tactic | MITRE ATT&CK Tactic | Techniques |
|------------|---------------------|------------|
| INITIAL_ACCESS | Initial Access | T1078 (Valid Accounts), T1110 (Brute Force) |
| DISCOVERY | Discovery | T1082 (System Info), T1033 (System Owner), T1016 (Network Config) |
| PERSISTENCE | Persistence | T1543.002 (Systemd Service), T1053.003 (Cron), T1546.004 (.bashrc) |
| PRIVILEGE_ESCALATION | Privilege Escalation | T1078.003 (Local Accounts), T1548 (Abuse Elevation Control) |
| DEFENSE_EVASION | Defense Evasion | T1070.004 (File Deletion), T1036 (Masquerading) |
| EXECUTION | Execution | T1059.004 (Unix Shell), T1106 (Native API) |
| CREDENTIAL_ACCESS | Credential Access | T1003.008 (/etc/passwd and /etc/shadow) |

## Integration with Other Tools

### Combine with strace
```bash
# Terminal 1: ltrace behavioral analysis
./ltrace-full.sh ./malware

# Terminal 2: strace system call analysis
strace -o strace.txt -ff -tt ./malware

# Compare behaviors across both traces
```

### Use in trace-malware.sh
The behavioral parser can be integrated into your existing `trace-malware.sh` script for comprehensive analysis.

### Export to SIEM
```bash
# Extract IOCs for SIEM ingestion
grep "IOC" ltrace_behavior_*.txt | awk '{print $2}' > iocs.txt
```

## Tips for Analysis

1. **Start with Executive Summary** - Get the big picture first
2. **Review Attack Chain** - Understand the progression
3. **Focus on High-Risk Tactics** - Privilege escalation and persistence
4. **Extract IOCs** - Use for threat hunting
5. **Compare Multiple Samples** - Identify common patterns

## Customization

You can extend the behavioral patterns by editing `parse-ltrace-behavior.py`:

```python
self.behaviors = {
    'YOUR_TACTIC': {
        'description': 'Your description',
        'indicators': [
            (r'pattern', 'Description of behavior'),
            # Add more patterns
        ]
    }
}
```

## Limitations

- Only analyzes library calls (not system calls)
- Requires dynamically linked binaries
- Pattern matching may have false positives
- Best used in combination with other tools (strace, auditd)

## Next Steps

After behavioral analysis:
1. Review the attack chain narrative
2. Extract and hunt for IOCs in your environment
3. Implement detection rules
4. Execute mitigation steps
5. Update security controls to prevent similar attacks
