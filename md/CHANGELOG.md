# Changelog - ltrace Behavioral Analysis Tools

## [2025-10-26] - Major Feature Addition

### Added
- **ltrace-full.sh** - Comprehensive ltrace wrapper with optimal flags for malware analysis
- **parse-ltrace-behavior.py** - Behavioral parser that maps calls to attack tactics and detects suspicious activities
- **demo-behavior-analysis.sh** - Interactive demonstration script
- **SUSPICIOUS category** - Added to behavior_patterns.json for flagging suspicious patterns

### Documentation Added
- **README_LTRACE.md** - Main overview and quick start guide
- **BEHAVIOR_ANALYSIS.md** - Complete behavioral analysis documentation
- **LTRACE_USAGE.md** - Technical ltrace usage reference
- **QUICK_REFERENCE.md** - Quick reference card with commands and IOCs
- **CONTAINER_USAGE.md** - Container-specific usage instructions

### Container Updates
- Updated Dockerfile to include all ltrace analysis tools
- Tools installed to `/usr/local/bin/` for easy access
- Documentation installed to `/opt/monitoring/`
- Demo script available in container
- Parser scripts support both host and container paths

### Features
1. **Behavioral Analysis**
   - Maps library calls to 8 attack tactics (MITRE ATT&CK-aligned)
   - Reconstructs 6-phase attack chain chronologically
   - Identifies 11 different reconnaissance activities
   - Detects 4 persistence mechanisms
   - Flags defense evasion techniques

2. **Attack Phase Detection**
   - Phase 1: Initial Access (SSH brute force)
   - Phase 2: Discovery (system reconnaissance)
   - Phase 3: Execution (payload deployment)
   - Phase 4: Persistence (survival mechanisms)
   - Phase 5: Privilege Escalation (elevated access)
   - Phase 6: Defense Evasion (covering tracks)

3. **IOC Extraction**
   - Automatic file system IOC identification
   - Process IOC detection
   - Network IOC flagging
   - Ready for SIEM/EDR integration

4. **Actionable Intelligence**
   - Detection rules for security tools
   - Step-by-step mitigation commands
   - Remediation procedures
   - Threat hunting queries

### Technical Details
- ltrace flags: `-s 4096 -n 4 -f -tt -T`
- Output location: `/tmp/ltrace_analysis/`
- Three-tier output: Raw, Technical, Behavioral
- Python 3 based parsers
- Supports both dynamically and statically linked analysis

### Specific to ThugLyfe Simulation
The behavioral parser specifically understands the attack simulation in `linux_commands.sh`:
- SSH brute force detection (50 attempts)
- Reconnaissance file mapping (config.dat = uname -a, etc.)
- Binary deployment tracking (svchost masquerading)
- Persistence mechanism identification (systemd, cron, .bashrc)
- Privilege escalation detection (sudoadmin user creation)
- Defense evasion flagging (script deletion, temp directories)

### Usage Examples
```bash
# In container
ltrace-full /home/app/malware_sample

# On host
./ltrace-full.sh ./malware_sample

# View results
cat /tmp/ltrace_analysis/ltrace_behavior_*.txt
```

### Files Modified
- `Dockerfile` - Added COPY commands for new tools and documentation
- `README.md` - Added section about ltrace behavioral analysis
- `ltrace-full.sh` - Updated to support multiple parser locations

### Compatibility
- Works in Docker containers
- Works on host systems
- Supports Ubuntu/Debian-based systems
- Requires Python 3.x
- Requires ltrace package

### Known Limitations
- Only analyzes dynamically linked binaries
- Pattern matching may have false positives
- Best used in combination with strace and auditd
- Requires library calls to be visible (not stripped)

### Future Enhancements
- Integration with trace-malware.sh
- JSON output format for SIEM ingestion
- Real-time analysis mode
- Additional tactic patterns
- Machine learning-based behavior classification
- Integration with MISP for IOC sharing

## Installation

### Container (Recommended)
```bash
docker-compose build
docker-compose up -d
docker exec -it linux_malware_container bash
ltrace-full /home/app/malware
```

### Host System
```bash
chmod +x ltrace-full.sh parse-ltrace-behavior.py
./ltrace-full.sh ./malware_sample
```

## Dependencies
- ltrace
- Python 3
- Standard Unix utilities (grep, awk, sed)

## Credits
Based on analysis of the ThugLyfe malware simulation (`linux_commands.sh`)
Aligned with MITRE ATT&CK framework tactics and techniques

## License
Same as parent project
