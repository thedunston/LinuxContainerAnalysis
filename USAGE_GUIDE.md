# Linux Malware Analysis Container - User Guide

## Table of Contents
1. [Quick Start](#quick-start)
2. [Overview](#overview)
3. [Prerequisites](#prerequisites)
4. [Environment Setup with Podman](#environment-setup-with-podman)
5. [Running a Malware Hunt](#running-a-malware-hunt)
6. [Analysis Tools](#analysis-tools)
7. [Understanding the Output](#understanding-the-output)
8. [Advanced Usage](#advanced-usage)
9. [Troubleshooting](#troubleshooting)

---

## Quick Start

Here's a complete workflow from setup to extracting analysis results:

```bash
# 1. Build the container
cd /home/thedunston/linux_malware_analysis_container
podman build -t linux-malware-analysis .

# 2. Compile the test program
cd samples
make

# 3. Run analysis using the automated script
cd ..
./linux_malware_analysis_container.sh samples/test_malware_simulator

# 4. Inside the container, run full analysis
ltrace-full /home/app/test_malware_simulator

# 5. View the behavioral report (inside container)
cat /tmp/ltrace_analysis/ltrace_behavior_*.txt

# 6. Copy analysis results to host (open a new terminal on host)
# Get the container name
podman ps -a | grep linux_malware_analysis

# Copy the entire analysis folder to host
podman cp <container_name>:/tmp/ltrace_analysis ./analysis_results

# Alternative: Copy specific files
podman cp <container_name>:/tmp/ltrace_analysis/ltrace_behavior_*.txt ./
podman cp <container_name>:/tmp/ltrace_analysis/ltrace_raw_*.txt ./

# 7. Exit container and view results on host
exit
cat ./analysis_results/ltrace_behavior_*.txt
```

**Note**: The automated script (`linux_malware_analysis_container.sh`) creates a container with a timestamped name like `linux-malware-analysis_1698508800`. Use `podman ps -a` to find the exact name.

---

## Overview

The Linux Malware Analysis Container is a secure, isolated environment for analyzing potentially malicious Linux binaries. It uses behavioral analysis techniques to identify malicious patterns by tracing library and system calls, mapping them to attack tactics and techniques.

### Key Features
- **Isolated Analysis**: Network-isolated container prevents malware from communicating externally
- **Behavioral Monitoring**: Real-time file system monitoring with inotify
- **Library Call Tracing**: Full ltrace analysis with comprehensive argument capture
- **System Call Tracing**: strace integration for low-level system call analysis
- **Pattern Matching**: Automated detection of malicious behaviors using configurable patterns
- **GTFOBins Detection**: Identifies potential privilege escalation and exploitation techniques
- **Attack Chain Mapping**: Maps detected behaviors to MITRE ATT&CK-style tactics

---

## Prerequisites

### Required Software
- **Podman** (version 3.0 or higher)
- **Python 3** (for local analysis)
- **Bash** (version 4.0 or higher)

### Install Podman

**On Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install -y podman
```

**On Fedora/RHEL:**
```bash
sudo dnf install -y podman
```

**On macOS:**
```bash
brew install podman
podman machine init
podman machine start
```

### Verify Installation
```bash
podman --version
```

---

## Environment Setup with Podman

### 1. Clone or Navigate to the Project Directory
```bash
cd /home/thedunston/linux_malware_analysis_container
```

### 2. Understand the Directory Structure
```
linux_malware_analysis_container/
├── Dockerfile                      # Container image definition
├── docker-compose.yml              # Docker Compose configuration
├── behavior_patterns.json          # Behavioral pattern definitions
├── parse-ltrace-behavior.py        # Behavioral analysis parser
├── ltrace-full.sh                  # Full ltrace wrapper script
├── trace-malware.sh                # Combined strace/ltrace script
├── start-monitoring.sh             # File system monitoring script
├── linux_malware_analysis_container.sh  # Main execution script
├── samples/                        # Place malware samples here
```

### 3. Build the Container Image

**Using the provided script (Podman):**
```bash
# The script will automatically build the image on first run
./linux_malware_analysis_container.sh <malware_file>
```

**Manual build with Podman:**
```bash
podman build -t linux-malware-analysis .
```

**Using Docker Compose (if using Docker instead):**
```bash
docker-compose build
```

### 4. Verify the Image
```bash
podman images | grep linux-malware-analysis
```

---

## Running a Malware Hunt

## Using the Automated Script (Recommended)

The `linux_malware_analysis_container.sh` script automates the entire analysis workflow:

```bash
./linux_malware_analysis_container.sh <malware_file> [additional_files...]
```

**Example:**
```bash
./linux_malware_analysis_container.sh samples/suspicious_binary
```

**What the script does:**
1. Builds the container image (if not already built)
2. Creates a temporary container with network isolation
3. Copies the malware sample(s) into the container
4. Makes ELF binaries and scripts executable
5. Starts file system monitoring
6. Opens an interactive bash session
7. Cleans up the container after exit


## Extracting Analysis Results to Host

After running your analysis inside the container, you'll want to copy the results to your host machine for further review or archiving.

**Step 1: Identify the container name**
```bash
# List all containers (including stopped ones)
podman ps -a | grep linux

# Or for Docker
docker ps -a | grep linux
```

**Step 2: Copy analysis results**
```bash
# Copy the entire ltrace analysis folder
podman cp <container_name>:/tmp/ltrace_analysis ./analysis_results

# Copy trace logs
podman cp <container_name>:/var/log/malware-trace ./trace_logs

# Copy file system monitoring logs
podman cp <container_name>:/var/log/inotify/filesystem.log ./filesystem_changes.log

# Copy specific files only
podman cp <container_name>:/tmp/ltrace_analysis/ltrace_behavior_*.txt ./
```

**Example workflow:**
```bash
# 1. Run analysis
./linux_malware_analysis_container.sh samples/test_malware_simulator

# 2. Inside container, run analysis
ltrace-full /home/app/test_malware_simulator

# 3. Open new terminal on host, find container name
podman ps -a | grep linux_malware_analysis
# Output: linux-malware-analysis_1698508800

# 4. Copy results
podman cp linux-malware-analysis_1698508800:/tmp/ltrace_analysis ./my_analysis_results

# 5. View on host
cat ./my_analysis_results/ltrace_behavior_*.txt
```

---

## Analysis Tools

Once inside the container, you have access to several analysis tools:

### 1. Full ltrace Analysis (Recommended)

Captures comprehensive library call traces with behavioral analysis:

```bash
ltrace-full /home/app/samples/suspicious_binary
```

**Output files:**
- Raw ltrace output: `/tmp/ltrace_analysis/ltrace_raw_<timestamp>.txt`
- Behavioral analysis: `/tmp/ltrace_analysis/ltrace_behavior_<timestamp>.txt`

**Options:**
```bash
# With arguments
ltrace-full /home/app/samples/binary --arg1 --arg2

# View help
ltrace-full
```

### 2. Combined Trace Analysis

Runs both strace and ltrace simultaneously:

```bash
trace-malware /home/app/samples/suspicious_binary
```

**Output files:**
- System calls: `/var/log/malware-trace/<binary>_<timestamp>_strace.log`
- Library calls: `/var/log/malware-trace/<binary>_<timestamp>_ltrace.log`
- Program output: `/var/log/malware-trace/<binary>_<timestamp>_output.log`

### 3. Manual Behavioral Analysis

Parse existing ltrace output:

```bash
parse-ltrace-behavior.py -i <ltrace_output> -o <report_output>
```

**Options:**
```bash
# Specify custom behavior patterns
parse-ltrace-behavior.py -i trace.txt -o report.txt -c custom_patterns.json

# View help
parse-ltrace-behavior.py --help
```

### 4. File System Monitoring

Monitor file system changes in real-time:

```bash
# View monitoring log
tail -f /var/log/inotify/filesystem.log

# Search for specific events
grep "CREATE" /var/log/inotify/filesystem.log
grep "/tmp/" /var/log/inotify/filesystem.log
```

### 5. Manual Analysis Tools

**ltrace (library calls):**
```bash
ltrace -s 4096 -f -tt -T -o output.txt ./binary
```

**strace (system calls):**
```bash
strace -f -t -T -s 1024 -e trace=all -o output.txt ./binary
```

**Static analysis:**
```bash
file binary              # Identify file type
strings binary           # Extract strings
hexdump -C binary        # Hex dump
objdump -d binary        # Disassemble
readelf -a binary        # ELF information
```

---

## Understanding the Output

### Behavioral Analysis Report Structure

The behavioral analysis report (`ltrace_behavior_<timestamp>.txt`) contains:

#### 1. Executive Summary
- Total behavioral indicators detected
- Number of function calls analyzed
- Tactics employed by the malware

#### 2. Tactics Overview
Lists all detected tactics with indicator counts:
- **DISCOVERY**: System and network reconnaissance
- **PERSISTENCE**: Mechanisms to maintain access
- **PRIVILEGE_ESCALATION**: Attempts to gain elevated privileges
- **DEFENSE_EVASION**: Techniques to avoid detection
- **EXECUTION**: Code execution methods
- **CREDENTIAL_ACCESS**: Password/credential theft
- **INITIAL_ACCESS**: Entry point methods
- **IMPACT**: System modifications
- **GTFOBIN_***: GTFOBins exploitation techniques
- **SUSPICIOUS**: General suspicious activities

#### 3. Attack Chain Analysis
Chronological narrative of the attack stages:
- Initial Access → Discovery → Execution → Persistence → Privilege Escalation → Defense Evasion

#### 4. Detailed Behavioral Analysis
For each tactic:
- Specific techniques detected
- Number of occurrences
- Evidence (function calls with arguments)
- Timestamps

#### 5. File Operations Summary
- Directories/files created
- Files written/modified
- Files made executable
- Files deleted

#### 6. Indicators of Compromise (IOCs)
- File system IOCs (suspicious paths)
- Process IOCs (suspicious process names)
- Network IOCs (network activities)

### Example Output Interpretation

```
EXECUTION              - Execute Malicious Code                        [  5 indicators]
PERSISTENCE            - Establish Persistence Mechanisms              [  2 indicators]
DEFENSE_EVASION        - Evade Detection and Analysis                  [  3 indicators]
```

This indicates:
- The malware executed code 5 times
- Attempted to establish persistence twice
- Used 3 defense evasion techniques

---

## Advanced Usage

### Custom Behavior Patterns

Create a custom `behavior_patterns.json`:

```json
{
  "CUSTOM_TACTIC": {
    "description": "Custom Detection Pattern",
    "indicators": [
      ["pattern_regex", "Description of indicator"],
      ["another_pattern", "Another description"]
    ]
  }
}
```

Use with the parser:
```bash
parse-ltrace-behavior.py -i trace.txt -o report.txt -c custom_patterns.json
```

### Analyzing Multiple Samples

```bash
# Batch analysis
for sample in samples/*; do
    echo "Analyzing $sample..."
    ltrace-full "$sample"
done
```

### Extracting Specific Behaviors

```bash
# Find all network operations
grep -A 5 "NETWORK" /tmp/ltrace_analysis/ltrace_behavior_*.txt

# Find persistence mechanisms
grep -A 10 "PERSISTENCE" /tmp/ltrace_analysis/ltrace_behavior_*.txt

# Find file operations on /tmp
grep "/tmp/" /tmp/ltrace_analysis/ltrace_raw_*.txt
```

### Comparing Multiple Runs

```bash
# Compare behavior patterns across samples
diff -u analysis1_behavior.txt analysis2_behavior.txt
```

---

## Troubleshooting

### Container Won't Start

**Issue:** Permission denied or capability errors

**Solution:**
```bash
# Ensure proper capabilities
podman run --cap-add=SYS_PTRACE --security-opt seccomp=unconfined ...

# Check SELinux context (if applicable)
podman run -v ./samples:/home/app/samples:Z ...
```

### ltrace/strace Not Capturing Data

**Issue:** Empty or incomplete traces

**Solution:**
```bash
# Ensure binary is executable
chmod +x /home/app/samples/binary

# Check if binary is statically linked
file /home/app/samples/binary

# For statically linked binaries, use strace instead
strace -f -s 4096 ./binary
```

### Parser Errors

**Issue:** JSON parsing errors in behavior_patterns.json

**Solution:**
```bash
# Validate JSON syntax
python3 -m json.tool behavior_patterns.json

# Check file encoding
file behavior_patterns.json
```

### Container Network Issues

**Issue:** Malware attempting network connections

**Solution:**
```bash
# Verify network isolation
podman inspect malware-analysis | grep NetworkMode

# Should show: "NetworkMode": "none"
```

### File System Monitoring Not Working

**Issue:** No logs in /var/log/inotify/filesystem.log

**Solution:**
```bash
# Check if inotify is running
ps aux | grep inotifywait

# Restart monitoring
/usr/local/bin/start-monitoring.sh

# Check for inotify limits
cat /proc/sys/fs/inotify/max_user_watches
```

### Binary Crashes Immediately

**Issue:** Malware detects analysis environment

**Solution:**
```bash
# Run with minimal tracing
./binary  # Run without ltrace first

# Use strace instead of ltrace
strace -f ./binary

# Check for anti-debugging
strings binary | grep -i "ptrace\|debug\|trace"
```

---

## Best Practices

### Safety Guidelines

1. **Always use network isolation** (`--network none`)
2. **Never run malware on your host system**
3. **Use disposable containers** (remove after analysis)
4. **Keep samples in dedicated directories**
5. **Review analysis output before sharing**

### Analysis Workflow

1. **Initial triage**: Use `file`, `strings`, `readelf` for static analysis
2. **Behavioral analysis**: Run `ltrace-full` for comprehensive tracing
3. **Review report**: Examine the behavioral analysis report
4. **Deep dive**: Investigate specific suspicious behaviors
5. **Document findings**: Save IOCs and attack patterns
6. **Clean up**: Remove container and temporary files

### Performance Optimization

```bash
# Limit trace output size
ltrace -s 1024 ...  # Instead of -s 4096

# Focus on specific functions
ltrace -e 'open+close+read+write' ./binary

# Reduce monitoring scope
inotifywait -m /tmp /var/tmp  # Instead of all directories
```

---

## Quick Reference

### Common Commands

```bash
# Build image
podman build -t linux-malware-analysis .

# Run analysis (automated)
./linux_malware_analysis_container.sh sample.bin

# Enter running container
podman exec -it malware-analysis /bin/bash

# Full trace analysis
ltrace-full /home/app/samples/binary

# View behavioral report
cat /tmp/ltrace_analysis/ltrace_behavior_*.txt

# Monitor file system
tail -f /var/log/inotify/filesystem.log

# Copy analysis results to host
podman cp <container_name>:/tmp/ltrace_analysis ./analysis_results
podman cp <container_name>:/var/log/malware-trace ./trace_logs

# Clean up
podman stop malware-analysis && podman rm malware-analysis
```

### Important Paths

- **Samples**: `/home/app/samples/`
- **Analysis output**: `/home/app/analysis/`
- **ltrace output**: `/tmp/ltrace_analysis/`
- **Trace logs**: `/var/log/malware-trace/`
- **File system log**: `/var/log/inotify/filesystem.log`
- **Behavior patterns**: `/usr/local/bin/behavior_patterns.json`

---

## Additional Resources

- **GTFOBins**: https://gtfobins.github.io/
- **MITRE ATT&CK**: https://attack.mitre.org/
- **ltrace manual**: `man ltrace`
- **strace manual**: `man strace`
- **Podman documentation**: https://docs.podman.io/

---

## Support and Contributing

For issues, questions, or contributions, please refer to the project repository.

**Original project**: https://github.com/LaurieWired/linux_malware_analysis_container
