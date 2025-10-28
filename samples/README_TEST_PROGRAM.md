# Test Malware Simulator

## Overview

The **Test Malware Simulator** is a benign C program designed to demonstrate and test the behavioral analysis capabilities of the Linux Malware Analysis Container. It simulates various malicious behaviors without causing any actual harm, making it perfect for:

- Testing the analysis environment
- Learning how behavioral analysis works
- Validating detection patterns
- Training and demonstrations

## Features

This test program simulates the following behavioral categories:

### 1. DISCOVERY
- System hostname discovery (`gethostname`)
- User identity discovery (`getenv`)
- Account discovery (`/etc/passwd`)
- Process enumeration (`ps aux`)

### 2. EXECUTION
- Shell command execution (`system()`)
- Script creation and execution
- File permission modification (`chmod 0755`)

### 3. PERSISTENCE
- Shell profile modification (`.bashrc`)
- Systemd service file creation (`.service`)
- Cron job simulation (`crontab`)

### 4. DEFENSE_EVASION
- Temporary directory usage (`/tmp/`, `/var/tmp/`)
- File deletion (`unlink()`)
- Cleanup operations

### 5. FILE_OPS
- File open/close (`fopen`, `fclose`)
- File read/write (`fread`, `fwrite`, `fprintf`)
- File status checks (`stat`, `access`)
- File operations (`rename`, `chmod`)

### 6. PROCESS
- Process creation (`fork`)
- Process waiting (`waitpid`)
- Pipe execution (`popen`)

### 7. NETWORK
- Socket creation (`socket`)
- Socket binding (`bind`)
- Socket operations

### 8. STRING_OPS
- String copying (`strcpy`, `strncpy`)
- String concatenation (`strcat`)
- String comparison (`strcmp`)
- String formatting (`sprintf`)
- Memory operations (`memcpy`, `memset`)

### 9. DIRECTORY
- Directory creation (`mkdir`)
- Directory removal (`rmdir`)
- Directory reading (`opendir`, `readdir`, `closedir`)
- Working directory operations (`getcwd`)

### 10. TIME
- Time retrieval (`time`)
- Time formatting (`ctime`, `strftime`)
- Sleep operations (`sleep`)

### 11. MEMORY
- Memory allocation (`malloc`, `calloc`)
- Memory reallocation (`realloc`)
- Memory deallocation (`free`)

### 12. CREDENTIAL_ACCESS
- Password file access (`/etc/passwd`)
- Shadow file access attempt (`/etc/shadow`)
- Home directory inspection
- Password-related string operations

## Compilation

### Using Make (Recommended)

```bash
# Compile the program
make

# Compile and run
make test

# Clean up
make clean

# Show help
make help
```

### Manual Compilation

```bash
gcc -Wall -Wextra -O2 -o test_malware_simulator test_malware_simulator.c
```

## Usage

### Basic Execution

```bash
# Run the program directly
./test_malware_simulator
```

### Analysis with ltrace-full (Recommended)

```bash
# Full behavioral analysis
ltrace-full ./test_malware_simulator

# View the behavioral report
cat /tmp/ltrace_analysis/ltrace_behavior_*.txt
```

### Analysis with trace-malware

```bash
# Combined strace and ltrace analysis
trace-malware ./test_malware_simulator

# View system calls
cat /var/log/malware-trace/test_malware_simulator_*_strace.log

# View library calls
cat /var/log/malware-trace/test_malware_simulator_*_ltrace.log
```

### Manual Analysis

```bash
# Library call tracing
ltrace -s 4096 -f -tt -T -o trace.txt ./test_malware_simulator

# Parse the trace
parse-ltrace-behavior.py -i trace.txt -o report.txt

# View the report
cat report.txt
```

## Expected Detection Results

When analyzed, the test program should trigger the following behavioral indicators:

### High-Level Tactics
- DISCOVERY (4+ indicators)
- EXECUTION (3+ indicators)
- PERSISTENCE (3+ indicators)
- DEFENSE_EVASION (2+ indicators)
- CREDENTIAL_ACCESS (2+ indicators)
- FILE_OPS (10+ indicators)
- PROCESS (3+ indicators)
- NETWORK (2+ indicators)
- STRING_OPS (8+ indicators)
- DIRECTORY (5+ indicators)
- TIME (4+ indicators)
- MEMORY (4+ indicators)

### Specific Indicators

**File System IOCs:**
- `/tmp/test_file.txt`
- `/tmp/test_renamed.txt`
- `/tmp/test_script.sh`
- `/tmp/.bashrc_test`
- `/tmp/test.service`
- `/tmp/crontab_test`
- `/tmp/test_dir/`
- `/var/tmp/cache.dat`

**Suspicious Patterns:**
- Executable file creation
- Persistence mechanism setup
- Credential file access
- Temporary directory usage
- Network socket operations

## Sample Output

```
===========================================
  Test Malware Simulator
  For Linux Malware Analysis Container
===========================================

[*] Starting behavioral simulation...

[DISCOVERY] Gathering system information...
  [+] Hostname: container-12345
  [+] Current user: root
  [+] Reading /etc/passwd...
  [+] Found 3 user entries
  [+] Enumerating processes...

[FILE_OPS] Performing file operations...
  [+] File write: /tmp/test_file.txt
  [+] File read: /tmp/test_file.txt
  [+] File stat: size=42 bytes
  [+] File access check: exists
  [+] Changed file permissions
  [+] Renamed file

[DIRECTORY] Performing directory operations...
  [+] Current directory: /home/app
  [+] Created directory: /tmp/test_dir
  [+] Opened directory: /tmp
  [+] Read 5 directory entries
  [+] Removed directory: /tmp/test_dir

... (additional output) ...

[*] Simulation complete!
[*] Check the behavioral analysis report for detected patterns.
```

## Behavioral Analysis Report

After running with `ltrace-full`, you'll get a comprehensive report showing:

1. **Executive Summary**
   - Total behavioral indicators detected
   - Tactics employed
   - Attack stages identified

2. **Attack Chain Analysis**
   - Chronological sequence of behaviors
   - Grouped by attack phase

3. **Detailed Behavioral Analysis**
   - Each tactic with specific techniques
   - Evidence (function calls)
   - Timestamps

4. **File Operations Summary**
   - Files created, modified, deleted
   - Executable files

5. **Indicators of Compromise**
   - Suspicious file paths
   - Process indicators
   - Network indicators

## Testing Scenarios

### Scenario 1: Basic Behavioral Analysis
```bash
# Run full analysis
ltrace-full ./test_malware_simulator

# Review the report
less /tmp/ltrace_analysis/ltrace_behavior_*.txt

# Search for specific tactics
grep "PERSISTENCE" /tmp/ltrace_analysis/ltrace_behavior_*.txt
```

### Scenario 2: File System Monitoring
```bash
# Start monitoring (if not already running)
/usr/local/bin/start-monitoring.sh

# Run the test program
./test_malware_simulator

# Check file system changes
cat /var/log/inotify/filesystem.log | grep test_
```

### Scenario 3: Custom Pattern Testing
```bash
# Create custom patterns
cat > custom_patterns.json << 'EOF'
{
  "CUSTOM_TEST": {
    "description": "Custom Test Patterns",
    "indicators": [
      ["test_malware_simulator", "Test Program Execution"],
      ["test_file", "Test File Operations"]
    ]
  }
}
EOF

# Run analysis with custom patterns
ltrace -s 4096 -f -o trace.txt ./test_malware_simulator
parse-ltrace-behavior.py -i trace.txt -o report.txt -c custom_patterns.json
cat report.txt
```

### Scenario 4: Comparing with Real Malware
```bash
# Analyze test program
ltrace-full ./test_malware_simulator
mv /tmp/ltrace_analysis/ltrace_behavior_*.txt test_report.txt

# Analyze real sample
ltrace-full ./suspicious_binary
mv /tmp/ltrace_analysis/ltrace_behavior_*.txt malware_report.txt

# Compare
diff -u test_report.txt malware_report.txt
```

## Safety Notes

**IMPORTANT**: While this program is benign and safe to run, it should still be executed in the isolated container environment for best practices:

- Always run in the container (not on host)
- Use network isolation (`--network none`)
- Review the source code before compilation
- Clean up test files after analysis

## Cleanup

The program creates several test files. To clean them up:

```bash
# Using make
make clean

# Manual cleanup
rm -f /tmp/test_*.txt /tmp/test_*.sh /tmp/.bashrc_test
rm -f /tmp/*.service /tmp/crontab_test
rm -rf /tmp/test_dir
```

## Educational Value

This test program is excellent for:

1. **Learning behavioral analysis**: See how different function calls map to malicious tactics
2. **Understanding ltrace/strace**: Observe how system and library calls are captured
3. **Pattern development**: Test new detection patterns in `behavior_patterns.json`
4. **Training**: Demonstrate malware analysis techniques safely
5. **Validation**: Verify the analysis environment is working correctly

## Extending the Test Program

You can modify the program to test additional patterns:

```c
// Add new behavior simulation
void simulate_custom_behavior() {
    printf("[CUSTOM] Simulating custom behavior...\n");
    
    // Your test code here
    
    printf("\n");
}

// Call from main()
int main() {
    // ... existing code ...
    simulate_custom_behavior();
    // ... rest of code ...
}
```

## Troubleshooting

### Program doesn't compile
```bash
# Check GCC is installed
gcc --version

# Install if missing
apt-get update && apt-get install -y gcc
```

### No behavioral patterns detected
```bash
# Verify behavior_patterns.json exists
ls -l /usr/local/bin/behavior_patterns.json

# Check parser is available
which parse-ltrace-behavior.py

# Run with verbose ltrace
ltrace -s 4096 -f -tt -T ./test_malware_simulator
```

### Permission errors
```bash
# Ensure executable
chmod +x test_malware_simulator

# Check /tmp permissions
ls -ld /tmp
```

## References

- **Main User Guide**: See `USER_GUIDE.md` for complete setup instructions
- **Behavior Patterns**: See `behavior_patterns.json` for all detection patterns
- **Analysis Scripts**: See `ltrace-full.sh` and `parse-ltrace-behavior.py`

## License

This test program is provided for educational and testing purposes only.
