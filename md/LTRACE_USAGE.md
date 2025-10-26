# ltrace Malware Analysis Tools

## Overview
This toolkit provides enhanced ltrace analysis capabilities for malware analysis with full output capture and intelligent parsing.

## Files
- **ltrace-full.sh** - Wrapper script that runs ltrace with optimal flags for malware analysis
- **parse-ltrace.py** - Python parser that organizes ltrace output into readable categories

## Usage

### Basic Analysis
```bash
./ltrace-full.sh ./thug_simulator
```

### With Arguments
```bash
./ltrace-full.sh ./malware_sample --arg1 --arg2
```

### Manual ltrace with Full Output
```bash
ltrace -s 4096 -n 4 -f -tt -T -o output.txt ./malware_sample
```

### Parse Existing ltrace Output
```bash
python3 parse-ltrace.py ltrace_output.txt parsed_output.txt
```

## ltrace Flags Explained

- **-s 4096** - Capture strings up to 4096 characters (default is 32)
- **-n 4** - Indent nested calls by 4 spaces for better readability
- **-f** - Follow child processes created by fork()
- **-tt** - Show absolute timestamps with microseconds
- **-T** - Show time spent in each system call
- **-o FILE** - Write output to file instead of stderr

## Parser Features

### Categories Tracked
1. **FILE_OPS** - File operations (fopen, fwrite, chmod, etc.)
2. **PROCESS** - Process operations (fork, exec, system, etc.)
3. **NETWORK** - Network operations (socket, connect, send, etc.)
4. **STRING_OPS** - String manipulation (strcpy, strcmp, etc.)
5. **DIRECTORY** - Directory operations (mkdir, rmdir, etc.)
6. **TIME** - Time-related calls (time, sleep, etc.)
7. **OUTPUT** - Output functions (printf, puts, etc.)
8. **CRYPTO** - Cryptographic operations
9. **MEMORY** - Memory management (malloc, free, etc.)

### Suspicious Pattern Detection
The parser automatically flags:
- Temp directory access (/tmp, /var/tmp)
- Shell script creation
- Systemd service manipulation
- Cron job creation
- Authentication log access
- SSH daemon interaction
- Password references
- System config access

### Report Sections
1. **Summary Statistics** - Call counts by category
2. **Suspicious Activities** - Flagged operations with context
3. **Detailed Analysis** - Per-category breakdown
4. **File Operations Detail** - Files accessed, written, deleted
5. **Process Operations Detail** - Process creation and execution
6. **Execution Timeline** - Chronological view of last 50 calls

## Output Location
All analysis files are saved to: `/tmp/ltrace_analysis/`

Files are timestamped: `ltrace_raw_YYYYMMDD_HHMMSS.txt`

## Example Workflow

```bash
# 1. Run full analysis
./ltrace-full.sh ./thug_simulator

# 2. View parsed output
cat /tmp/ltrace_analysis/ltrace_parsed_*.txt

# 3. Search for specific activities
grep "FILE_OPS" /tmp/ltrace_analysis/ltrace_parsed_*.txt
grep "SUSPICIOUS" /tmp/ltrace_analysis/ltrace_parsed_*.txt

# 4. View raw output for specific function
grep "mkdir" /tmp/ltrace_analysis/ltrace_raw_*.txt
```

## Integration with Other Tools

### Combine with strace
```bash
# Terminal 1: ltrace
./ltrace-full.sh ./malware &

# Terminal 2: strace
strace -o strace_output.txt -ff -tt -T ./malware
```

### Combine with trace-malware.sh
```bash
# Run comprehensive trace (includes ltrace)
./trace-malware.sh ./thug_simulator
```

## Tips

1. **Large Output** - For malware with many library calls, the output can be large. Use grep to filter:
   ```bash
   grep -E "(fopen|fwrite|system|fork)" ltrace_raw_*.txt
   ```

2. **Focus on Suspicious** - Check the SUSPICIOUS ACTIVITIES section first:
   ```bash
   sed -n '/SUSPICIOUS ACTIVITIES/,/DETAILED ANALYSIS/p' ltrace_parsed_*.txt
   ```

3. **File Timeline** - Track file operations chronologically:
   ```bash
   grep -E "(fopen|fwrite|fclose|unlink)" ltrace_raw_*.txt | head -50
   ```

4. **Network Activity** - Check for network operations:
   ```bash
   grep -E "(socket|connect|send|recv)" ltrace_raw_*.txt
   ```

## Troubleshooting

### ltrace not found
```bash
apt-get install ltrace
```

### Permission denied
```bash
chmod +x ltrace-full.sh parse-ltrace.py
```

### Parser errors
Ensure Python 3 is installed:
```bash
python3 --version
```

### No output
Check if the binary is dynamically linked:
```bash
ldd ./malware_sample
```
ltrace only works with dynamically linked binaries.

## Advanced Options

### Custom String Length
```bash
ltrace -s 8192 ./malware  # Capture 8KB strings
```

### Filter Specific Functions
```bash
ltrace -e 'fopen+fwrite+system' ./malware
```

### Library-Specific Tracing
```bash
ltrace -l /lib/x86_64-linux-gnu/libc.so.6 ./malware
```

### Count Calls Only
```bash
ltrace -c ./malware  # Summary statistics only
```
