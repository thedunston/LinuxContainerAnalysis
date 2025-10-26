# Behavior Patterns Configuration - Changes Summary

## Overview
The behavior patterns have been externalized from the Python code into a separate JSON configuration file for easier maintenance and updates.

## Changes Made

### 1. Created `behavior_patterns.json`
- **Location**: `/home/thedunston/linux_malware_analysis_container/behavior_patterns.json`
- **Purpose**: External configuration file containing all behavior detection patterns
- **Format**: JSON with tactics, descriptions, and regex indicators

### 2. Updated DISCOVERY Section
**Before** (Specific filenames):
```json
["config\\.dat", "System Information Discovery (uname -a)"]
["network\\.dat", "Network Configuration Discovery (ip a show)"]
["data\\.txt", "DNS Configuration Discovery (resolv.conf)"]
```

**After** (Generic patterns):
```json
["uname", "System Information Discovery"]
["ip.*show", "Network Configuration Discovery"]
["resolv\\.conf", "DNS Configuration Discovery"]
```

**Benefits**:
- More generic patterns catch variations
- Focuses on actual commands/behaviors rather than specific output files
- Added more discovery indicators (19 total vs 11 original)

### 3. Modified `parse-ltrace-behavior.py`
**Key Changes**:
- Added `json` and `os` imports
- Modified `__init__()` to accept `config_file` parameter
- Added `_load_behaviors()` method to read JSON configuration
- Removed hardcoded behavior patterns dictionary
- Added error handling for missing/invalid config files

**Code Changes**:
```python
# Old
def __init__(self):
    self.behaviors = { ... hardcoded patterns ... }

# New
def __init__(self, config_file='behavior_patterns.json'):
    self.behaviors = self._load_behaviors(config_file)
```

### 4. Created Documentation
- **BEHAVIOR_PATTERNS_CONFIG.md**: Complete guide for using and updating the configuration

## New Features

### Flexible Configuration Loading
The script now searches for the config file in:
1. Same directory as the script
2. Current working directory

### Enhanced DISCOVERY Patterns
Added new generic indicators:
- `ifconfig` - Network Interface Discovery
- `netstat` - Network Statistics Discovery
- `rpm.*-qa` - Package Discovery (RPM-based systems)
- `whoami` - User Identity Discovery
- `hostname` - System Hostname Discovery
- `ps.*aux` - Process Discovery
- `lsof` - Open Files Discovery

### Improved Error Handling
- Graceful handling of missing config files
- JSON parsing error detection
- Informative error messages

## Benefits

1. **Easy Updates**: Modify patterns without touching Python code
2. **Version Control**: Track pattern changes separately from code
3. **Collaboration**: Security analysts can update patterns without Python knowledge
4. **Testing**: Easy to test different pattern sets
5. **Portability**: Share pattern sets between installations
6. **Generic Patterns**: Better detection coverage with behavior-focused patterns

## Usage

### Standard Usage (unchanged)
```bash
python3 parse-ltrace-behavior.py ltrace_output.txt
```

### Custom Config File
```bash
# Modify the script or use a custom config location
python3 parse-ltrace-behavior.py ltrace_output.txt
```

### Validate Configuration
```bash
python3 -c "import json; json.load(open('behavior_patterns.json')); print('Valid')"
```

## Migration Notes

### For Existing Users
1. The new `behavior_patterns.json` file must be in the same directory as the script
2. All original patterns are preserved (with DISCOVERY made more generic)
3. The script will warn if the config file is missing

### For Custom Patterns
If you had modified the hardcoded patterns:
1. Copy your custom patterns to `behavior_patterns.json`
2. Follow the JSON format shown in the documentation
3. Test with sample ltrace output

## Pattern Comparison

### DISCOVERY Section Changes

| Old Pattern | New Pattern | Improvement |
|------------|-------------|-------------|
| `config\\.dat` | `uname` | Detects actual command vs output file |
| `network\\.dat` | `ip.*show` | Catches all ip show variants |
| `data\\.txt` | `resolv\\.conf` | Detects config file access |
| `connections\\.dat` | `ss.*-` | Catches all ss command variants |
| `accounts\\.dat` | `/etc/passwd` | Detects actual file access |
| `userlist\\.dat` | `/etc/shadow` | Detects actual file access |
| `services\\.dat` | `systemctl.*list` | Catches all systemctl list variants |
| `cronjobs\\.dat` | `crontab.*-l` | Detects actual command |
| `packages\\.dat` | `dpkg.*-l` | Detects actual command |
| `autorun\\.dat` | `rc\\.local` | Detects config file access |
| `startup\\.dat` | `\\.bashrc` | Detects config file access |

## Files Modified/Created

1. ✅ `behavior_patterns.json` - Created (new configuration file)
2. ✅ `parse-ltrace-behavior.py` - Modified (loads external config)
3. ✅ `BEHAVIOR_PATTERNS_CONFIG.md` - Created (documentation)
4. ✅ `BEHAVIOR_PATTERNS_CHANGES.md` - Created (this file)

## Testing

To verify the changes work correctly:

```bash
# Check JSON is valid
python3 -c "import json; data = json.load(open('behavior_patterns.json')); print(f'Loaded {len(data)} tactics')"

# Test script loads config
python3 parse-ltrace-behavior.py sample_ltrace.txt

# Expected output should include:
# [*] Loaded behavior patterns from: /path/to/behavior_patterns.json
```
