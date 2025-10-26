# Behavior Patterns Configuration

## Overview

The `parse-ltrace-behavior.py` script uses an external JSON configuration file (`behavior_patterns.json`) to define behavioral patterns for malware analysis. This allows you to update detection patterns without modifying the Python code.

## Configuration File Location

The script looks for `behavior_patterns.json` in the following order:
1. Same directory as the script
2. Current working directory

## JSON Structure

The configuration file follows this structure:

```json
{
  "TACTIC_NAME": {
    "description": "Human-readable description of the tactic",
    "indicators": [
      ["regex_pattern", "Description of what this pattern detects"],
      ["another_pattern", "Another description"]
    ]
  }
}
```

## Tactics

The following MITRE ATT&CK-inspired tactics are supported:

- **DISCOVERY**: System and Network Discovery
- **PERSISTENCE**: Establish Persistence Mechanisms
- **PRIVILEGE_ESCALATION**: Privilege Escalation Attempts
- **DEFENSE_EVASION**: Evade Detection and Analysis
- **EXECUTION**: Execute Malicious Code
- **CREDENTIAL_ACCESS**: Credential Theft and Access
- **INITIAL_ACCESS**: Initial Access Vector
- **IMPACT**: System Impact and Modifications

## Adding New Patterns

To add a new detection pattern:

1. Open `behavior_patterns.json`
2. Navigate to the appropriate tactic section
3. Add a new indicator array with:
   - A regex pattern (remember to escape special characters)
   - A description of what the pattern detects

Example:
```json
"DISCOVERY": {
  "description": "System and Network Discovery",
  "indicators": [
    ["uname", "System Information Discovery"],
    ["your_new_pattern", "Your description here"]
  ]
}
```

## Regex Pattern Tips

- Use `\\` to escape special regex characters (e.g., `\\.` for literal dot)
- Patterns are case-insensitive by default
- Use `.*` for wildcard matching (e.g., `chmod.*\\+x`)
- Test patterns carefully to avoid false positives

## Adding New Tactics

To add a completely new tactic:

1. Add a new top-level key in the JSON file
2. Include `description` and `indicators` fields
3. The script will automatically detect and use the new tactic

Example:
```json
"COLLECTION": {
  "description": "Data Collection Activities",
  "indicators": [
    ["tar.*czf", "Archive Creation"],
    ["zip.*-r", "Recursive Zip Archive"]
  ]
}
```

## Validation

To validate your JSON configuration:

```bash
python3 -c "import json; json.load(open('behavior_patterns.json')); print('Valid JSON')"
```

## Example Patterns

### Generic Patterns (Recommended)
```json
["uname", "System Information Discovery"]
["chmod.*\\+x", "Make File Executable"]
["/etc/passwd", "Password File Access"]
```

### Specific Patterns (Use Sparingly)
```json
["config\\.dat", "Specific config file access"]
["Secur1ty@2025", "Hardcoded password detection"]
```

## Best Practices

1. **Keep patterns generic** - Focus on behaviors, not specific filenames
2. **Avoid over-specific patterns** - They may miss variants
3. **Document patterns clearly** - Use descriptive text
4. **Test regularly** - Validate against known malware samples
5. **Version control** - Track changes to the configuration file

## Troubleshooting

### Config file not found
```
[!] Warning: Config file 'behavior_patterns.json' not found.
```
**Solution**: Ensure `behavior_patterns.json` is in the same directory as the script.

### JSON parsing error
```
[!] Error parsing JSON config file: ...
```
**Solution**: Validate your JSON syntax using a JSON validator or the validation command above.

### No patterns detected
**Solution**: Check that your regex patterns are correctly escaped and match the expected ltrace output format.
