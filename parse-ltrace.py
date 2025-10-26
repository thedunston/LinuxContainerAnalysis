#!/usr/bin/env python3
"""
ltrace Output Parser for Malware Analysis
Parses ltrace output and organizes it into readable categories
"""

import re
import sys
from collections import defaultdict
from datetime import datetime

class LtraceParser:
    def __init__(self):
        # Define function categories for malware analysis
        self.categories = {
            'FILE_OPS': ['fopen', 'fclose', 'fwrite', 'fread', 'fprintf', 'stat', 'access', 
                         'open', 'close', 'read', 'write', 'unlink', 'rename', 'chmod', 'chown'],
            'PROCESS': ['fork', 'execve', 'system', 'popen', 'waitpid', 'kill', 'exit', 'clone'],
            'NETWORK': ['socket', 'connect', 'bind', 'listen', 'accept', 'send', 'recv', 
                       'sendto', 'recvfrom', 'gethostbyname', 'getaddrinfo'],
            'STRING_OPS': ['strcpy', 'strncpy', 'strcat', 'strcmp', 'strlen', 'sprintf', 
                          'snprintf', 'strstr', 'strchr', 'strrchr', 'memcpy', 'memset'],
            'DIRECTORY': ['mkdir', 'rmdir', 'opendir', 'readdir', 'closedir', 'chdir', 'getcwd'],
            'TIME': ['time', 'ctime', 'localtime', 'gmtime', 'strftime', 'sleep', 'usleep', 'nanosleep'],
            'OUTPUT': ['printf', 'puts', 'putchar', 'fprintf', 'write'],
            'CRYPTO': ['MD5', 'SHA', 'AES', 'DES', 'encrypt', 'decrypt', 'rand', 'srand'],
            'MEMORY': ['malloc', 'calloc', 'realloc', 'free', 'mmap', 'munmap'],
            'REGISTRY': ['RegOpenKey', 'RegSetValue', 'RegQueryValue', 'RegCloseKey'],
        }
        
        self.suspicious_patterns = [
            (r'/tmp/', 'Temp directory access'),
            (r'/var/tmp/', 'Var temp directory access'),
            (r'\.sh"', 'Shell script'),
            (r'systemd', 'Systemd service'),
            (r'cron', 'Cron job'),
            (r'auth\.log', 'Authentication log access'),
            (r'sshd', 'SSH daemon'),
            (r'password', 'Password reference'),
            (r'/etc/', 'System config access'),
            (r'\.service', 'Service file'),
        ]
        
        self.stats = defaultdict(int)
        self.timeline = []
        self.categorized_calls = defaultdict(list)
        self.suspicious_activities = []
        
    def categorize_function(self, func_name):
        """Determine the category of a function call"""
        for category, functions in self.categories.items():
            if any(func_name.startswith(f) for f in functions):
                return category
        return 'OTHER'
    
    def parse_line(self, line):
        """Parse a single ltrace output line"""
        # Pattern: [timestamp] [pid] function(args) = return_value <duration>
        # Example: 12:34:56.789012 [1234] fopen("/tmp/file", "w") = 0x12345 <0.000123>
        
        # Extract timestamp if present
        timestamp_match = re.match(r'^(\d+:\d+:\d+\.\d+)\s+', line)
        timestamp = timestamp_match.group(1) if timestamp_match else None
        
        # Extract PID if present
        pid_match = re.search(r'\[(\d+)\]', line)
        pid = pid_match.group(1) if pid_match else None
        
        # Extract function call
        func_match = re.search(r'(\w+)\((.*?)\)\s*=\s*(.+?)(?:\s+<([\d.]+)>)?$', line)
        if not func_match:
            return None
        
        func_name = func_match.group(1)
        args = func_match.group(2)
        return_val = func_match.group(3).strip()
        duration = func_match.group(4) if func_match.group(4) else None
        
        return {
            'timestamp': timestamp,
            'pid': pid,
            'function': func_name,
            'args': args,
            'return': return_val,
            'duration': duration,
            'raw_line': line.strip()
        }
    
    def check_suspicious(self, call_info):
        """Check if a call contains suspicious patterns"""
        full_text = call_info['raw_line']
        findings = []
        
        for pattern, description in self.suspicious_patterns:
            if re.search(pattern, full_text, re.IGNORECASE):
                findings.append(description)
        
        return findings
    
    def process_file(self, input_file):
        """Process the ltrace output file"""
        print(f"[*] Parsing {input_file}...")
        
        with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith('+++ ') or line.startswith('--- '):
                    continue
                
                call_info = self.parse_line(line)
                if not call_info:
                    continue
                
                # Categorize
                category = self.categorize_function(call_info['function'])
                call_info['category'] = category
                
                # Update stats
                self.stats[category] += 1
                self.stats['total_calls'] += 1
                
                # Store categorized call
                self.categorized_calls[category].append(call_info)
                
                # Check for suspicious activity
                suspicious = self.check_suspicious(call_info)
                if suspicious:
                    call_info['suspicious'] = suspicious
                    self.suspicious_activities.append(call_info)
                
                # Add to timeline
                self.timeline.append(call_info)
        
        print(f"[*] Parsed {self.stats['total_calls']} function calls")
    
    def generate_report(self, output_file):
        """Generate a readable analysis report"""
        with open(output_file, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("LTRACE MALWARE ANALYSIS REPORT\n")
            f.write("=" * 80 + "\n\n")
            
            # Summary Statistics
            f.write("## SUMMARY STATISTICS\n")
            f.write("-" * 80 + "\n")
            f.write(f"Total Function Calls: {self.stats['total_calls']}\n")
            f.write(f"Suspicious Activities: {len(self.suspicious_activities)}\n\n")
            
            f.write("Calls by Category:\n")
            for category in sorted(self.categories.keys()):
                count = self.stats.get(category, 0)
                if count > 0:
                    f.write(f"  {category:20s}: {count:5d}\n")
            other_count = self.stats.get('OTHER', 0)
            if other_count > 0:
                f.write(f"  {'OTHER':20s}: {other_count:5d}\n")
            f.write("\n")
            
            # Suspicious Activities
            if self.suspicious_activities:
                f.write("## SUSPICIOUS ACTIVITIES\n")
                f.write("-" * 80 + "\n")
                for idx, activity in enumerate(self.suspicious_activities, 1):
                    f.write(f"\n[{idx}] {activity['function']}()\n")
                    if activity.get('timestamp'):
                        f.write(f"    Time: {activity['timestamp']}\n")
                    if activity.get('pid'):
                        f.write(f"    PID: {activity['pid']}\n")
                    f.write(f"    Flags: {', '.join(activity['suspicious'])}\n")
                    f.write(f"    Call: {activity['function']}({activity['args']}) = {activity['return']}\n")
                f.write("\n")
            
            # Detailed Analysis by Category
            f.write("## DETAILED ANALYSIS BY CATEGORY\n")
            f.write("=" * 80 + "\n\n")
            
            for category in sorted(self.categories.keys()):
                calls = self.categorized_calls.get(category, [])
                if not calls:
                    continue
                
                f.write(f"### {category}\n")
                f.write("-" * 80 + "\n")
                f.write(f"Total calls: {len(calls)}\n\n")
                
                # Show unique operations
                unique_ops = defaultdict(int)
                for call in calls:
                    unique_ops[call['function']] += 1
                
                f.write("Function breakdown:\n")
                for func, count in sorted(unique_ops.items(), key=lambda x: x[1], reverse=True):
                    f.write(f"  {func:30s}: {count:5d} calls\n")
                
                # Show sample calls (first 10)
                f.write(f"\nSample calls (showing first 10):\n")
                for call in calls[:10]:
                    ts = f"[{call['timestamp']}] " if call.get('timestamp') else ""
                    pid = f"[PID:{call['pid']}] " if call.get('pid') else ""
                    duration = f" <{call['duration']}s>" if call.get('duration') else ""
                    f.write(f"  {ts}{pid}{call['function']}({call['args']}) = {call['return']}{duration}\n")
                
                if len(calls) > 10:
                    f.write(f"  ... and {len(calls) - 10} more calls\n")
                
                f.write("\n")
            
            # File Operations Detail
            if self.categorized_calls.get('FILE_OPS'):
                f.write("## FILE OPERATIONS DETAIL\n")
                f.write("-" * 80 + "\n")
                
                files_accessed = set()
                files_written = []
                files_deleted = []
                
                for call in self.categorized_calls['FILE_OPS']:
                    # Extract file paths from arguments
                    file_match = re.findall(r'"([^"]+)"', call['args'])
                    for filepath in file_match:
                        if '/' in filepath:
                            files_accessed.add(filepath)
                            
                            if call['function'] in ['fopen', 'open'] and ('w' in call['args'] or 'a' in call['args']):
                                files_written.append((filepath, call['function']))
                            elif call['function'] in ['unlink', 'remove']:
                                files_deleted.append((filepath, call['function']))
                
                f.write(f"\nUnique files accessed: {len(files_accessed)}\n")
                for filepath in sorted(files_accessed):
                    f.write(f"  - {filepath}\n")
                
                if files_written:
                    f.write(f"\nFiles written/modified:\n")
                    for filepath, func in files_written:
                        f.write(f"  - {filepath} ({func})\n")
                
                if files_deleted:
                    f.write(f"\nFiles deleted:\n")
                    for filepath, func in files_deleted:
                        f.write(f"  - {filepath} ({func})\n")
                
                f.write("\n")
            
            # Process Operations Detail
            if self.categorized_calls.get('PROCESS'):
                f.write("## PROCESS OPERATIONS DETAIL\n")
                f.write("-" * 80 + "\n")
                
                for call in self.categorized_calls['PROCESS']:
                    f.write(f"  {call['function']}({call['args']}) = {call['return']}\n")
                
                f.write("\n")
            
            # Timeline (last 50 calls)
            f.write("## EXECUTION TIMELINE (Last 50 calls)\n")
            f.write("-" * 80 + "\n")
            for call in self.timeline[-50:]:
                ts = f"[{call['timestamp']}] " if call.get('timestamp') else ""
                cat = f"[{call['category']}] "
                suspicious = " ⚠️ SUSPICIOUS" if call.get('suspicious') else ""
                f.write(f"{ts}{cat}{call['function']}({call['args'][:60]}...) = {call['return']}{suspicious}\n")
            
            f.write("\n")
            f.write("=" * 80 + "\n")
            f.write("END OF REPORT\n")
            f.write("=" * 80 + "\n")

def main():
    if len(sys.argv) < 2:
        print("Usage: parse-ltrace.py <ltrace_output_file> [parsed_output_file]")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else input_file.replace('.txt', '_parsed.txt')
    
    parser = LtraceParser()
    parser.process_file(input_file)
    parser.generate_report(output_file)
    
    print(f"[✓] Analysis complete!")
    print(f"[✓] Report saved to: {output_file}")
    print(f"\n[*] Quick Stats:")
    print(f"    Total calls: {parser.stats['total_calls']}")
    print(f"    Suspicious activities: {len(parser.suspicious_activities)}")
    print(f"    Categories detected: {len([k for k, v in parser.stats.items() if k != 'total_calls' and v > 0])}")

if __name__ == '__main__':
    main()
