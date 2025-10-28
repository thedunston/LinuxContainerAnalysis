#!/usr/bin/env python3
"""
Parses an ltrace file for behaviors like file operations, network activity, process creation, etc..
Maps library calls to specific malicious behaviors and TTPs (Tactics, Techniques, Procedures)
Includes checks for GTFOBIns in the behavior_patterns.json file.
"""

import re
import sys
import json
import os
import argparse
from collections import defaultdict
from datetime import datetime

class BehaviorAnalyzer:
    def __init__(self, config_file='behavior_patterns.json'):
        # Load behavior patterns from external JSON configuration
        self.behaviors = self._load_behaviors(config_file)
        
        self.timeline = []
        self.behavior_matches = defaultdict(list)
        self.file_operations = defaultdict(list)
        self.attack_chain = []
    
    def _load_behaviors(self, config_file):
        """Load behavior patterns from JSON configuration file"""
        # Try to find the config file in the script directory
        script_dir = os.path.dirname(os.path.abspath(__file__))
        config_path = os.path.join(script_dir, config_file)
        
        # If not found in script directory, try current directory
        if not os.path.exists(config_path):
            config_path = config_file
        
        try:
            with open(config_path, 'r') as f:
                behaviors_data = json.load(f)
            
            # Convert list format to tuple format for regex patterns
            behaviors = {}
            for tactic, data in behaviors_data.items():
                behaviors[tactic] = {
                    'description': data['description'],
                    'indicators': [(pattern, description) for pattern, description in data['indicators']]
                }
            
            print(f"[*] Loaded behavior patterns from: {config_path}")
            return behaviors
        
        except FileNotFoundError:
            print(f"[!] Warning: Config file '{config_path}' not found. Using empty behavior set.")
            print(f"[!] Please ensure 'behavior_patterns.json' is in the same directory as this script.")
            return {}
        except json.JSONDecodeError as e:
            print(f"[!] Error parsing JSON config file: {e}")
            return {}
        
    def analyze_call(self, call_info):
        """Analyze a single library call for behavioral indicators"""
        full_text = call_info['raw_line']
        behaviors_found = []
        
        for tactic, data in self.behaviors.items():
            for pattern, description in data['indicators']:
                if re.search(pattern, full_text, re.IGNORECASE):
                    behaviors_found.append({
                        'tactic': tactic,
                        'technique': description,
                        'evidence': full_text
                    })
                    self.behavior_matches[tactic].append({
                        'technique': description,
                        'call': call_info,
                        'timestamp': call_info.get('timestamp', 'N/A')
                    })
        
        return behaviors_found
    
    def parse_line(self, line):
        """Parse a single ltrace output line"""
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
    
    def extract_file_operations(self):
        """Extract and categorize all file operations"""
        file_ops = {
            'created': [],
            'written': [],
            'read': [],
            'deleted': [],
            'modified': [],
            'executed': []
        }
        
        for call in self.timeline:
            func = call['function']
            args = call['args']
            
            # Extract file paths
            file_paths = re.findall(r'"([^"]+)"', args)
            
            for filepath in file_paths:
                if '/' not in filepath:
                    continue
                
                if func in ['mkdir']:
                    file_ops['created'].append(filepath)
                elif func in ['fopen', 'open']:
                    if 'w' in args or 'a' in args:
                        file_ops['written'].append(filepath)
                    else:
                        file_ops['read'].append(filepath)
                elif func in ['fwrite', 'fprintf', 'write']:
                    if file_paths:
                        file_ops['written'].append(file_paths[0])
                elif func in ['unlink', 'remove']:
                    file_ops['deleted'].append(filepath)
                elif func in ['chmod']:
                    if '755' in args or '+x' in args:
                        file_ops['executed'].append(filepath)
                    file_ops['modified'].append(filepath)
        
        return file_ops
    
    def build_attack_chain(self):
        """Build a chronological attack chain narrative"""
        chain = []
        
        # Initial Access 
        initial_access = [m for m in self.behavior_matches.get('INITIAL_ACCESS', [])]
        if initial_access:
            chain.append({
                'phase': 'Initial Access',
                'description': 'Attacker gains initial access',
                'activities': initial_access
            })
        
        # Phase 2: Discovery
        discovery = [m for m in self.behavior_matches.get('DISCOVERY', [])]
        if discovery:
            chain.append({
                'phase': 'Discovery',
                'description': 'System reconnaissance and information gathering',
                'activities': discovery
            })
        
        # Execution
        execution = [m for m in self.behavior_matches.get('EXECUTION', [])]
        if execution:
            chain.append({
                'phase': 'Execution',
                'description': 'Deploy and execute malicious payloads',
                'activities': execution
            })
        
        # Persistence
        persistence = [m for m in self.behavior_matches.get('PERSISTENCE', [])]
        if persistence:
            chain.append({
                'phase': 'Persistence',
                'description': 'Establish persistence mechanisms',
                'activities': persistence
            })
        
        # Privilege Escalation
        privesc = [m for m in self.behavior_matches.get('PRIVILEGE_ESCALATION', [])]
        if privesc:
            chain.append({
                'phase': 'Privilege Escalation',
                'description': 'Attempt to gain elevated privileges',
                'activities': privesc
            })
        
        # Defense Evasion
        evasion = [m for m in self.behavior_matches.get('DEFENSE_EVASION', [])]
        if evasion:
            chain.append({
                'phase': 'Defense Evasion',
                'description': 'Cover tracks and evade detection',
                'activities': evasion
            })
        
        return chain
    
    def process_file(self, input_file):
        """Process the ltrace output file"""
        print(f"[*] Analyzing behavioral patterns in {input_file}...")
        
        with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('+++ ') or line.startswith('--- '):
                    continue
                
                call_info = self.parse_line(line)
                if not call_info:
                    continue
                
                # Analyze for behaviors
                behaviors = self.analyze_call(call_info)
                if behaviors:
                    call_info['behaviors'] = behaviors
                
                self.timeline.append(call_info)
        
        print(f"[*] Analyzed {len(self.timeline)} function calls")
        print(f"[*] Detected {sum(len(v) for v in self.behavior_matches.values())} behavioral indicators")
    
    def generate_report(self, output_file):
        """Generate a behavior-focused analysis report"""
        with open(output_file, 'w') as f:
            f.write("=" * 100 + "\n")
            f.write("MALWARE BEHAVIOR ANALYSIS REPORT\n")
            f.write("Generated: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\n")
            f.write("=" * 100 + "\n\n")
            
            # Executive Summary
            f.write("## EXECUTIVE SUMMARY\n")
            f.write("-" * 100 + "\n")
            f.write("This report analyzes the behavioral patterns detected in the ltrace output,\n")
            f.write("identifying malicious tactics, techniques, and procedures (TTPs) based on\n")
            f.write("library call patterns and system interactions.\n\n")
            
            total_behaviors = sum(len(v) for v in self.behavior_matches.values())
            f.write(f"Total Behavioral Indicators Detected: {total_behaviors}\n")
            f.write(f"Total Function Calls Analyzed: {len(self.timeline)}\n")
            f.write(f"Tactics Employed: {len([k for k, v in self.behavior_matches.items() if v])}\n\n")
            
            # Suspicious Activities Highlight
            suspicious_count = len(self.behavior_matches.get('SUSPICIOUS', []))
            if suspicious_count > 0:
                f.write("  SUSPICIOUS ACTIVITIES DETECTED: {} indicators\n\n".format(suspicious_count))
            
            # Tactics Overview
            f.write("## TACTICS OVERVIEW\n")
            f.write("-" * 100 + "\n")
            for tactic, data in self.behaviors.items():
                count = len(self.behavior_matches.get(tactic, []))
                if count > 0:
                    f.write(f"{tactic:25s} - {data['description']:50s} [{count:3d} indicators]\n")
                else:
                    f.write(f"  {tactic:25s} - {data['description']:50s} [  0 indicators]\n")
            f.write("\n")
            
            # Attack Chain Narrative
            f.write("## ATTACK CHAIN ANALYSIS\n")
            f.write("=" * 100 + "\n\n")
            
            attack_chain = self.build_attack_chain()
            for phase_data in attack_chain:
                f.write(f"### {phase_data['phase']}\n")
                f.write(f"{phase_data['description']}\n")
                f.write("-" * 100 + "\n")
                
                # Group by technique
                techniques = defaultdict(list)
                for activity in phase_data['activities']:
                    techniques[activity['technique']].append(activity)
                
                for technique, activities in techniques.items():
                    f.write(f"\n▸ {technique}\n")
                    f.write(f"  Occurrences: {len(activities)}\n")
                    
                    # Show first few examples
                    for i, activity in enumerate(activities[:3], 1):
                        call = activity['call']
                        ts = f"[{call.get('timestamp', 'N/A')}] " if call.get('timestamp') else ""
                        f.write(f"  Example {i}: {ts}{call['function']}({call['args'][:80]}...)\n")
                    
                    if len(activities) > 3:
                        f.write(f"  ... and {len(activities) - 3} more occurrences\n")
                
                f.write("\n")
            
            # Suspicious Activities Section
            suspicious_matches = self.behavior_matches.get('SUSPICIOUS', [])
            if suspicious_matches:
                f.write("## SUSPICIOUS ACTIVITIES\n")
                f.write("=" * 100 + "\n")
                f.write(f"Total Suspicious Indicators: {len(suspicious_matches)}\n\n")
                
                # Group by technique
                by_technique = defaultdict(list)
                for match in suspicious_matches:
                    by_technique[match['technique']].append(match)
                
                for technique, occurrences in sorted(by_technique.items(), key=lambda x: len(x[1]), reverse=True):
                    f.write(f"  {technique}\n")
                    f.write(f"   Count: {len(occurrences)}\n")
                    f.write(f"   Evidence:\n")
                    
                    for occ in occurrences[:5]:  # Show first 5
                        call = occ['call']
                        ts = f"[{occ['timestamp']}] " if occ['timestamp'] != 'N/A' else ""
                        f.write(f"     {ts}{call['function']}({call['args'][:70]}...) = {call['return']}\n")
                    
                    if len(occurrences) > 5:
                        f.write(f"     ... and {len(occurrences) - 5} more\n")
                    f.write("\n")
                
                f.write("\n")
            
            # Detailed Behavioral Analysis
            f.write("## DETAILED BEHAVIORAL ANALYSIS\n")
            f.write("=" * 100 + "\n\n")
            
            for tactic, data in self.behaviors.items():
                matches = self.behavior_matches.get(tactic, [])
                if not matches:
                    continue
                
                f.write(f"### {tactic}: {data['description']}\n")
                f.write("-" * 100 + "\n")
                f.write(f"Total Indicators: {len(matches)}\n\n")
                
                # Group by technique
                by_technique = defaultdict(list)
                for match in matches:
                    by_technique[match['technique']].append(match)
                
                for technique, occurrences in sorted(by_technique.items()):
                    f.write(f"▸ {technique}\n")
                    f.write(f"  Count: {len(occurrences)}\n")
                    f.write(f"  Evidence:\n")
                    
                    for occ in occurrences[:5]:  # Show first 5
                        call = occ['call']
                        ts = f"[{occ['timestamp']}] " if occ['timestamp'] != 'N/A' else ""
                        f.write(f"    {ts}{call['function']}({call['args'][:70]}...) = {call['return']}\n")
                    
                    if len(occurrences) > 5:
                        f.write(f"    ... and {len(occurrences) - 5} more\n")
                    f.write("\n")
            
            # File Operations Summary
            f.write("## FILE OPERATIONS SUMMARY\n")
            f.write("=" * 100 + "\n")
            
            file_ops = self.extract_file_operations()
            
            if file_ops['created']:
                f.write("\n### Directories/Files Created:\n")
                for path in sorted(set(file_ops['created'])):
                    f.write(f"  [+] {path}\n")
            
            if file_ops['written']:
                f.write("\n### Files Written/Modified:\n")
                for path in sorted(set(file_ops['written'])):
                    f.write(f"  [W] {path}\n")
            
            if file_ops['executed']:
                f.write("\n### Files Made Executable:\n")
                for path in sorted(set(file_ops['executed'])):
                    f.write(f"  [X] {path}\n")
            
            if file_ops['deleted']:
                f.write("\n### Files Deleted:\n")
                for path in sorted(set(file_ops['deleted'])):
                    f.write(f"  [-] {path}\n")
            
            f.write("\n")
            
            # Indicators of Compromise (IOCs)
            f.write("## INDICATORS OF COMPROMISE (IOCs)\n")
            f.write("=" * 100 + "\n\n")
            
            # Extract unique file paths
            all_files = set()
            for call in self.timeline:
                files = re.findall(r'"(/[^"]+)"', call['args'])
                all_files.update(files)
            
            f.write("### File System IOCs:\n")
            suspicious_keywords = [
                '/tmp/', '/var/tmp/', '.service', '.dat', 'config', 'network',
                'accounts', 'userlist', 'passwd', 'shadow'
            ]
            
            suspicious_files = []
            for path in sorted(all_files):
                if any(keyword in path.lower() for keyword in suspicious_keywords):
                    suspicious_files.append(path)
            
            if suspicious_files:
                for path in suspicious_files:
                    f.write(f"  • {path}\n")
            else:
                f.write("  • No suspicious file paths detected\n")
            
            f.write("\n### Process IOCs:\n")
            # Extract process names from timeline
            process_names = set()
            for call in self.timeline:
                if 'svchost' in call['raw_line'] or 'service' in call['raw_line']:
                    process_names.add("Suspicious process names detected in calls")
            
            if process_names:
                for proc in process_names:
                    f.write(f"  • {proc}\n")
            else:
                f.write("  • Review process execution patterns in detailed analysis\n")
            
            f.write("\n### Network IOCs:\n")
            network_activity = [m for m in self.behavior_matches.get('INITIAL_ACCESS', [])]
            if network_activity:
                f.write(f"  • {len(network_activity)} network-related activities detected\n")
            else:
                f.write("  • Review network connections in detailed analysis\n")
            
            f.write("\n")
            
            f.write("=" * 100 + "\n")
            f.write("END OF BEHAVIORAL ANALYSIS REPORT\n")
            f.write("=" * 100 + "\n")

def main():
    parser = argparse.ArgumentParser(description='Analyzes ltrace output for malicious behavioral patterns and maps them to attack tactics and techniques.',
        formatter_class=argparse.RawDescriptionHelpFormatter)
    
    parser.add_argument('-i', '--input',required=True,metavar='FILE',help='ltrace output file to analyze')
    
    parser.add_argument('-o', '--output',metavar='FILE',help='behavior report output file (default: <input_file>_behavior.txt)')
    
    parser.add_argument('-c', '--config',default='behavior_patterns.json',metavar='FILE',help='JSON configuration file with behavior patterns (default: behavior_patterns.json)')
    
    args = parser.parse_args()
    
    # Verify the json config file exists
    if not os.path.exists(args.config):
        print(f"[!] Error: {args.config} not found. Please ensure it exists or specify a different config file with -c/--config.")
        sys.exit(1)
    
    # Basic check json file is valid.
    try:
        with open(args.config, 'r') as f:
            json.load(f)
    except ValueError as e:
        print(f"[!] Error: Invalid JSON file. Please ensure {args.config} is a valid JSON file. Error: {e}")
        sys.exit(1)
    
    input_file = args.input
    output_file = args.output if args.output else input_file.replace('.txt', '_behavior.txt')
    
    analyzer = BehaviorAnalyzer(config_file=args.config)
    analyzer.process_file(input_file)
    analyzer.generate_report(output_file)
    
    print(f"\nBehavioral analysis complete!")
    print(f"Report saved to: {output_file}")
    print(f"\n[*] Summary:")
    print(f"    Total behaviors detected: {sum(len(v) for v in analyzer.behavior_matches.values())}")
    print(f"    Tactics identified: {len([k for k, v in analyzer.behavior_matches.items() if v])}")
    print(f"    Attack stages: {len(analyzer.build_attack_chain())}")

if __name__ == '__main__':
    main()
