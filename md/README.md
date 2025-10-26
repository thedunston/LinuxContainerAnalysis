# Linux Malware Analysis Container

[![Follow @lauriewired](https://img.shields.io/twitter/follow/lauriewired?style=social)](https://twitter.com/lauriewired)

# Description
Quickly build a lightweight Docker container to bundle tools for dynamic Linux malware analysis.

When dynamically analyzing malware, it is important to properly isolate the analysis environment from the host machine. To do this, you need to have a dedicated machine for your malware analysis. This container is designed to be run from within your malware analysis machine to bundle and pre-install common Reverse Engineering tools. It also provides an easy mechanism to quickly reset container state for samples requiring repetitive analysis.

> :exclamation: <span style="color:red">Important! Only run this from within a secure malware analysis environment! Many Docker container escapes exist in the wild. </span>

## Example Use-Cases
- Case 1: Reseting directories for ransomware analysis without having to fully revert the entire host upon each execution of the malware
- Case 2: Bundling Reverse Engineering tools to share between malware analysis machines that might be lacking dependencies

![docker_linux](https://github.com/LaurieWired/linux_malware_analysis_container/assets/123765654/ac6e839a-c07a-4d4c-b567-b0edcca9a4f1)

# Usage

## Running
Simply run the bash script to build and start the Docker container. Pass any files you would like copied to the container as command line arguments:

```
linux_malware_analysis_container.sh MY_FILE_1 MY_FILE_2
```

This will build and start the Docker container and copy the target files into the container at ```/home/app```. Once built, it opens an interactive shell where you can begin your analysis process. The container is based on Ubuntu meaning that the interactive shell will accept standard Linux commands and be able to dynamically run ELF binaries. The following list contains suggested commands for common Reverse Engineering tasks. These tools come pre-installed in the container along with many more:

- strace
- ltrace (with behavioral analysis parsers)
- strings
- gdb
- objdump
- file

## New: ltrace Behavioral Analysis

The container now includes comprehensive ltrace behavioral analysis tools that map library calls to attack tactics and techniques:

```bash
# Run complete behavioral analysis
ltrace-full /home/app/malware_sample

# View behavioral report
cat /tmp/ltrace_analysis/ltrace_behavior_*.txt

# Run interactive demo
/opt/monitoring/demo-behavior-analysis.sh
```

**Features:**
- Maps library calls to attack tactics (Initial Access, Discovery, Persistence, etc.)
- Reconstructs attack chain chronologically
- Extracts IOCs automatically
- Provides detection rules and mitigation steps
- Analyzes based on MITRE ATT&CK framework

**Documentation:**
- `/opt/monitoring/README_LTRACE.md` - Quick start guide
- `/opt/monitoring/BEHAVIOR_ANALYSIS.md` - Complete documentation
- `/opt/monitoring/QUICK_REFERENCE.md` - Command reference
- See `CONTAINER_USAGE.md` for container-specific instructions

## Removing
Once you have completed your analysis, enter ```exit``` as the command. This will automatically kill and remove the container.
