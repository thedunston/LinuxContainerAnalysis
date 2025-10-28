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
