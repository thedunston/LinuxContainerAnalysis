# Using ltrace Analysis Tools in Container

## Container Setup

The Dockerfile has been updated to include all ltrace analysis tools and documentation.

### Files Installed in Container

**Tools** (in `/usr/local/bin/`):
- `ltrace-full` - Main analysis wrapper
- `parse-ltrace-behavior.py` - Behavioral parser with suspicious activity detection

**Demo** (in `/opt/monitoring/`):
- `demo-behavior-analysis.sh` - Interactive demo

**Documentation** (in `/opt/monitoring/`):
- `README_LTRACE.md`
- `BEHAVIOR_ANALYSIS.md`
- `LTRACE_USAGE.md`
- `QUICK_REFERENCE.md`

## Building the Container

```bash
# Build the image
docker-compose build

# Or with docker directly
docker build -t linux_malware_analysis .
```

## Running Analysis in Container

### Start the Container
```bash
docker-compose up -d
```

### Copy Malware Sample into Container
```bash
# Copy your malware sample
docker cp ./thug_simulator linux_malware_container:/home/app/

# Or mount a volume in docker-compose.yml
```

### Run Analysis
```bash
# Enter the container
docker exec -it linux_malware_container bash

# Run complete analysis
ltrace-full /home/app/thug_simulator

# View results
cat /tmp/ltrace_analysis/ltrace_behavior_*.txt

# Run demo
cd /opt/monitoring
./demo-behavior-analysis.sh
```

### Copy Results Out
```bash
# From host machine
docker cp linux_malware_container:/tmp/ltrace_analysis/ ./results/
```

## Quick Commands

### One-Line Analysis
```bash
# Run analysis and copy results out
docker exec linux_malware_container ltrace-full /home/app/malware && \
docker cp linux_malware_container:/tmp/ltrace_analysis/ ./results/
```

### View Documentation
```bash
# Inside container
cat /opt/monitoring/README_LTRACE.md
cat /opt/monitoring/QUICK_REFERENCE.md
```

### Run Demo
```bash
docker exec -it linux_malware_container /opt/monitoring/demo-behavior-analysis.sh
```

## Volume Mounting for Easy Access

Update `docker-compose.yml` to mount volumes:

```yaml
services:
  malware_analysis:
    volumes:
      - ./samples:/home/app/samples:ro  # Read-only malware samples
      - ./results:/tmp/ltrace_analysis  # Analysis output
```

Then:
```bash
# Place malware in ./samples/ on host
# Run analysis in container
docker exec linux_malware_container ltrace-full /home/app/samples/malware
# Results automatically appear in ./results/ on host
```

## Environment Variables

Set in docker-compose.yml or docker run:

```yaml
environment:
  - LTRACE_OUTPUT_DIR=/tmp/ltrace_analysis
  - LTRACE_STRING_LENGTH=4096
```

## Troubleshooting

### Parser Not Found
```bash
# Check if files are installed
docker exec linux_malware_container ls -la /usr/local/bin/ltrace-full
docker exec linux_malware_container ls -la /usr/local/bin/parse-ltrace-behavior.py
```

### Permission Issues
```bash
# Make sure files are executable
docker exec linux_malware_container chmod +x /usr/local/bin/ltrace-full
docker exec linux_malware_container chmod +x /usr/local/bin/parse-ltrace-behavior.py
```

### Python Not Found
```bash
# Check Python installation
docker exec linux_malware_container python3 --version
```

### Rebuild Container
```bash
# If you updated the Dockerfile
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

## Best Practices

1. **Always use containers** for malware analysis (isolation)
2. **Mount volumes** for easy file transfer
3. **Copy results out** before stopping container
4. **Use read-only mounts** for malware samples
5. **Snapshot container** before running unknown malware
6. **Review logs** after analysis

## Example Workflow

```bash
# 1. Build and start container
docker-compose build
docker-compose up -d

# 2. Copy malware sample
docker cp ./suspicious_binary linux_malware_container:/home/app/

# 3. Run analysis
docker exec linux_malware_container ltrace-full /home/app/suspicious_binary

# 4. Copy results
docker cp linux_malware_container:/tmp/ltrace_analysis/ ./analysis_results/

# 5. View behavioral report
cat ./analysis_results/ltrace_behavior_*.txt

# 6. Clean up
docker-compose down
```

## Integration with Other Container Tools

### With Cuckoo Sandbox
```bash
# Export ltrace results to Cuckoo
docker cp linux_malware_container:/tmp/ltrace_analysis/ /opt/cuckoo/storage/
```

### With MISP
```bash
# Extract IOCs and import to MISP
docker exec linux_malware_container grep "• /" /tmp/ltrace_analysis/ltrace_behavior_*.txt > iocs.txt
# Import iocs.txt to MISP
```

### With ELK Stack
```bash
# Forward analysis results to Elasticsearch
docker exec linux_malware_container cat /tmp/ltrace_analysis/ltrace_behavior_*.txt | \
  curl -X POST "localhost:9200/malware-analysis/_doc" -H 'Content-Type: application/json' -d @-
```
