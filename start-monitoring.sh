#!/bin/bash

echo "========================================="
echo "  Starting File System Monitoring"
echo "========================================="

# Create log directory
mkdir -p /var/log/inotify

# Start inotify monitoring in background
echo "[*] Starting inotify file system monitoring..."
nohup inotifywait -m -r -e create,delete,modify,move,attrib /tmp /var/tmp /dev/shm /etc /home/app /root /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /opt --format '[%T] %e %w%f' --timefmt '%Y-%m-%d %H:%M:%S' > /var/log/inotify/filesystem.log 2>&1 &
INOTIFY_PID=$!
sleep 1

# Check status
echo ""
echo "[*] Monitoring Status:"
echo "    - Inotify: $(pgrep -x inotifywait >/dev/null && echo 'Running' || echo 'Not running')"
echo ""
echo "[*] Log location:"
echo "    - File system changes: /var/log/inotify/filesystem.log"
echo ""
echo "========================================="
echo "  Monitoring initialized"
echo "========================================="
echo ""
echo "Useful commands:"
echo "  - View file changes: tail -f /var/log/inotify/filesystem.log"
echo "  - Trace a process: ltrace-full <command>"
echo "  - Analyze behavior: parse-ltrace-behavior.py <ltrace-output-file>"
echo ""
