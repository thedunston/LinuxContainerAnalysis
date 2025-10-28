FROM ubuntu:latest

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    ltrace \
    python3 \
    python3-pip \
    gdb \
    strace \
    binwalk \
    yara \
    hexedit \
    binutils \
    elfutils \
    wget \
    netcat-openbsd \
    curl \
    netcat-traditional \
    inotify-tools \
    file \
    && rm -rf /var/lib/apt/lists/*

# Copy monitoring and trace analysis tools.
COPY start-monitoring.sh /usr/local/bin/start-monitoring.sh
RUN chmod +x /usr/local/bin/start-monitoring.sh

# Copy ltrace analysis tools.
COPY ltrace-full.sh /usr/local/bin/ltrace-full
COPY parse-ltrace-behavior.py /usr/local/bin/parse-ltrace-behavior.py
COPY behavior_patterns.json /etc/behavior_patterns.json
RUN chmod +x /usr/local/bin/ltrace-full
RUN chmod +x /usr/local/bin/parse-ltrace-behavior.py

# Set working directory.
RUN mkdir -p /home/app
WORKDIR /home/app

# Keep container running.
CMD ["tail", "-f", "/dev/null"]
