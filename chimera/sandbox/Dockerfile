# Chimera Sandbox Base Image
# Build manually later with: docker build -t chimera-sandbox:latest .
FROM kalilinux/kali-rolling:latest

RUN apt-get update && apt-get install -y \
    python3 python3-pip python3-venv \
    golang-go git curl wget \
    nmap masscan \
    libpcap-dev \
    chromium \
    && rm -rf /var/lib/apt/lists/*

ENV PATH="${PATH}:/root/go/bin"

RUN pip3 install --break-system-packages \
    requests playwright pwntools \
    beautifulsoup4 lxml

RUN playwright install chromium

WORKDIR /workspace
CMD ["tail", "-f", "/dev/null"]
