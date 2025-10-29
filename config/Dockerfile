FROM ubuntu:22.04

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-dev \
    bpfcc-tools \
    python3-bpfcc \
    build-essential \
    linux-headers-generic \
    linux-headers-$(uname -r) \
    coreutils \
    findutils \
    procps \
    net-tools \
    nmap \
    kmod \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY . /app
WORKDIR /app

# Install Python dependencies
RUN pip3 install -r requirements.txt

# Set entrypoint
ENTRYPOINT ["python3", "security_agent.py"]
