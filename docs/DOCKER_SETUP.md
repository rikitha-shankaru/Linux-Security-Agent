# Docker Setup Guide

This guide explains how to set up Docker on your Linux VM to run the security agent in a containerized environment.

## Prerequisites

- Linux VM (Ubuntu/Debian recommended)
- Root or sudo access
- Internet connection

## Quick Installation

Run the installation script:

```bash
# On your VM
cd ~/linux_security_agent
sudo bash scripts/install_docker.sh
```

## Manual Installation

If you prefer to install Docker manually:

### 1. Update Package List

```bash
sudo apt-get update
```

### 2. Install Prerequisites

```bash
sudo apt-get install -y \
    ca-certificates \
    curl \
    gnupg \
    lsb-release
```

### 3. Add Docker's GPG Key

```bash
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
```

### 4. Set Up Docker Repository

```bash
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
```

### 5. Install Docker

```bash
sudo apt-get update
sudo apt-get install -y \
    docker-ce \
    docker-ce-cli \
    containerd.io \
    docker-buildx-plugin \
    docker-compose-plugin
```

### 6. Start Docker Service

```bash
sudo systemctl start docker
sudo systemctl enable docker
```

### 7. Add User to Docker Group (Optional)

```bash
sudo usermod -aG docker $USER
# Log out and back in for changes to take effect
```

## Verify Installation

```bash
docker --version
docker compose version
docker run hello-world
```

## Running the Security Agent in Docker

### Using Docker Compose (Recommended)

```bash
cd ~/linux_security_agent

# Build the image
docker-compose -f docker-compose.auditd.yml build

# Run the agent
docker-compose -f docker-compose.auditd.yml up
```

### Using Docker Run

```bash
# Build the image
docker build -f Dockerfile.auditd -t security-agent:auditd .

# Run the container
docker run --privileged \
  -v /var/log/audit:/var/log/audit:rw \
  -v /proc:/host/proc:ro \
  -v /sys:/host/sys:ro \
  -e COLLECTOR=auditd \
  security-agent:auditd \
  --collector auditd --train-models --dashboard --threshold 30
```

## Troubleshooting

### Permission Denied

If you get permission errors, make sure:
1. Your user is in the `docker` group: `groups`
2. You've logged out and back in after adding to the group
3. Or use `sudo` with docker commands

### Docker Service Not Running

```bash
sudo systemctl status docker
sudo systemctl start docker
```

### Auditd Not Working in Container

Auditd requires direct kernel access. Make sure:
1. Container is running with `--privileged` flag
2. You're on a real Linux host (not Docker Desktop on Mac)
3. Auditd service is started in the container

## Next Steps

After Docker is installed:
1. Build the security agent image
2. Configure auditd rules
3. Run the agent and test with attack simulations

See `docs/DOCKER_TEST_GUIDE.md` for detailed testing instructions.

