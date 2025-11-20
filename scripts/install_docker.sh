#!/bin/bash
# Script to install Docker on Linux VM
# Works on Ubuntu/Debian systems

set -e

echo "🐳 Installing Docker on Linux VM..."
echo "===================================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "❌ Please run as root (use sudo)"
    exit 1
fi

# Update package list
echo "📦 Updating package list..."
apt-get update -qq

# Install prerequisites
echo "📦 Installing prerequisites..."
apt-get install -y -qq \
    ca-certificates \
    curl \
    gnupg \
    lsb-release

# Add Docker's official GPG key
echo "🔑 Adding Docker GPG key..."
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg

# Set up Docker repository
echo "📦 Setting up Docker repository..."
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null

# Update package list again
apt-get update -qq

# Install Docker Engine
echo "🐳 Installing Docker Engine..."
apt-get install -y -qq \
    docker-ce \
    docker-ce-cli \
    containerd.io \
    docker-buildx-plugin \
    docker-compose-plugin

# Start Docker service
echo "🚀 Starting Docker service..."
systemctl start docker
systemctl enable docker

# Add current user to docker group (if not root)
if [ -n "$SUDO_USER" ]; then
    echo "👤 Adding $SUDO_USER to docker group..."
    usermod -aG docker "$SUDO_USER"
    echo "✅ User $SUDO_USER added to docker group"
    echo "⚠️  You may need to log out and back in for group changes to take effect"
fi

# Verify installation
echo ""
echo "✅ Docker installation complete!"
echo ""
echo "🔍 Verifying installation..."
docker --version
docker compose version

echo ""
echo "🎉 Docker is ready to use!"
echo ""
echo "💡 Next steps:"
echo "   1. If you added a user to docker group, log out and back in"
echo "   2. Test Docker: docker run hello-world"
echo "   3. Build security agent image: docker-compose -f docker-compose.auditd.yml build"
echo "   4. Run security agent: docker-compose -f docker-compose.auditd.yml up"

