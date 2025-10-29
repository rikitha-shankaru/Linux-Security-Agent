#!/bin/bash

echo "🍎 Linux Security Agent - macOS Setup"
echo "======================================"

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker Desktop for Mac:"
    echo "   https://www.docker.com/products/docker-desktop/"
    exit 1
fi

# Check if Docker is running
if ! docker info &> /dev/null; then
    echo "❌ Docker is not running. Please start Docker Desktop."
    exit 1
fi

echo "✅ Docker is available"

# Build the Docker image
echo "🔨 Building Docker image..."
docker build -t security-agent .

if [ $? -eq 0 ]; then
    echo "✅ Docker image built successfully"
else
    echo "❌ Failed to build Docker image"
    exit 1
fi

echo ""
echo "🚀 Starting Linux Security Agent..."
echo "   Press Ctrl+C to stop"
echo ""

# Run the security agent
docker run --rm -it \
    --privileged \
    --name security-agent \
    -v /var/log:/var/log:rw \
    -v /proc:/host/proc:ro \
    -v /sys:/host/sys:ro \
    security-agent \
    --dashboard \
    --anomaly-detection \
    --threshold 30
