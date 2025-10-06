#!/bin/bash

echo "🐳 Docker Linux Security Agent Demo"
echo "===================================="
echo ""

# Check if Docker is running
if ! docker info &> /dev/null; then
    echo "❌ Docker is not running. Please start Docker Desktop."
    echo "   Run: open -a Docker"
    exit 1
fi

echo "✅ Docker is running"
echo ""

# Check if image exists
if ! docker images | grep -q security-agent; then
    echo "🔨 Building Docker image..."
    docker build -t security-agent .
    
    if [ $? -ne 0 ]; then
        echo "❌ Failed to build Docker image"
        exit 1
    fi
    
    echo "✅ Docker image built successfully"
else
    echo "✅ Docker image already exists"
fi

echo ""
echo "🚀 Starting Linux Security Agent with eBPF..."
echo ""

# Run the security agent
docker run --rm --privileged security-agent --dashboard --threshold 30
