#!/bin/bash

echo "=== Installing Python Dependencies ==="
echo

# Check if pip is installed
if ! command -v pip3 &> /dev/null; then
    echo "Installing pip..."
    sudo apt-get update
    sudo apt-get install -y python3-pip
fi

echo "Installing Python packages..."
pip3 install --user psutil docker rich numpy scipy scikit-learn

echo
echo "Adding user pip packages to PATH..."
export PATH="$HOME/.local/bin:$PATH"

echo
echo "Verifying installation..."
python3 -c "import psutil; print('✅ psutil')" 2>/dev/null || echo "❌ psutil"
python3 -c "import docker; print('✅ docker')" 2>/dev/null || echo "❌ docker"
python3 -c "import rich; print('✅ rich')" 2>/dev/null || echo "❌ rich"
python3 -c "import numpy; print('✅ numpy')" 2>/dev/null || echo "❌ numpy"
python3 -c "import sklearn; print('✅ sklearn')" 2>/dev/null || echo "❌ sklearn"

echo
echo "=== Done ==="

