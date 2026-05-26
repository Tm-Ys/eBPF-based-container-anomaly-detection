#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "========================================"
echo "  eBPF Container Anomaly Detection"
echo "  Environment Setup Script"
echo "========================================"
echo ""

# ----- Install system packages -----
echo "[1/5] Installing system dependencies..."
sudo apt-get update -qq
sudo apt-get install -y -qq \
    clang \
    llvm \
    lld \
    libelf-dev \
    linux-tools-common \
    linux-tools-$(uname -r) \
    python3-pip \
    python3-venv \
    python3-dev \
    cmake \
    pkg-config \
    git

# ----- Check libbpf -----
echo "[2/5] Checking libbpf..."
if pkg-config --atleast-version=1.0 libbpf 2>/dev/null; then
    echo "  libbpf: OK ($(pkg-config --modversion libbpf))"
else
    echo "  Installing libbpf-dev from apt..."
    sudo apt-get install -y -qq libbpf-dev
    if pkg-config --atleast-version=1.0 libbpf 2>/dev/null; then
        echo "  libbpf: OK ($(pkg-config --modversion libbpf))"
    else
        echo "  Building libbpf from source..."
        if [ ! -d /tmp/libbpf ]; then
            git clone --depth 1 --branch v1.4.7 https://github.com/libbpf/libbpf.git /tmp/libbpf
        fi
        make -C /tmp/libbpf/src -j$(nproc)
        sudo make -C /tmp/libbpf/src install
        sudo ldconfig
    fi
fi

# ----- Python virtual environment -----
echo "[3/5] Creating Python virtual environment..."
if [ ! -d ".venv" ]; then
    python3 -m venv .venv
fi

source .venv/bin/activate

echo "[4/5] Installing Python packages..."
pip install -q --upgrade pip setuptools wheel
pip install -q \
    scikit-learn \
    numpy \
    pandas \
    matplotlib \
    psutil

# ----- Build project -----
echo "[5/5] Building BPF programs and loader..."
make clean 2>/dev/null || true
make all

echo ""
echo "========================================"
echo "  Setup complete!"
echo ""
echo "  Quick start:"
echo "    source .venv/bin/activate"
echo "    echo YOUR_PASSWORD | sudo -S .venv/bin/python3 -m src.main"
echo "========================================"
