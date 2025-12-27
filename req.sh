#!/bin/bash
set -e

echo "[+] Aggiornamento repository"
apt update

echo "[+] Installazione toolchain base"
apt install -y \
    build-essential \
    clang \
    llvm \
    make \
    gcc \
    git \
    pkg-config

echo "[+] Installazione headers kernel"
apt install -y \
    linux-headers-$(uname -r)

echo "[+] Installazione librerie BPF / XDP"
apt install -y \
    libbpf-dev \
    libelf-dev \
    zlib1g-dev \
    iproute2 \
    ethtool

echo "[+] Verifica supporto XDP nel kernel"
if zgrep CONFIG_XDP_SOCKETS /proc/config.gz >/dev/null 2>&1; then
    echo "    ✔ CONFIG_XDP_SOCKETS abilitato"
else
    echo "    ⚠ CONFIG_XDP_SOCKETS NON abilitato (AF_XDP non funzionerà)"
fi

echo "[+] Versioni installate:"
echo "    gcc      : $(gcc --version | head -n1)"
echo "    clang    : $(clang --version | head -n1)"
echo "    libbpf   : $(pkg-config --modversion libbpf || echo 'non trovata')"

echo "[+] Setup completato"
echo
echo "➡ Ora puoi fare:"
echo "   make clean && make"
echo
echo "⚠ Nota:"
echo "   AF_XDP funziona SOLO su NIC fisiche con XDP native."
echo "   Su VM (ens160 / xdpgeneric) funzionerà solo UDP normale."
