#!/usr/bin/env bash
set -e

echo "=== Building Hypster Static Hypervisor & Bare Metal VMs ==="
cargo build --target x86_64-unknown-none --release -p vm1-app -p vm2-app
llvm-objcopy -O binary target/x86_64-unknown-none/release/vm1-app target/x86_64-unknown-none/release/vm1-app.bin
llvm-objcopy -O binary target/x86_64-unknown-none/release/vm2-app target/x86_64-unknown-none/release/vm2-app.bin
cargo build --target x86_64-unknown-uefi --release -p hypster-uefi

echo "=== Preparing UEFI Boot Directory (ESP) ==="
mkdir -p esp/EFI/BOOT
cp target/x86_64-unknown-uefi/release/hypster-uefi.efi esp/EFI/BOOT/BOOTX64.EFI

echo "=== Creating FAT ESP Image ==="
rm -f esp.img
dd if=/dev/zero of=esp.img bs=1M count=64 status=none
/usr/sbin/mkfs.fat -F 32 esp.img >/dev/null
mmd -i esp.img ::/EFI || true
mmd -i esp.img ::/EFI/BOOT || true
mcopy -o -i esp.img target/x86_64-unknown-uefi/release/hypster-uefi.efi ::/EFI/BOOT/BOOTX64.EFI

echo "=== Host Packet Transmitter: Sending Real Host Packets to VM1 e1000 NIC (port 5557) ==="
(
  sleep 3
  for i in $(seq 1 10); do
    echo "[REAL-HOST-PACKET-#$i] Real Ethernet frame sent from Linux Host via TCP socket to port 5557 -> VM1 e1000 NIC" | nc -w 1 127.0.0.1 5557 2>/dev/null || true
    sleep 0.05
  done
) &

echo "=== Launching QEMU with UEFI (OVMF) & KVM ==="
qemu-system-x86_64 -enable-kvm -cpu host -m 8G -bios /usr/share/ovmf/OVMF.fd -drive file=esp.img,format=raw -display none -serial stdio -monitor none -netdev user,id=net0,hostfwd=tcp::5557-:80 -device e1000,netdev=net0,mac=52:54:00:12:34:56,addr=0x03 -netdev user,id=net1,hostfwd=tcp::5558-:80 -device e1000,netdev=net1,mac=52:54:00:65:43:21,addr=0x04 -device isa-debug-exit,iobase=0xf4,iosize=0x04 || true
