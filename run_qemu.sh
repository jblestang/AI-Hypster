#!/usr/bin/env bash
set -e

TARGET_MODE="${TARGET_MODE:-B}"

echo "=== Building Hypster Target ${TARGET_MODE}: guest(s) + UEFI loader ==="
rustup target add x86_64-unknown-none x86_64-unknown-uefi 2>/dev/null || true

# Absolute linker script path — relative -Tlinker.ld breaks when cargo is
# invoked from the workspace root rather than crates/vm1-app.
export RUSTFLAGS="-C link-arg=-T${PWD}/crates/vm1-app/linker.ld"
cargo build --target x86_64-unknown-none --release -p vm1-app
objcopy -O binary target/x86_64-unknown-none/release/vm1-app target/x86_64-unknown-none/release/vm1-app.bin

export RUSTFLAGS="-C link-arg=-T${PWD}/crates/vm1-app/linker.ld"
cargo build --target x86_64-unknown-none --release -p vm2-app
objcopy -O binary target/x86_64-unknown-none/release/vm2-app target/x86_64-unknown-none/release/vm2-app.bin

unset RUSTFLAGS
export TARGET_MODE
cargo build --target x86_64-unknown-uefi --release -p hypster-uefi

echo "=== Preparing UEFI boot image ==="
mkdir -p esp/EFI/BOOT
rm -f esp.img
dd if=/dev/zero of=esp.img bs=1M count=64 status=none
/usr/sbin/mkfs.fat -F 32 esp.img >/dev/null
mmd -i esp.img ::/EFI ::/EFI/BOOT 2>/dev/null || true
mcopy -i esp.img target/x86_64-unknown-uefi/release/hypster-uefi.efi ::/EFI/BOOT/BOOTX64.EFI

echo "=== Launching QEMU (KVM + OVMF) ==="
if [ "$TARGET_MODE" = "A" ]; then
  echo "Expect serial output: 'Hello from VM1 guest running under Intel VT-x!'"
else
  echo "Expect serial output: '[HYPSTER] SUCCESS: Dual partitions ran under hardware VT-x'"
fi

OVMF_CODE="${OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}"
OVMF_VARS="${OVMF_VARS:-ovmf_vars.fd}"
cp -n /usr/share/OVMF/OVMF_VARS_4M.fd "$OVMF_VARS" 2>/dev/null || true

KVM_ARGS=()
if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
  KVM_ARGS=(-enable-kvm -cpu host)
else
  echo "WARNING: /dev/kvm unavailable — VMX requires KVM nested virtualization on Linux"
  KVM_ARGS=(-cpu max)
fi

qemu-system-x86_64 \
  "${KVM_ARGS[@]}" \
  -m 512M \
  -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
  -drive if=pflash,format=raw,file="$OVMF_VARS" \
  -drive file=esp.img,format=raw \
  -display none \
  -serial stdio \
  -monitor none \
  -device isa-debug-exit,iobase=0xf4,iosize=0x04
