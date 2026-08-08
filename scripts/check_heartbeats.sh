#!/usr/bin/env bash
# Prove concurrent endless guests are making progress via shared-memory heartbeats.
# Usage: ./scripts/check_heartbeats.sh
set -euo pipefail
cd "$(dirname "$0")/.."

MONITOR_PORT="${MONITOR_PORT:-4444}"
export TARGET_MODE="${TARGET_MODE:-B}"
export SMP="${SMP:-2}"
export MONITOR_PORT

LOG=$(mktemp)
cleanup() {
  if [[ -n "${QEMU_PID:-}" ]] && kill -0 "$QEMU_PID" 2>/dev/null; then
    kill "$QEMU_PID" 2>/dev/null || true
    wait "$QEMU_PID" 2>/dev/null || true
  fi
  rm -f "$LOG"
}
trap cleanup EXIT

echo "=== Building + launching (monitor :$MONITOR_PORT) ==="
./run_qemu.sh >"$LOG" 2>&1 &
QEMU_PID=$!

echo -n "Waiting for heartbeat HPA"
HB=""
for _ in $(seq 1 90); do
  if ! kill -0 "$QEMU_PID" 2>/dev/null; then
    echo
    echo "QEMU exited early:"; tail -40 "$LOG" | tr -d '\000'
    exit 1
  fi
  HB=$(tr -d '\000' <"$LOG" | sed 's/\x1b\[[0-9;]*[a-zA-Z]//g' \
    | grep -aoE 'heartbeat HPA=0x[0-9A-Fa-f]+' | tail -1 | sed 's/.*HPA=//' || true)
  if [[ -n "$HB" ]]; then
    echo " -> $HB"
    break
  fi
  echo -n .
  sleep 1
done
if [[ -z "$HB" ]]; then
  echo
  echo "No heartbeat HPA in log yet:"; tail -30 "$LOG" | tr -d '\000'
  exit 1
fi

sleep 3

sample() {
  {
    sleep 0.3
    printf '\xff\xfc\x01\xff\xfe\x01\xff\xfc\x03\xff\xfe\x03'
    sleep 0.2
    printf 'xp /5gx %s\r\n' "$HB"
    sleep 0.8
  } | nc -w 3 127.0.0.1 "$MONITOR_PORT" 2>/dev/null \
    | tr -cd '\11\12\15\40-\176' \
    | grep -aoE '[0-9a-fA-F]+:[ \t]+0x[0-9a-fA-F]+.*' \
    | head -3 \
    | tr '\n' ' '
  echo
}

echo "Sample 1:"
S1=$(sample)
echo "  $S1"
sleep 2
echo "Sample 2:"
S2=$(sample)
echo "  $S2"

if [[ -z "$S1" || -z "$S2" ]]; then
  echo "FAIL: empty monitor samples (is nc installed? port $MONITOR_PORT free?)"
  exit 1
fi

python3 - "$S1" "$S2" <<'PY'
import sys, re
def parse(line):
    nums = re.findall(r'0x([0-9a-fA-F]+)', line)
    if len(nums) < 5:
        raise SystemExit(f'bad sample ({len(nums)} hex words): {line!r}')
    return [int(x, 16) for x in nums[:5]]

a = parse(sys.argv[1])
b = parse(sys.argv[2])
magic, c1a, t1a, c2a, t2a = a
magic_b, c1b, t1b, c2b, t2b = b
d1, d2 = c1b - c1a, c2b - c2a
skew = abs(c1b - c2b)
print(f'magic     {magic:#x} (expect 0x4859504245415400)')
print(f'vm1_acked {c1a} -> {c1b}  delta {d1}')
print(f'vm2_acked {c2a} -> {c2b}  delta {d2}')
# Monitor xp tears under multi-MHz exchange; require both rising and
# skew << progress (true deadlock would leave one side flat).
skew_ok = skew <= max(1024, min(d1, d2) // 50)
ok = (
    magic == 0x4859504245415400
    and magic_b == 0x4859504245415400
    and d1 > 0
    and d2 > 0
    and skew_ok
)
if ok:
    print(f'PASS: IPC counter exchange live (skew={skew})')
    sys.exit(0)
print(f'FAIL: need rising lockstep counters (skew={skew})')
sys.exit(1)
PY
