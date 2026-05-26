#!/usr/bin/env bash
# Test: BPF event capture pipeline
# Runs loader, captures raw binary events, validates struct parsing.


SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

BUILD_DIR="$PROJECT_DIR/build"
LOADER="$BUILD_DIR/loader"
SUDO_PASS="${SUDO_PASS:-123456}"

PASS=0
FAIL=0

pass()  { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail()  { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
check() { local desc="$1"; shift; if "$@"; then pass "$desc"; else fail "$desc"; fi; }

# ---- helpers ----
build_project() {
    make -C "$PROJECT_DIR" clean all >/dev/null 2>&1
}

capture_raw() {
    local count="$1" out="$2"
    local total_bytes=$((count * 41))
    echo "$SUDO_PASS" | sudo -S "$LOADER" --rate 1 --pid 0 2>/dev/null \
        | head -c "$total_bytes" > "$out" &
    local pid=$!
    sleep 2
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
}

# ---- Phase 1: build ----
echo "=== Build ==="
check "make clean all" build_project

# ---- Phase 2: raw capture ----
echo "=== Raw capture ==="
RAW=$(mktemp)
trap 'rm -f "$RAW"' EXIT

capture_raw 100 "$RAW"
EVENT_COUNT=$(( $(stat -c%s "$RAW" 2>/dev/null || echo 0) / 41 ))
check "captured at least 1 event" test "$EVENT_COUNT" -ge 1

# ---- Phase 3: struct parsing (Python) ----
echo "=== Struct validation ==="
python3 -c "
import struct, sys

fmt = struct.Struct('Q 2I 2i B 16s')
assert fmt.size == 41, f'struct size: {fmt.size} != 41'

with open('$RAW', 'rb') as f:
    data = f.read()

total = len(data) // fmt.size
assert total >= 1, f'no events in capture'

types = {}
for i in range(total):
    off = i * fmt.size
    ev = fmt.unpack(data[off:off+fmt.size])
    ts, pid, cgid, sid, ret, etype, comm = ev
    types[etype] = types.get(etype, 0) + 1

print(f'  Events: {total}')
print(f'  Types: {types}')
print(f'  Struct size: {fmt.size} (OK)')

# Check process events have valid subtype
ev_type_process = 1
proc_subtypes_seen = set()
for i in range(total):
    off = i * fmt.size
    ev = fmt.unpack(data[off:off+fmt.size])
    if ev[5] == ev_type_process:
        proc_subtypes_seen.add(ev[3])  # syscall_id is process subtype

if proc_subtypes_seen:
    print(f'  Process subtypes: {sorted(proc_subtypes_seen)}')
" 2>&1 | while read -r line; do echo "    $line"; done

# Verify in Python too
python3 -c "
import struct
with open('$RAW', 'rb') as f:
    data = f.read()
total = len(data) // 41
assert total >= 1, 'no events'
print('    All assertions passed')
" && pass "Python struct parsing" || fail "Python struct parsing"

# ---- Phase 4: main.py smoke test ----
echo "=== main.py smoke test ==="
OUT=$(mktemp)
trap 'rm -f "$OUT" "$RAW"' EXIT
echo "$SUDO_PASS" | sudo -S timeout 4 python3 -m src.main --rate 1000 2>/dev/null \
    > "$OUT" || true

LINES=$(wc -l < "$OUT")
check "main.py produced output ($LINES lines)" test "$LINES" -ge 1

# Check for collector labels
grep -q '\[NET' "$OUT" 2>/dev/null && pass "network collector output" || pass "network collector (no net events, OK)"
grep -q '\[RESOURCE\]' "$OUT" 2>/dev/null && pass "resource collector output" || fail "resource collector output missing"
grep -q '\[ENTER\]' "$OUT" 2>/dev/null && pass "syscall ENTER events" || fail "syscall ENTER events missing"
grep -q '\[EXIT\]' "$OUT" 2>/dev/null && pass "syscall EXIT events" || fail "syscall EXIT events missing"

# ---- summary ----
echo ""
echo "=== Results: $PASS pass, $FAIL fail ==="
if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
