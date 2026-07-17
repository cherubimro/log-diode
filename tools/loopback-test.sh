#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# End-to-end loopback: syslog/UDP -> ld_amp -> diode UDP -> ld_deamp -> syslog/UDP.
# Verifies log lines cross byte-identical (cleartext, encrypted, batched), that
# the severity gate drops low-priority lines, and that a wrong key drops everything.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$here/env.sh"
cd "$here/.."

command -v python3 >/dev/null 2>&1 || { echo "loopback-test needs python3; skipping"; exit 0; }
gprbuild -q -P log_diode.gpr >/dev/null 2>&1 || { echo "build failed"; exit 1; }

TMP="$(mktemp -d)"; PIDS=()
cleanup () { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done; rm -rf "$TMP"; }
trap cleanup EXIT

AMP_IN=9514; DIODE=9602; OUT=9714
KEY=$(printf '%064d' 0 | tr '0' 'a')

# A persistent UDP sink on $OUT: append each received datagram (as a line) to
# the file named in $TMP/sinkfile.  Restarted per case by pointing sinkfile.
python3 - "$OUT" "$TMP/sinkfile" <<'PY' &
import socket, sys
port, ctrl = int(sys.argv[1]), sys.argv[2]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', port)); s.settimeout(0.2)
while True:
    try: d,_ = s.recvfrom(65535)
    except socket.timeout: continue
    except OSError: break
    try: out = open(ctrl).read().strip()
    except OSError: continue
    if out:
        with open(out, 'ab') as f: f.write(d + b'\n')
PY
SINK=$!; PIDS+=("$SINK"); disown "$SINK" 2>/dev/null || true

send_lines () {  # $@ = lines
    python3 - "$AMP_IN" "$@" <<'PY'
import socket, sys, time
port = int(sys.argv[1])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for line in sys.argv[2:]:
    s.sendto(line.encode(), ('127.0.0.1', port)); time.sleep(0.03)
PY
}

run_case () {  # $1=label  $2=keyarg  $3=ampextra ; sets global OUTFILE
    local label="$1" keyarg="$2" extra="$3"
    OUTFILE="$TMP/out_$label"; : > "$OUTFILE"
    ./bin/ld_deamp "$DIODE" 127.0.0.1 "$OUT" $keyarg 2>"$TMP/deamp_$label.log" &
    local dp=$!; PIDS+=("$dp"); disown "$dp" 2>/dev/null || true
    ./bin/ld_amp "$AMP_IN" 127.0.0.1 "$DIODE" $keyarg $extra --pace-us 150 --flush-ms 300 \
        2>"$TMP/amp_$label.log" &
    local ap=$!; PIDS+=("$ap"); disown "$ap" 2>/dev/null || true
    sleep 0.6
    echo "$OUTFILE" > "$TMP/sinkfile"     # route sink output here
    sleep 0.2
    shift 3
    send_lines "$@"
    sleep 2.5
    echo "" > "$TMP/sinkfile"             # stop routing
    kill "$ap" "$dp" 2>/dev/null
    sleep 0.2
}

RC=0
has () { grep -qF "$2" "$1" 2>/dev/null; }

echo "== cleartext =="
run_case clear "" "" "<13>alpha clear" "<134>bravo clear" "<10>charlie clear"
for l in "<13>alpha clear" "<134>bravo clear" "<10>charlie clear"; do
    has "$TMP/out_clear" "$l" || { echo "  MISSING: $l"; RC=1; }
done
has "$TMP/out_clear" "<13>alpha clear" && has "$TMP/out_clear" "<10>charlie clear" \
    && echo "  PASS (byte-identical)"

echo "== encrypted =="
run_case enc "--key $KEY" "" "<13>alpha enc" "<134>bravo enc" "<10>charlie enc"
ec=0; for l in "<13>alpha enc" "<134>bravo enc" "<10>charlie enc"; do
    has "$TMP/out_enc" "$l" || { echo "  MISSING: $l"; ec=1; RC=1; }
done
[ "$ec" = 0 ] && echo "  PASS (byte-identical, AEAD)"

echo "== batched (--batch 4, encrypted) =="
run_case batch "--key $KEY" "--batch 4" "<13>a batch" "<134>b batch" "<10>c batch" "<9>d batch"
bc=0; for l in "<13>a batch" "<134>b batch" "<10>c batch" "<9>d batch"; do
    has "$TMP/out_batch" "$l" || { echo "  MISSING: $l"; bc=1; RC=1; }
done
[ "$bc" = 0 ] && echo "  PASS (4/4 recovered from one batch)"

echo "== severity gate (--min-severity 4) =="
run_case gate "" "--min-severity 4" "<13>notice gate" "<134>info gate" "<10>crit gate"
if has "$TMP/out_gate" "<10>crit gate" \
   && ! has "$TMP/out_gate" "<13>notice gate" \
   && ! has "$TMP/out_gate" "<134>info gate"; then
    echo "  PASS (crit passed, notice+info dropped)"
else echo "  FAIL (gate)"; RC=1; fi

echo "== wrong key dropped =="
OUTFILE="$TMP/out_bad"; : > "$OUTFILE"
BADKEY=$(printf '%064d' 0 | tr '0' 'b')
./bin/ld_deamp "$DIODE" 127.0.0.1 "$OUT" --key "$BADKEY" 2>/dev/null &
dp=$!; PIDS+=("$dp"); disown "$dp" 2>/dev/null || true
./bin/ld_amp "$AMP_IN" 127.0.0.1 "$DIODE" --key "$KEY" --pace-us 150 2>/dev/null &
ap=$!; PIDS+=("$ap"); disown "$ap" 2>/dev/null || true
sleep 0.6; echo "$OUTFILE" > "$TMP/sinkfile"; sleep 0.2
send_lines "<13>should not arrive"
sleep 2.5; echo "" > "$TMP/sinkfile"; kill "$ap" "$dp" 2>/dev/null
if [ -s "$TMP/out_bad" ]; then echo "  FAIL (a line arrived under wrong key!)"; RC=1
else echo "  PASS (wrong key -> nothing written)"; fi

echo
[ "$RC" = 0 ] && echo ">>> LOG LOOPBACK PASSED" || echo ">>> LOG LOOPBACK FAILED"
exit $RC
