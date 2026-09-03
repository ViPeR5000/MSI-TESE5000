#!/usr/bin/env bash
# run.sh — repeat the 1 GiB vault encryption benchmark N times and save one JSON
# per run. Both ciphers in C, same I/O regime -> fair cross-cipher comparison:
#   Bravo   = ASCON-128     (ascon_bench.c, scalar C)
#   Charlie = AES-128-GCM   (aes_bench.c, OpenSSL EVP -> ARMv8-A AES)
#
#   bash run.sh all       # both ciphers on THIS host (hardware-controlled compare)
#   bash run.sh bravo | charlie
#   args: run.sh <all|bravo|charlie> [runs=5] [infile=/root/vault.txt]
#
# WARM=1 (default): prime the file into the page cache, no drop_caches, no fsync
#   -> reads/writes hit RAM, so the number reflects the CIPHER (matches the
#      original benchmarks.md methodology). WARM=0: drop caches each run (SD-bound,
#      end-to-end). The chosen mode is recorded in each JSON.
set -euo pipefail
cd "$(dirname "$0")"

WHICH="${1:?usage: run.sh <all|bravo|charlie> [runs] [infile]}"
RUNS="${2:-5}"
INFILE="${3:-/root/vault.txt}"
WARM="${WARM:-1}"
KEY="393a58192a69b6483cc0ec89d27e30f6"          # SHA-256("viper5000")[:16]
# MEM=<MiB>: in-memory cipher-throughput mode (no file I/O) — isolates the cipher
# on the CPU (the 1 GiB file benchmark is SD-bound on a Pi and cannot). Both C only.
MEM="${MEM:-}"
if [ -n "$MEM" ]; then MODE=mem; MEMBYTES=$((MEM*1048576))
else [ -f "$INFILE" ] || { echo "missing input: $INFILE" >&2; exit 1; }
     OUT="$(dirname "$INFILE")/.vault.bench.out"; MODE=$([ "$WARM" = 1 ] && echo warm || echo cold); fi
RESULTS="results-1gb"; mkdir -p "$RESULTS"

drop_caches(){ sync; { echo 3 >/proc/sys/vm/drop_caches; } 2>/dev/null \
               || sudo sh -c 'echo 3 >/proc/sys/vm/drop_caches' 2>/dev/null || true; }

build_aes_c(){   # 0 on success, aes_bench built (always rebuild -> avoid stale binary)
  gcc -O2 -o aes_bench aes_bench.c -lcrypto 2>/dev/null && return 0
  { apt-get install -y libssl-dev >/dev/null 2>&1 || sudo apt-get install -y libssl-dev >/dev/null 2>&1; } || true
  gcc -O2 -o aes_bench aes_bench.c -lcrypto 2>/dev/null && return 0
  return 1
}
resolve_pyc(){   # fallback only: a python that can import cryptography
  for p in python3 /home/pi/*/venv/bin/python3 /home/*/*/venv/bin/python3 /opt/*/venv/bin/python3; do
    "$p" -c 'import cryptography' 2>/dev/null && { echo "$p"; return; }
  done
  python3 -m venv /tmp/bench_venv >/dev/null 2>&1 \
    && /tmp/bench_venv/bin/pip -q install cryptography >/dev/null 2>&1 \
    && { echo /tmp/bench_venv/bin/python3; return; }
  echo ""
}

run_phase(){
  local phase="$1" cmd bin
  case "$phase" in
    bravo)   gcc -O2 -o ascon_bench ascon_bench.c   # always rebuild (avoid stale binary)
             bin=./ascon_bench ;;
    charlie) if build_aes_c; then bin=./aes_bench
             elif [ -z "$MEM" ]; then local pyc; pyc="$(resolve_pyc)"
                  [ -n "$pyc" ] || { echo "no AES backend (no libssl-dev, no python cryptography) — skipping charlie" >&2; return 1; }
                  echo "  [note] AES falling back to Python ($pyc)"; "$pyc" aes_bench.py --selftest
                  bin="$pyc aes_bench.py"
             else echo "mem mode needs the C AES (libssl-dev) — skipping charlie" >&2; return 1; fi ;;
  esac
  if [ -n "$MEM" ]; then cmd=($bin "$KEY" --mem "$MEMBYTES")
  else cmd=($bin "$KEY" "$INFILE" "$OUT"); fi
  [ -z "$MEM" ] && [ "$WARM" = 1 ] && { echo -n "  priming cache ... "; cat "$INFILE" >/dev/null 2>&1 || true; echo ok; }
  echo "== phase=$phase mode=$MODE runs=$RUNS $([ -n "$MEM" ] && echo "size=${MEM}MiB(RAM)" || echo "input=$INFILE") =="
  local i raw
  for i in $(seq 1 "$RUNS"); do
    [ "$WARM" = 1 ] || drop_caches
    echo -n "  run $i/$RUNS ... "
    raw="$("${cmd[@]}")"
    echo "$raw" | python3 -c "import json,sys,socket,datetime; \
d=json.load(sys.stdin); d.update(phase='$phase',run=$i,mode='$MODE',host=socket.gethostname(), \
ts=datetime.datetime.now().isoformat(timespec='seconds')); \
open('$RESULTS/$phase-run$i.json','w').write(json.dumps(d,indent=2))"
    echo "$raw"
  done
  rm -f "${OUT:-}"
  python3 - "$RESULTS" "$phase" <<'PY'
import json,sys,glob,statistics
d,phase=sys.argv[1],sys.argv[2]
fs=sorted(glob.glob(f"{d}/{phase}-run*.json"))
t=[json.load(open(f))["throughput_MBps"] for f in fs]; s=[json.load(open(f))["time_s"] for f in fs]
print(f"  {phase}: n={len(t)}  time {statistics.mean(s):.3f}s (±{statistics.pstdev(s):.3f})  "
      f"throughput {statistics.mean(t):.2f} MB/s (±{statistics.pstdev(t):.2f})")
PY
}

case "$WHICH" in
  all)     run_phase bravo; run_phase charlie ;;
  bravo)   run_phase bravo ;;
  charlie) run_phase charlie ;;
  *) echo "first arg must be all|bravo|charlie" >&2; exit 1 ;;
esac
echo "== done ($MODE) — JSON in $RESULTS/ (host $(hostname)); copy back to results/1gb/ =="
