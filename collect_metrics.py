#!/usr/bin/env python3
"""
collect_metrics.py — MSI-TESE: 20 metrics × 3 phases (Alpha | Bravo | Charlie)

Sources per metric:
  InfluxDB telemetry  → latency, jitter, throughput, loss, deadline, energy, ram, aead_cpu_us
  Server /monitor     → handshake counter, algorithm names
  KEX benchmark       → PQC/ECDH handshake time (live timing)
  Computed formula    → ciphertext expansion ratio (ASCON / AES-GCM wire format)
  Filesystem          → firmware .ino.bin sizes
  Suricata eve.json   → IDS TPR / FPR / FNR       (--suricata-log)
  C2 loot directory   → Data Utility entropy score (--alpha-loot / --bravo-loot / --charlie-loot)
  C2 log file         → Exfiltration Success Rate  (--c2-log)
  psutil (local)      → gateway CPU % / RAM %
  HTTP ping           → System Availability
  CLI args / manual   → max sessions, recovery time, cmd violations

Usage:
  pip install requests influxdb-client cryptography
  python3 collect_metrics.py [--window 1h] [--runs 20] [--no-benchmark]
  python3 collect_metrics.py --suricata-log /var/log/suricata/eve.json \\
                              --alpha-loot /opt/c2/loot/alpha \\
                              --bravo-loot /opt/c2/loot/bravo \\
                              --charlie-loot /opt/c2/loot/charlie \\
                              --total-attacks 50 --total-legitimate 200
"""
import argparse, base64, csv, json, math, os, statistics, sys, time, warnings
from datetime import datetime
from pathlib import Path

warnings.filterwarnings("ignore")

try:
    import requests
    from influxdb_client import InfluxDBClient
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
except ImportError as e:
    sys.exit(f"Dependência em falta: {e}\n  pip install requests influxdb-client cryptography")

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


# ── Defaults ───────────────────────────────────────────────────────────────────
ALPHA_INFLUX   = "http://192.168.100.100:8086"
BRAVO_INFLUX   = "http://192.168.20.100:8086"
CHARLIE_INFLUX = "http://192.168.30.100:8086"
BRAVO_SERVER   = "http://192.168.20.200:8000"
CHARLIE_SERVER = "http://192.168.30.200:8000"
INFLUX_TOKEN   = "my-super-secret-auth-token-12345678"
INFLUX_ORG     = "msi-tese"
INFLUX_BUCKET  = "telemetry"
REPO_ROOT      = Path(__file__).parent


# ── A: InfluxDB ────────────────────────────────────────────────────────────────
def influx_mean(client, field, phase=None, window="1h", measurement="telemetry_performance"):
    pf = f'|> filter(fn: (r) => r["phase"] == "{phase}")' if phase else ""
    q = f"""
from(bucket: "{INFLUX_BUCKET}")
  |> range(start: -{window})
  |> filter(fn: (r) => r["_measurement"] == "{measurement}" and r["_field"] == "{field}")
  {pf}
  |> mean()
"""
    try:
        vals = [r.get_value() for t in client.query_api().query(q) for r in t.records]
        return round(statistics.mean(vals), 4) if vals else None
    except Exception:
        return None


def collect_influx(url, phase_tag, window):
    c  = InfluxDBClient(url=url, token=INFLUX_TOKEN, org=INFLUX_ORG)
    pt = None if phase_tag in ("alpha", None) else phase_tag
    is_alpha   = phase_tag == "alpha"
    is_charlie = phase_tag == "charlie"
    cpu_field  = None if is_alpha else ("aead_cpu_us" if is_charlie else "lwc_cpu_us")
    ram_field  = None if is_alpha else ("aead_ram_kb" if is_charlie else "lwc_ram_kb")
    m = lambda f: influx_mean(c, f, pt, window)
    return {
        "avg_lat_ms":     m("avg_lat_ms"),
        "jitter_ms":      m("jitter_ms"),
        "throughput_bps": m("throughput_bps"),
        "loss_pct":       m("loss_pct"),
        "deadline_pct":   m("deadline_pct"),
        "energy_mj":      m("energy_mj"),
        "aead_cpu_us":    m(cpu_field) if cpu_field else 0,
        "aead_ram_kb":    m(ram_field) if ram_field else 0,
        "ram_mb":         m("ram_mb"),
        "cpu_pct_gw":     m("cpu_pct"),   # gateway CPU% if bridge writes it
        "cmd_violations": m("cmd_violations"),
    }


# ── B: Server /monitor ────────────────────────────────────────────────────────
def server_stats(url, phase):
    try:
        d = requests.get(f"{url}/monitor", timeout=5, verify=False).json()
        return {"handshake_counter": d.get("handshake_counter"),
                "kex_algorithm": d.get("kem_algorithm" if phase == "bravo" else "kex_algorithm", "—"),
                "sig_algorithm": d.get("sig_algorithm", "—"),
                "availability":  True}
    except Exception as e:
        print(f"  [WARN] {url}/monitor: {e}", file=sys.stderr)
        return {"availability": False}


def check_availability(urls, n=5):
    """Ping URLs n times, return success % per URL."""
    results = {}
    for url in urls:
        ok = 0
        for _ in range(n):
            try:
                requests.get(url, timeout=2, verify=False)
                ok += 1
            except Exception:
                pass
            time.sleep(0.2)
        results[url] = round(ok / n * 100, 1)
    return results


# ── B: KEX Benchmark ──────────────────────────────────────────────────────────
def _p384_pub_b64():
    priv = ec.generate_private_key(ec.SECP384R1())
    raw  = priv.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    return base64.b64encode(raw).decode()


def benchmark_kex(phase, url, n):
    if phase == "alpha":
        return None, None
    ep      = "/kem/encapsulate" if phase == "bravo" else "/kex/exchange"
    payload = {"node_id": "BENCHMARK"}
    if phase == "charlie":
        payload["client_pub_b64"] = _p384_pub_b64()
    times, ok = [], 0
    for i in range(n):
        if phase == "charlie":
            payload["client_pub_b64"] = _p384_pub_b64()
        try:
            t0 = time.perf_counter()
            r  = requests.post(f"{url}{ep}", json=payload, timeout=15, verify=False)
            ms = (time.perf_counter() - t0) * 1000
            if r.ok: times.append(ms); ok += 1
        except Exception as e:
            print(f"  [WARN] {phase} run {i+1}: {e}", file=sys.stderr)
        sys.stdout.write(f"\r  {phase}: {i+1}/{n}  "); sys.stdout.flush()
    print()
    return (round(statistics.mean(times), 2) if times else None,
            round(statistics.stdev(times), 2) if len(times) > 1 else 0.0)


# ── C: Ciphertext Expansion Ratio ─────────────────────────────────────────────
def expansion_ratios(plaintext_bytes=120):
    """MQTT wire payload size / plaintext size, including base64 encoding."""
    p = plaintext_bytes
    bravo_wire   = math.ceil((p + 32) * 4 / 3)   # nonce(16)+ct(p)+tag(16) → base64
    charlie_wire = math.ceil((p + 28) * 4 / 3)   # iv(12)+ct(p)+tag(16) → base64
    return {"alpha": 1.0,
            "bravo": round(bravo_wire / p, 3),
            "charlie": round(charlie_wire / p, 3)}


# ── D: Firmware Sizes ─────────────────────────────────────────────────────────
def firmware_sizes():
    """Return {alpha_kb, bravo_kb, charlie_kb}. None if not compiled."""
    def find_bin(pattern):
        hits = list(REPO_ROOT.rglob(pattern))
        return hits[0] if hits else None

    alpha   = find_bin("esp32-dadoscineticos.ino.bin")
    bravo   = find_bin("Secure-KineticNode.ino.bin")
    charlie = find_bin("Charlie-KineticNode.ino.bin")

    def kb(p): return round(p.stat().st_size / 1024, 1) if p else None

    ak, bk, ck = kb(alpha), kb(bravo), kb(charlie)
    return {"alpha_kb": ak, "bravo_kb": bk, "charlie_kb": ck,
            "bravo_overhead_kb": round(bk - ak, 1) if ak and bk else None,
            "charlie_overhead_kb": round(ck - ak, 1) if ak and ck else None}


# ── E: Suricata IDS ───────────────────────────────────────────────────────────
def parse_suricata(log_path, total_attacks=None, total_legitimate=None,
                   attack_start=None, attack_end=None):
    """Returns (tpr, fpr, fnr) from Suricata eve.json. All None if log absent."""
    if not log_path or not os.path.exists(log_path):
        return None, None, None
    atk_alerts, norm_alerts = 0, 0
    try:
        with open(log_path) as f:
            for line in f:
                try:
                    evt = json.loads(line)
                    if evt.get("event_type") != "alert":
                        continue
                    ts = evt.get("timestamp", "")
                    if attack_start and attack_end:
                        if attack_start <= ts[:len(attack_start)] <= attack_end:
                            atk_alerts += 1
                        else:
                            norm_alerts += 1
                    else:
                        atk_alerts += 1
                except Exception:
                    pass
    except Exception as e:
        print(f"  [WARN] Suricata log: {e}", file=sys.stderr)
        return None, None, None

    tpr = round(atk_alerts / total_attacks * 100, 1) if total_attacks else None
    fnr = round(100 - tpr, 1) if tpr is not None else None
    fpr = round(norm_alerts / total_legitimate * 100, 1) if total_legitimate else None
    return tpr, fpr, fnr


# ── F: Data Utility (C2 loot entropy) ────────────────────────────────────────
def _file_entropy(path):
    data = open(path, "rb").read(4096)
    if not data: return 0.0
    counts = [0] * 256
    for b in data: counts[b] += 1
    n = len(data)
    return -sum((c/n)*math.log2(c/n) for c in counts if c)

def assess_loot(loot_dir):
    """Score: 0=encrypted (H>7), 1=partial (H 4-7), 2=plaintext (H<4). Returns avg."""
    if not loot_dir or not os.path.isdir(loot_dir):
        return None
    scores = []
    for f in Path(loot_dir).iterdir():
        if f.is_file():
            try:
                h = _file_entropy(f)
                scores.append(2 if h < 4.0 else (1 if h < 7.0 else 0))
            except Exception:
                pass
    return round(statistics.mean(scores), 2) if scores else None


# ── G: Exfiltration Success Rate ──────────────────────────────────────────────
def parse_c2_log(log_path):
    """Grep C2 log for HTTP POST 200 vs total POST attempts."""
    if not log_path or not os.path.exists(log_path):
        return None
    total = ok = 0
    try:
        with open(log_path) as f:
            for line in f:
                if "POST" in line:
                    total += 1
                    if " 200 " in line or "200 OK" in line:
                        ok += 1
    except Exception as e:
        print(f"  [WARN] C2 log: {e}", file=sys.stderr)
        return None
    return round(ok / total * 100, 1) if total else None


# ── H: Gateway CPU / RAM ──────────────────────────────────────────────────────
def gateway_cpu_ram(interval=3):
    if not HAS_PSUTIL:
        return None, None
    cpu = psutil.cpu_percent(interval=interval)
    ram = psutil.virtual_memory().percent
    return round(cpu, 1), round(ram, 1)


# ── Output ────────────────────────────────────────────────────────────────────
N = "N/A"

def _f(v, unit="", d=2):
    if v is None: return N
    if v == 0 and unit == " µs": return f"0{unit}"
    return f"{round(v, d)}{unit}"

def _r(base, val):
    try:
        if base in (None, 0) or val is None: return N
        return f"{val/base:.2f}×"
    except Exception:
        return N

def print_table(a, b, c, av, bv, cv,
                bs, cs, avail,
                fw, exp, ids, exfil_pct,
                gw_cpu, gw_ram, args):
    W = 80
    b_hs, b_hs_std = bv
    c_hs, c_hs_std = cv

    def row(label, unit, av_, bv_, cv_):
        print(f"  {label:<38} {_f(av_,unit):<12} {_f(bv_,unit):<12} {_f(cv_,unit):<12}"
              f" {_r(av_,bv_):>6}  {_r(av_,cv_):>6}")

    print("\n" + "═"*W)
    print("  MSI-TESE — Alpha (sem cripto) | Bravo (PQC) | Charlie (Clássico)")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  |  janela InfluxDB: {args.window}")
    print("═"*W)
    print(f"  {'Métrica':<38} {'Alpha':^12} {'Bravo PQC':^12} {'Charlie CL':^12} {'B/A':>6}  {'C/A':>6}")

    print("─"*W)
    print("  ▸ SEGURANÇA")
    data_u = (assess_loot(args.alpha_loot),
              assess_loot(args.bravo_loot),
              assess_loot(args.charlie_loot))
    if any(v is not None for v in data_u):
        row("  Data Utility After Exfiltration", " /2",  *data_u)
    else:
        print(f"  {'  Data Utility After Exfiltration':<38} {'(manual — ver loot dir)'}")
    exfil_a = parse_c2_log(getattr(args, "alpha_c2_log", None))
    exfil_b = parse_c2_log(getattr(args, "bravo_c2_log", None))
    exfil_c = parse_c2_log(getattr(args, "charlie_c2_log", None))
    row("  Exfiltration Success Rate",       " %",  exfil_a, exfil_b, exfil_c)
    row("  Command Integrity Violations",    "",
        a.get("cmd_violations"), b.get("cmd_violations"), c.get("cmd_violations"))
    ids_tpr, ids_fpr, ids_fnr = ids
    row("  IDS Detection Rate (TPR)",        " %",  None, ids_tpr, ids_tpr)
    row("  IDS False Positive Rate (FPR)",   " %",  None, ids_fpr, ids_fpr)
    row("  IDS False Negative Rate (FNR)",   " %",  None, ids_fnr, ids_fnr)
    row("  Recovery Time After Attack",      " s",  None, args.recovery_time, args.recovery_time)

    print("─"*W)
    print("  ▸ DESEMPENHO TEMPORAL")
    row("  Telemetry Transmission Latency",  " ms", a["avg_lat_ms"],  b["avg_lat_ms"],  c["avg_lat_ms"])
    row("  Latency Jitter",                  " ms", a["jitter_ms"],   b["jitter_ms"],   c["jitter_ms"])
    row("  PQC/KEX Handshake Time (média)",  " ms", None,             b_hs,             c_hs)
    row("  PQC/KEX Handshake Time (σ)",      " ms", None,             b_hs_std,         c_hs_std)
    row("  Real-Time Deadline Violation",    " %",  a["deadline_pct"],b["deadline_pct"],c["deadline_pct"])

    print("─"*W)
    print("  ▸ OVERHEAD CRIPTOGRÁFICO")
    row("  Ciphertext Expansion Ratio",      "×",   exp["alpha"],     exp["bravo"],     exp["charlie"])
    row("  CPU Encriptação ESP32",           " µs", a["aead_cpu_us"], b["aead_cpu_us"], c["aead_cpu_us"])
    gw_a_cpu = gw_cpu[0] if gw_cpu else None
    row("  CPU Gateway (durante cifra)",     " %",  gw_a_cpu,         gw_a_cpu,         gw_a_cpu)
    row("  RAM Gateway",                     " MB", a["ram_mb"],      b["ram_mb"],      c["ram_mb"])
    row("  RAM Cripto ESP32",                " KB", a["aead_ram_kb"], b["aead_ram_kb"], c["aead_ram_kb"])
    row("  Firmware Size",                   " KB", fw["alpha_kb"],   fw["bravo_kb"],   fw["charlie_kb"])
    row("  Firmware Overhead vs Alpha",      " KB", 0,                fw["bravo_overhead_kb"], fw["charlie_overhead_kb"])

    print("─"*W)
    print("  ▸ ENERGIA / REDE")
    row("  Energy Consumption per Session",  " mJ", a["energy_mj"],      b["energy_mj"],      c["energy_mj"])
    row("  Network Throughput",              " B/s",a["throughput_bps"], b["throughput_bps"], c["throughput_bps"])
    row("  Packet Loss Rate",               " %",  a["loss_pct"],        b["loss_pct"],        c["loss_pct"])
    row("  Max Secure Session Capacity",    "",    None,                  args.max_sessions,    args.max_sessions)
    avl_b = avail.get(args.bravo_server)
    avl_c = avail.get(args.charlie_server)
    row("  System Availability Under Load", " %",  None, avl_b, avl_c)

    print("═"*W)
    print(f"  Algoritmo KEX: Alpha=nenhum | Bravo={bs.get('kex_algorithm','Kyber768')} | Charlie={cs.get('kex_algorithm','ECDH-secp384r1')}")
    print(f"  Algoritmo SIG: Alpha=nenhum | Bravo={bs.get('sig_algorithm','Dilithium3')} | Charlie={cs.get('sig_algorithm','ECDSA-secp384r1')}")
    print(f"  Handshakes: Bravo={bs.get('handshake_counter','N/A')} | Charlie={cs.get('handshake_counter','N/A')}")
    print()


def export_csv(a, b, c, bv, cv, fw, exp, ids, avail, args, filename):
    b_hs, b_hs_std = bv
    c_hs, c_hs_std = cv
    ids_tpr, ids_fpr, ids_fnr = ids
    avl_b = avail.get(args.bravo_server)
    avl_c = avail.get(args.charlie_server)

    def r(base, val):
        try: return round(val/base, 4) if base not in (None, 0) and val is not None else None
        except: return None

    rows = [
        ("data_utility_score",         None,               None,                None),
        ("exfiltration_success_pct",   None,               None,                None),
        ("cmd_integrity_violations",   a.get("cmd_violations"), b.get("cmd_violations"), c.get("cmd_violations")),
        ("ids_tpr_pct",                None,               ids_tpr,             ids_tpr),
        ("ids_fpr_pct",                None,               ids_fpr,             ids_fpr),
        ("ids_fnr_pct",                None,               ids_fnr,             ids_fnr),
        ("recovery_time_s",            None,               args.recovery_time,  args.recovery_time),
        ("avg_latency_ms",             a["avg_lat_ms"],    b["avg_lat_ms"],     c["avg_lat_ms"]),
        ("jitter_ms",                  a["jitter_ms"],     b["jitter_ms"],      c["jitter_ms"]),
        ("kex_handshake_mean_ms",      None,               b_hs,                c_hs),
        ("kex_handshake_std_ms",       None,               b_hs_std,            c_hs_std),
        ("deadline_violation_pct",     a["deadline_pct"],  b["deadline_pct"],   c["deadline_pct"]),
        ("ciphertext_expansion_ratio", exp["alpha"],       exp["bravo"],        exp["charlie"]),
        ("aead_cpu_us_esp32",          a["aead_cpu_us"],   b["aead_cpu_us"],    c["aead_cpu_us"]),
        ("ram_mb_gateway",             a["ram_mb"],        b["ram_mb"],         c["ram_mb"]),
        ("aead_ram_kb_esp32",          a["aead_ram_kb"],   b["aead_ram_kb"],    c["aead_ram_kb"]),
        ("firmware_size_kb",           fw["alpha_kb"],     fw["bravo_kb"],      fw["charlie_kb"]),
        ("firmware_overhead_kb",       0,                  fw["bravo_overhead_kb"], fw["charlie_overhead_kb"]),
        ("energy_mj",                  a["energy_mj"],     b["energy_mj"],      c["energy_mj"]),
        ("throughput_bps",             a["throughput_bps"],b["throughput_bps"], c["throughput_bps"]),
        ("loss_pct",                   a["loss_pct"],      b["loss_pct"],       c["loss_pct"]),
        ("max_sessions",               None,               args.max_sessions,   args.max_sessions),
        ("system_availability_pct",    None,               avl_b,               avl_c),
    ]
    with open(filename, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["metric", "alpha_plaintext", "bravo_pqc", "charlie_classical",
                    "ratio_bravo_over_alpha", "ratio_charlie_over_alpha",
                    "unit", "collected_at"])
        units = ["score_0-2","%","count","%","%","%","s",
                 "ms","ms","ms","ms","%","×","µs","MB","KB","KB","KB",
                 "mJ","B/s","%","sessions","%"]
        ts = datetime.now().isoformat()
        for (name, av_, bv_, cv_), u in zip(rows, units):
            w.writerow([name, av_, bv_, cv_, r(av_, bv_), r(av_, cv_), u, ts])
    print(f"  CSV → {filename}\n")


# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="MSI-TESE — 20 métricas × 3 fases")
    # InfluxDB
    ap.add_argument("--alpha-influx",    default=ALPHA_INFLUX)
    ap.add_argument("--bravo-influx",    default=BRAVO_INFLUX)
    ap.add_argument("--charlie-influx",  default=CHARLIE_INFLUX)
    # Servers
    ap.add_argument("--bravo-server",    default=BRAVO_SERVER)
    ap.add_argument("--charlie-server",  default=CHARLIE_SERVER)
    # Run config
    ap.add_argument("--window",          default="1h")
    ap.add_argument("--runs",            default=10, type=int)
    ap.add_argument("--no-benchmark",    action="store_true")
    ap.add_argument("--payload-size",    default=120, type=int,
                    help="Tamanho típico payload plaintext (bytes) para cálculo de expansão")
    # IDS
    ap.add_argument("--suricata-log",    default=None)
    ap.add_argument("--total-attacks",   default=None, type=int)
    ap.add_argument("--total-legitimate",default=None, type=int)
    ap.add_argument("--attack-start",    default=None, help="ISO timestamp inicio janela ataque")
    ap.add_argument("--attack-end",      default=None)
    # C2
    ap.add_argument("--alpha-loot",      default=None)
    ap.add_argument("--bravo-loot",      default=None)
    ap.add_argument("--charlie-loot",    default=None)
    ap.add_argument("--alpha-c2-log",    default=None)
    ap.add_argument("--bravo-c2-log",    default=None)
    ap.add_argument("--charlie-c2-log",  default=None)
    # Manual
    ap.add_argument("--max-sessions",    default=None, type=int)
    ap.add_argument("--recovery-time",   default=None, type=float, help="Segundos")
    # Output
    ap.add_argument("--csv",             default=None)
    args = ap.parse_args()
    csv_file = args.csv or f"metrics_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

    print(f"\n[1/7] Alpha InfluxDB ({args.alpha_influx}, window={args.window})...")
    am = collect_influx(args.alpha_influx, "alpha", args.window)

    print(f"[2/7] Bravo InfluxDB ({args.bravo_influx})...")
    bm = collect_influx(args.bravo_influx, None, args.window)

    print(f"[3/7] Charlie InfluxDB ({args.charlie_influx})...")
    cm = collect_influx(args.charlie_influx, "charlie", args.window)

    print("[4/7] Servidores /monitor + disponibilidade...")
    bs   = server_stats(args.bravo_server,   "bravo")
    cs   = server_stats(args.charlie_server, "charlie")
    avail = check_availability([args.bravo_server, args.charlie_server])

    print("[5/7] Firmware sizes + expansão + IDS...")
    fw  = firmware_sizes()
    exp = expansion_ratios(args.payload_size)
    ids = parse_suricata(args.suricata_log, args.total_attacks, args.total_legitimate,
                         args.attack_start, args.attack_end)

    print("[6/7] Gateway CPU/RAM (psutil)...")
    if HAS_PSUTIL:
        gw_cpu_val, gw_ram_val = gateway_cpu_ram(interval=3)
        gw_cpu = (gw_cpu_val,)
    else:
        print("  [INFO] psutil não disponível — instale: pip install psutil")
        gw_cpu = None

    if args.no_benchmark:
        bv = cv = (None, None)
    else:
        print(f"[7/7] Benchmark KEX ({args.runs} runs cada)...")
        bv = benchmark_kex("bravo",   args.bravo_server,   args.runs)
        cv = benchmark_kex("charlie", args.charlie_server, args.runs)

    print_table(am, bm, cm, (None, None), bv, cv,
                bs, cs, avail, fw, exp, ids, None, gw_cpu, None, args)
    export_csv(am, bm, cm, bv, cv, fw, exp, ids, avail, args, csv_file)


if __name__ == "__main__":
    main()
