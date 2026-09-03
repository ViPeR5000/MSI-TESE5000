#!/usr/bin/env python3
"""
Extrai e compara as métricas de performance das fases Alpha/Bravo/Charlie do
testbed MSI-TESE para uma janela temporal (por omissão as últimas 24 h).

Cada fase escreve no seu próprio InfluxDB (mesma org/bucket/token). Este script
consulta os três por HTTP (API /api/v2/query, Flux), normaliza os nomes dos
campos de cripto de campo — Alpha/Bravo usam `lwc_*`, Charlie usa `aead_*` — e
produz:

  raw/<fase>_performance.csv   pontos por-mensagem (long: time,node,metric,value)
  raw/<fase>_environment.csv   temp/hum
  summary.csv                  n, média, mediana, p95, desvio, min, max por
                               (fase, métrica)
  imprime a tabela comparativa + os dois deltas do desenho experimental:
     Alpha→Charlie (custo de TER cripto) e Charlie→Bravo (custo de ser PQC).

Só stdlib. Corre a partir de qualquer host que alcance os três InfluxDB:
  python3 extract_24h.py --hours 24 --out ./run_2026-07-13
  python3 extract_24h.py --start 2026-07-12T20:00:00Z --stop 2026-07-13T20:00:00Z
"""
import argparse, csv, io, os, statistics, sys, urllib.request

TOKEN = "my-super-secret-auth-token-12345678"
ORG   = "msi-tese"
BUCKET = "telemetry"

PHASES = {                      # fase → host do InfluxDB
    "alpha":   "192.168.100.60",
    "bravo":   "192.168.20.60",
    "charlie": "192.168.30.60",
}
# Os 3 Shelly plugs publicam todos no broker Alpha; o shelly-bridge (scada-a) grava a
# measurement `energy` no InfluxDB Alpha, distinguindo por tag `phase`. `test` = consumo
# da infra de segurança (C2 + suricata-a a capturar/gravar pcaps) — entra nos resultados.
ENERGY_HOST = PHASES["alpha"]

# Campos partilhados (mesmo nome nas três fases).
# NOTA: `energy_mj` removido (2026-07-16) — era uma constante fictícia (3.3·160·uptime)
# sem lógica real; deixou de ser publicado pelos firmwares/bridges. Dados históricos
# ainda o contêm, mas novas corridas não.
SHARED = ["avg_lat_ms", "jitter_ms", "throughput_bps", "loss_pct",
          "deadline_pct", "ram_mb"]
# Campos de cripto de campo com nomes diferentes → nome canónico.
CRYPTO_ALIASES = {"crypto_cpu_us": ["aead_cpu_us", "lwc_cpu_us"],
                  "crypto_ram_kb": ["aead_ram_kb", "lwc_ram_kb"]}
ENV = ["temperature", "humidity"]   # as três fases usam estes nomes (bridges Python)
# Custo assimétrico do handshake (Alpha não tem — fica vazio, o que é correto).
HANDSHAKE = ["hs_latency_ms", "hs_req_bytes", "hs_resp_bytes"]

PERF_METRICS = SHARED + list(CRYPTO_ALIASES) + HANDSHAKE   # ordem de saída


def flux(host, query):
    req = urllib.request.Request(
        f"http://{host}:8086/api/v2/query?org={ORG}",
        data=query.encode(),
        headers={"Authorization": f"Token {TOKEN}",
                 "Accept": "application/csv",
                 "Content-Type": "application/vnd.flux"},
        method="POST")
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read().decode()


def parse_points(csv_text):
    """Devolve lista de (time, node, field, float(value)) do CSV do InfluxDB."""
    out = []
    reader = csv.reader(io.StringIO(csv_text))
    header = None
    for row in reader:
        if not row or all(c == "" for c in row):
            header = None
            continue
        if "_field" in row:
            header = row
            continue
        if not header:
            continue
        d = dict(zip(header, row))
        try:
            out.append((d.get("_time", ""), d.get("node", ""),
                        d.get("_field", ""), float(d["_value"])))
        except (KeyError, ValueError):
            pass
    return out


def fetch(host, start, stop, measurement, fields):
    fexpr = " or ".join(f'r._field=="{f}"' for f in fields)
    q = (f'from(bucket:"{BUCKET}")'
         f'|>range(start:{start},stop:{stop})'
         f'|>filter(fn:(r)=>r._measurement=="{measurement}" and ({fexpr}))'
         f'|>keep(columns:["_time","_field","_value","node"])')
    return parse_points(flux(host, q))


def fetch_energy(host, start, stop):
    """energy (Shelly), agrupado pela tag phase → {phase: {field: [(time,val),...]}}."""
    q = (f'from(bucket:"{BUCKET}")'
         f'|>range(start:{start},stop:{stop})'
         f'|>filter(fn:(r)=>r._measurement=="energy" and '
         f'(r._field=="power_w" or r._field=="total_wh"))'
         f'|>keep(columns:["_time","_field","_value","phase"])')
    out = {}
    reader = csv.reader(io.StringIO(flux(host, q)))
    header = None
    for row in reader:
        if not row or all(c == "" for c in row):
            header = None
            continue
        if "_field" in row:
            header = row
            continue
        if not header:
            continue
        d = dict(zip(header, row))
        try:
            v = float(d["_value"])
        except (KeyError, ValueError):
            continue
        out.setdefault(d.get("phase", "?"), {}).setdefault(
            d.get("_field", ""), []).append((d.get("_time", ""), v))
    return out


def canonicalize(points):
    """Renomeia lwc_*/aead_* para o nome canónico de cripto."""
    rev = {alias: canon for canon, al in CRYPTO_ALIASES.items() for alias in al}
    return [(t, n, rev.get(f, f), v) for (t, n, f, v) in points]


def stats(values):
    if not values:
        return None
    vs = sorted(values)
    p95 = vs[min(len(vs) - 1, int(round(0.95 * (len(vs) - 1))))]
    return {
        "n": len(vs),
        "mean": statistics.fmean(vs),
        "median": statistics.median(vs),
        "p95": p95,
        "std": statistics.pstdev(vs) if len(vs) > 1 else 0.0,
        "min": vs[0], "max": vs[-1],
    }


def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--hours", type=float, default=24.0, help="janela em horas até agora")
    ap.add_argument("--start", help="RFC3339, ex 2026-07-12T20:00:00Z (override --hours)")
    ap.add_argument("--stop", default="now()", help="RFC3339 ou now()")
    ap.add_argument("--out", default="./extract_run", help="diretório de saída")
    ap.add_argument("--phases", default="alpha,bravo,charlie")
    ap.add_argument("--exclude", default="", help="intervalos UTC a cortar de TODAS as fases "
                    "(igualdade de base temporal): start/stop[,start/stop...] RFC3339")
    args = ap.parse_args()

    start = args.start if args.start else f"-{int(round(args.hours * 3600))}s"
    stop = args.stop
    phases = [p.strip() for p in args.phases.split(",") if p.strip() in PHASES]

    # Janelas de incidente a excluir. Comparacao lexicografica dos 1os 19 chars
    # ("YYYY-MM-DDTHH:MM:SS") = ordem cronologica para timestamps UTC de largura fixa.
    excludes = []
    for pair in args.exclude.split(","):
        pair = pair.strip()
        if "/" in pair:
            a, b = pair.split("/", 1)
            excludes.append((a.strip()[:19], b.strip()[:19]))
    def keep(pts):   # descarta pontos cujo _time cai num intervalo excluido
        if not excludes:
            return pts
        return [p for p in pts if not any(a <= p[0][:19] <= b for a, b in excludes)]
    if excludes:
        print(f"[INFO] a excluir {len(excludes)} intervalo(s) de todas as fases: "
              + "; ".join(f"{a}..{b}" for a, b in excludes))
    os.makedirs(os.path.join(args.out, "raw"), exist_ok=True)

    summary = []   # (phase, metric, stats-dict)
    per_phase_perf = {}

    for ph in phases:
        host = PHASES[ph]
        try:
            perf = canonicalize(fetch(host, start, stop, "telemetry_performance",
                                      SHARED + sum(CRYPTO_ALIASES.values(), [])))
            hs = fetch(host, start, stop, "telemetry_handshake", HANDSHAKE)
            env = fetch(host, start, stop, "telemetry_environment", ENV)
        except Exception as e:
            print(f"[AVISO] {ph} ({host}) inacessível: {e}", file=sys.stderr)
            continue

        perf = keep(perf); hs = keep(hs); env = keep(env)   # corta janelas de incidente
        perf = perf + hs   # a medição de handshake entra nas métricas de performance
        _write_long(os.path.join(args.out, "raw", f"{ph}_performance.csv"), perf)
        _write_long(os.path.join(args.out, "raw", f"{ph}_handshake.csv"), hs)
        _write_long(os.path.join(args.out, "raw", f"{ph}_environment.csv"), env)

        by_metric = {}
        for (_, _, f, v) in perf:
            by_metric.setdefault(f, []).append(v)
        per_phase_perf[ph] = by_metric
        for m in PERF_METRICS:
            st = stats(by_metric.get(m, []))
            if st:
                summary.append((ph, m, st))

    # Energia (Shelly) — centralizada no InfluxDB Alpha, uma query, todas as tags phase.
    try:
        en = fetch_energy(ENERGY_HOST, start, stop)
        raw = []
        print("\nEnergia (Shelly):")
        for ph, fields in sorted(en.items()):
            fields = {f: keep(lst) for f, lst in fields.items()}   # corta janelas de incidente
            for f, lst in fields.items():
                raw += [(t, ph, f, v) for t, v in lst]
            st = stats([v for _, v in fields.get("power_w", [])])
            if st:
                summary.append((ph, "power_w", st))
            wh = [v for _, v in sorted(fields.get("total_wh", []))]
            if wh:
                # ponytail: consumo = last-first do contador monotónico; um reboot do plug
                # dá delta negativo — visível no CSV raw se acontecer, não vale mais código.
                consumed = wh[-1] - wh[0]
                summary.append((ph, "energy_wh", {"n": len(wh), "mean": consumed,
                                "median": consumed, "p95": consumed, "std": 0.0,
                                "min": wh[0], "max": wh[-1]}))
                print(f"  {ph:<10} {st['mean']:.1f} W médio, {consumed:.1f} Wh na janela"
                      if st else f"  {ph:<10} {consumed:.1f} Wh na janela")
        _write_long(os.path.join(args.out, "raw", "energy.csv"), raw)
    except Exception as e:
        print(f"[AVISO] energia ({ENERGY_HOST}) inacessível: {e}", file=sys.stderr)

    _write_summary(os.path.join(args.out, "summary.csv"), summary)
    _print_comparison(per_phase_perf, phases)
    print(f"\nCSVs escritos em: {os.path.abspath(args.out)}")


def _write_long(path, points):
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["time", "node", "metric", "value"])
        w.writerows(points)


def _write_summary(path, summary):
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["phase", "metric", "n", "mean", "median", "p95", "std", "min", "max"])
        for ph, m, st in summary:
            w.writerow([ph, m, st["n"], f'{st["mean"]:.4g}', f'{st["median"]:.4g}',
                        f'{st["p95"]:.4g}', f'{st["std"]:.4g}', f'{st["min"]:.4g}', f'{st["max"]:.4g}'])


def _print_comparison(per_phase, phases):
    print(f"\n{'métrica':<16}" + "".join(f"{p:>14}" for p in phases))
    print("-" * (16 + 14 * len(phases)))
    for m in PERF_METRICS:
        row = f"{m:<16}"
        for p in phases:
            vals = per_phase.get(p, {}).get(m, [])
            row += f"{statistics.median(vals):>14.3g}" if vals else f"{'—':>14}"
        print(row)

    def med(p, m):
        vals = per_phase.get(p, {}).get(m, [])
        return statistics.median(vals) if vals else None

    print("\nDeltas (mediana; % = overhead relativo):")
    for a, b, label in [("alpha", "charlie", "Alpha→Charlie (custo de ter cripto)"),
                        ("charlie", "bravo", "Charlie→Bravo (custo de ser PQC)")]:
        if a in phases and b in phases:
            print(f"  {label}:")
            for m in PERF_METRICS:
                va, vb = med(a, m), med(b, m)
                if va is None or vb is None:
                    continue
                pct = (vb - va) / va * 100 if va else float("inf")
                print(f"    {m:<16} {va:>10.3g} → {vb:<10.3g} ({pct:+.1f}%)")


if __name__ == "__main__":
    main()
