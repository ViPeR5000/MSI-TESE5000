#!/usr/bin/env python3
"""
Valida os inputs dos sensores e a telemetria das 3 fases (Alpha/Bravo/Charlie).
Para cada fase consulta o InfluxDB e reporta, por nó:
  - presença/recência (último ponto dentro de FRESH_S segundos)
  - sanidade dos valores (temp/hum em gama; loss/latência plausíveis)
  - handshake presente (fases seguras)
Só stdlib. Sinaliza [OK] / [STALE] / [RANGE] / [MISSING].
"""
import csv, io, sys, urllib.request
from datetime import datetime, timezone

TOKEN="my-super-secret-auth-token-12345678"; ORG="msi-tese"; BUCKET="telemetry"
PHASES={"alpha":"192.168.100.60","bravo":"192.168.20.60","charlie":"192.168.30.60"}
SECURE={"bravo","charlie"}
FRESH_S=120           # dados mais antigos que isto = STALE
RANGES={              # (min,max) plausíveis; fora disto = RANGE
    "temperature":(0,60),"humidity":(0,100),"loss_pct":(0,100),
    "avg_lat_ms":(0,5000),"jitter_ms":(0,5000),"throughput_bps":(0,1e7),
    "hs_latency_ms":(1,10000),
}

def flux(host,q):
    req=urllib.request.Request(f"http://{host}:8086/api/v2/query?org={ORG}",data=q.encode(),
        headers={"Authorization":f"Token {TOKEN}","Accept":"application/csv","Content-Type":"application/vnd.flux"},method="POST")
    with urllib.request.urlopen(req,timeout=30) as r: return r.read().decode()

def rows(host,meas,fields,window="-1h"):
    fexpr=" or ".join(f'r._field=="{f}"' for f in fields)
    q=(f'from(bucket:"{BUCKET}")|>range(start:{window})'
       f'|>filter(fn:(r)=>r._measurement=="{meas}" and ({fexpr}))'
       f'|>last()|>keep(columns:["_time","_field","_value","node"])')
    out=[]
    for row in csv.reader(io.StringIO(flux(host,q))):
        if not row or "_field" in row or row[0]!="": continue
        # cols: ,result,table,_time,_value,_field,node
        try: out.append((row[6],row[5],float(row[4]),row[3]))   # node,field,val,time
        except (IndexError,ValueError): pass
    return out

def age(ts):
    try: return (datetime.now(timezone.utc)-datetime.fromisoformat(ts.replace("Z","+00:00"))).total_seconds()
    except Exception: return 1e9

def main():
    problems=0
    for ph,host in PHASES.items():
        print(f"\n===== {ph.upper()} ({host}) =====")
        try:
            env=rows(host,"telemetry_environment",["temperature","humidity"])
            perf=rows(host,"telemetry_performance",["avg_lat_ms","jitter_ms","throughput_bps","loss_pct"])
            hs=rows(host,"telemetry_handshake",["hs_latency_ms"],window="-24h")
        except Exception as e:
            print(f"  [MISSING] InfluxDB inacessível: {e}"); problems+=1; continue
        nodes=sorted({n for (n,_,_,_) in env+perf+hs})
        if not nodes: print("  [MISSING] nenhum nó a publicar na última hora"); problems+=1; continue
        for nd in nodes:
            flags=[]
            def latest(rowset,f):
                c=[(t,v) for (n,ff,v,t) in rowset if n==nd and ff==f]
                return c[0] if c else None
            # recência (usa o env ou perf mais recente)
            times=[t for (n,_,_,t) in env+perf if n==nd]
            a=min((age(t) for t in times), default=1e9)
            fresh = a<=FRESH_S
            if not fresh: flags.append("STALE no-fresh-telemetry" if a>=1e8 else f"STALE {int(a/60)}min")
            # sanidade
            vals={}
            for meas in (env,perf,hs):
                for (n,f,v,t) in meas:
                    if n==nd: vals[f]=v
            for f,(lo,hi) in RANGES.items():
                if f in vals and not (lo<=vals[f]<=hi): flags.append(f"RANGE {f}={vals[f]:.3g}")
            # handshake: rotação horária. Flag só se falhou uma rotação (>75min) ou nunca (24h).
            hs_age=None
            if ph in SECURE:
                hts=[t for (n,f,_,t) in hs if n==nd and f=="hs_latency_ms"]
                if not hts:
                    flags.append("NO-HANDSHAKE-24h")
                else:
                    hs_age=age(hts[0])
                    if hs_age>4500: flags.append(f"HS-STALE {int(hs_age/60)}min")
            status="OK" if not flags else "  ".join(flags)
            tv=vals.get("temperature"); hv=vals.get("humidity"); lt=vals.get("avg_lat_ms"); lo=vals.get("loss_pct")
            desc=[]
            if tv is not None: desc.append(f"T={tv:.1f}C")
            if hv is not None: desc.append(f"H={hv:.0f}%")
            if lt is not None: desc.append(f"lat={lt:.0f}ms")
            if lo is not None: desc.append(f"loss={lo:.1f}%")
            if "hs_latency_ms" in vals:
                desc.append(f"hs={vals['hs_latency_ms']:.0f}ms/{int(hs_age/60)}m-ago" if hs_age else f"hs={vals['hs_latency_ms']:.0f}ms")
            mark="[OK]   " if not flags else "[WARN] "
            if flags and any(x.startswith(("STALE","RANGE","MISSING","NO-HANDSHAKE","HS-STALE")) for x in flags): problems+=1
            print(f"  {mark}{nd:<14} {' '.join(desc):<42} {'' if status=='OK' else '<< '+status}")
    print(f"\n{'='*40}\nResultado: {'TUDO OK' if problems==0 else str(problems)+' problema(s)'}")
    sys.exit(1 if problems else 0)

if __name__=="__main__": main()
