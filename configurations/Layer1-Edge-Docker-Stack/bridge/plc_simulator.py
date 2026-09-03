import os
import time
import json
import base64
import requests
import urllib3
import paho.mqtt.client as mqtt
import ascon

# ====================================================================
# CONFIGURAÇÕES DO PLC
# ====================================================================
MQTT_HOST = os.getenv("MQTT_BROKER_HOST", "localhost")
MQTT_PORT = int(os.getenv("MQTT_BROKER_PORT", 1883))
PQC_TOPIC = "EDGE/GATEWAY/pqc_payload"
PLC_STATUS_TOPIC = "PLC/STATUS/telemetry"
PQC_SERVER_URL = os.getenv("PQC_SERVER_URL", "https://192.168.20.200:8000")

PQC_TLS_CERT = os.getenv("PQC_TLS_CERT_PATH")
if PQC_TLS_CERT:
    print(f"[TLS] Certificado PQC configurado: {PQC_TLS_CERT}")
else:
    print("[TLS] AVISO: PQC_TLS_CERT_PATH não definido — TLS sem verificação de certificado!")
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
_tls_verify = PQC_TLS_CERT if PQC_TLS_CERT else False

# ====================================================================
# DECIFRAÇÃO SIMÉTRICA (ASCON-128 AEAD)
# ====================================================================
def decrypt_ascon(b64_ciphertext: str, key_bytes: bytes) -> str:
    """Decifra os dados usando a chave simétrica acordada por KEM (ASCON-128 AEAD)."""
    pt = ascon.decrypt_from_b64(key_bytes[:16], b64_ciphertext)
    if pt is None:
        raise ValueError("ASCON: autenticação falhou ou payload inválido")
    return pt.decode('utf-8')

# ====================================================================
# EXECUÇÃO DE LÓGICA DE CONTROLO INDUSTRIAL (IEC 61131-3)
# ====================================================================
def execute_control_logic(telemetry_data: dict):
    """Simula lógica ladder de automação e controlo baseada na temperatura."""
    temp = telemetry_data.get("temp")
    hum = telemetry_data.get("hum")
    node_id = telemetry_data.get("node", "ESP32")
    
    print(f"\n[PLC] [IEC 61131-3 LOGIC] A processar dados do Nó: {node_id}")
    print(f" -> Temperatura: {temp}°C | Humidade: {hum}%")
    
    # Lógica de Automação: Se temperatura ultrapassar 28°C, liga atuador de refrigeração
    cooling_relay = "OFF"
    alarm_status = "NORMAL"
    
    if temp > 28.0:
        cooling_relay = "ON (Speed 100%)"
        alarm_status = "CRITICAL_HIGH_TEMP"
        print(f"[PLC] [ALERTA] Temperatura crítica ({temp}°C)! Ativando relé de arrefecimento.")
    elif temp > 25.0:
        cooling_relay = "ON (Speed 50%)"
        print(f"[PLC] [AVISO] Temperatura em alta ({temp}°C). Refrigeração preventiva ativa.")
    else:
        print(f"[PLC] Parâmetros de temperatura normais. Relé de refrigeração: {cooling_relay}")
        
    return {
        "status": "PROCESSED",
        "node": node_id,
        "temperature": temp,
        "cooling_relay": cooling_relay,
        "alarm": alarm_status,
        "timestamp": int(time.time())
    }

# ====================================================================
# CALLBACKS DO BROKER MQTT
# ====================================================================
def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print(f"[PLC] Conectado ao EMQX. Subscrevendo a: {PQC_TOPIC}")
        client.subscribe(PQC_TOPIC)
    else:
        print(f"[PLC] Falha ao ligar ao EMQX. Código: {rc}")

def on_message(client, userdata, msg):
    try:
        payload_str = msg.payload.decode('utf-8')
        packet = json.loads(payload_str)
        
        # Extrair campos do pacote PQC
        kem_ciphertext_b64 = packet["kem_ciphertext_b64"]
        encrypted_payload = packet["encrypted_payload_b64"]
        signature_b64 = packet["signature_b64"]
        gateway_pub_sig_b64 = packet.get("gateway_pub_sig_b64")
        
        if not gateway_pub_sig_b64:
            print("[PLC] Chave pública de assinatura em falta no pacote. Ignorando.")
            return

        # Reconstruir dados que foram assinados
        kem_ciphertext_raw = base64.b64decode(kem_ciphertext_b64)
        data_to_verify = kem_ciphertext_raw + encrypted_payload.encode('utf-8')
        data_to_verify_b64 = base64.b64encode(data_to_verify).decode('utf-8')

        # 1. Delegar Verificação de Assinatura Dilithium3 ao Key Manager (viper-keys)
        print("[PLC] A solicitar verificação de assinatura Dilithium3 ao viper-keys...")
        r_verify = requests.post(
            f"{PQC_SERVER_URL}/sig/verify",
            json={
                "message_b64": data_to_verify_b64,
                "signature_b64": signature_b64,
                "public_key_b64": gateway_pub_sig_b64
            },
            timeout=5,
            verify=_tls_verify
        )
        if r_verify.status_code != 200 or not r_verify.json().get("is_valid"):
            print("[PLC] [ERRO CRÍTICO] Falha na verificação da assinatura Dilithium3 pelo Key Manager! Mensagem rejeitada.")
            return

        print("[PLC] [VERIFICAÇÃO PQC] Assinatura Dilithium3 do Gateway validada com sucesso! (AUTÊNTICO)")
        
        # 2. Delegar a Decapsulação Kyber768 ao Key Manager (viper-keys)
        print("[PLC] A solicitar decapsulação Kyber768 ao viper-keys...")
        r_decap = requests.post(
            f"{PQC_SERVER_URL}/kem/decapsulate",
            json={"ciphertext_b64": kem_ciphertext_b64},
            timeout=5,
            verify=_tls_verify
        )
        if r_decap.status_code != 200:
            print(f"[PLC] Erro na decapsulação Kyber: {r_decap.text}")
            return
            
        shared_secret = base64.b64decode(r_decap.json()["shared_secret_b64"])
        
        # 3. Decifrar payload LWC usando a chave simétrica desselada pelo Key Manager
        plaintext_str = decrypt_ascon(encrypted_payload, shared_secret)
        telemetry_data = json.loads(plaintext_str)
        print(f"[PLC] [PQC DECIFRADO] Payload de dados original: {plaintext_str}")
        
        # 4. Executar Lógica de Automação
        plc_state = execute_control_logic(telemetry_data)
        
        # 5. Publicar estado atualizado para o SCADA
        client.publish(PLC_STATUS_TOPIC, json.dumps(plc_state))
        print(f"[PLC] Status atualizado publicado no SCADA ({PLC_STATUS_TOPIC})")
        
    except Exception as e:
        print(f"[PLC] Erro ao processar mensagem PQC: {e}")

if __name__ == "__main__":
    print("==========================================================")
    print(" PLC IEC 61131-3 SIMULATOR (PQC SECURE LAYER 2) INICIADO ")
    print("==========================================================")
    
    time.sleep(2)
    
    client = mqtt.Client("msi_plc_simulator")
    client.on_connect = on_connect
    client.on_message = on_message
    
    while True:
        try:
            client.connect(MQTT_HOST, MQTT_PORT, 60)
            break
        except Exception as e:
            print(f"[PLC] A aguardar broker EMQX em {MQTT_HOST}... Tentando em 5s.")
            time.sleep(5)
            
    client.loop_forever()
