import os
import time
import json
import base64
import requests
import urllib3
import paho.mqtt.client as mqtt
import ascon

# ====================================================================
# CONFIGURAÇÕES DO GATEWAY
# ====================================================================
MQTT_HOST = os.getenv("MQTT_BROKER_HOST", "localhost")
MQTT_PORT = int(os.getenv("MQTT_BROKER_PORT", 1883))
LWC_TOPIC = "BRAVO/+/telemetria"  # Subscreve a todos os nós de campo
PQC_OUT_TOPIC = "EDGE/GATEWAY/pqc_payload"
PQC_SERVER_URL = os.getenv("PQC_SERVER_URL", "https://192.168.20.200:8000")

PQC_TLS_CERT = os.getenv("PQC_TLS_CERT_PATH")
if PQC_TLS_CERT:
    print(f"[TLS] Certificado PQC configurado: {PQC_TLS_CERT}")
else:
    print("[TLS] AVISO: PQC_TLS_CERT_PATH não definido — TLS sem verificação de certificado!")
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
_tls_verify = PQC_TLS_CERT if PQC_TLS_CERT else False

# Chaves locais em cache (geridas centralmente pelo Key Manager)
lwc_session_key = None
gateway_pub_sig_key = None

# ====================================================================
# ASCON-128: DECRIPTÇÃO (DO ESP32) e ENCRIPTÇÃO (PARA PLC)
# ====================================================================
def decrypt_ascon(b64_ciphertext: str, key_bytes: bytes) -> str:
    """Decifra telemetria ASCON-128 vinda do ESP32."""
    if not key_bytes:
        raise ValueError("Chave LWC não disponível.")
    pt = ascon.decrypt_from_b64(key_bytes[:16], b64_ciphertext)
    if pt is None:
        raise ValueError("Falha de autenticação ASCON-128 (tag inválida ou chave errada)")
    return pt.decode('utf-8')

def encrypt_ascon(plaintext: str, key_bytes: bytes) -> str:
    """Encripta payload com ASCON-128 e nonce aleatório."""
    return ascon.encrypt_to_b64(key_bytes[:16], plaintext.encode('utf-8'))

# ====================================================================
# COMUNICAÇÃO COM O SERVIDOR DE CHAVES (viper-keys)
# ====================================================================
def fetch_keys_from_server():
    global lwc_session_key, gateway_pub_sig_key
    try:
        # Obter a chave LWC ativa e chave de assinatura do servidor
        print(f"[GATEWAY] A contactar o Key Manager (viper-keys) em {PQC_SERVER_URL}/monitor...")
        r = requests.get(f"{PQC_SERVER_URL}/monitor", timeout=5, verify=_tls_verify)
        if r.status_code == 200:
            data = r.json()
            key_b64 = data.get("active_session_key_b64")
            if key_b64:
                lwc_session_key = base64.b64decode(key_b64)
                print(f"[GATEWAY] Chave LWC ativa em cache: {key_b64[:12]}...")
            
            pub_sig_b64 = data.get("sig_public_key_b64")
            if pub_sig_b64:
                gateway_pub_sig_key = pub_sig_b64
        else:
            print(f"[GATEWAY] Resposta inesperada do Key Manager. Código: {r.status_code}")
    except Exception as e:
        print(f"[GATEWAY] Erro ao contactar o Key Manager: {e}")

# ====================================================================
# PROCESSAMENTO DE MENSAGENS E TRADUÇÃO PQC
# ====================================================================
def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print(f"[GATEWAY] Conectado ao broker EMQX. Subscrevendo a: {LWC_TOPIC}")
        client.subscribe(LWC_TOPIC)
    else:
        print(f"[GATEWAY] Falha ao ligar ao EMQX. Código: {rc}")

def on_message(client, userdata, msg):
    global lwc_session_key, gateway_pub_sig_key
    try:
        node_id = msg.topic.split("/")[1]
        payload_str = msg.payload.decode('utf-8')
        print(f"\n[GATEWAY] [LWC RECEBIDO] Nó: {node_id} | Payload: {payload_str}")
        
        # Garante que temos a chave LWC
        if not lwc_session_key:
            fetch_keys_from_server()
            if not lwc_session_key:
                print("[GATEWAY] Chave LWC em falta. Ignorando mensagem.")
                return
        
        # 1. Decifrar payload LWC (ASCON) do ESP32
        try:
            plaintext = decrypt_ascon(payload_str, lwc_session_key)
            print(f"[GATEWAY] [LWC DECIFRADO] Plaintext: {plaintext}")
        except Exception as dec_err:
            print(f"[GATEWAY] Falha ao decifrar. A atualizar chave LWC... ({dec_err})")
            fetch_keys_from_server()
            plaintext = decrypt_ascon(payload_str, lwc_session_key)
            print(f"[GATEWAY] [LWC DECIFRADO APÓS ROT] Plaintext: {plaintext}")
            
        # 2. Delegar a encriptação/encapsulamento PQC ao Key Manager (viper-keys)
        print("[GATEWAY] A solicitar encapsulamento KEM Kyber768 ao viper-keys...")
        r_kem = requests.post(f"{PQC_SERVER_URL}/kem/encapsulate", timeout=5, verify=_tls_verify)
        if r_kem.status_code != 200:
            print(f"[GATEWAY] Erro no encapsulamento KEM: {r_kem.text}")
            return
            
        kem_data = r_kem.json()
        ciphertext_b64 = kem_data["ciphertext_b64"]
        shared_secret = base64.b64decode(kem_data["shared_secret_b64"])
        
        # Cifra os dados dos sensores usando o segredo partilhado gerado centralmente
        encrypted_payload = encrypt_ascon(plaintext, shared_secret)
        
        # 3. Delegar Assinatura Dilithium3 ao Key Manager (viper-keys)
        # Prepara a junção do ciphertext + payload encriptado para assinatura
        data_to_sign = base64.b64decode(ciphertext_b64) + encrypted_payload.encode('utf-8')
        data_to_sign_b64 = base64.b64encode(data_to_sign).decode('utf-8')
        
        print("[GATEWAY] A solicitar assinatura Dilithium3 ao viper-keys...")
        r_sig = requests.post(
            f"{PQC_SERVER_URL}/sig/sign",
            json={"message_b64": data_to_sign_b64},
            timeout=5,
            verify=_tls_verify
        )
        if r_sig.status_code != 200:
            print(f"[GATEWAY] Erro ao assinar payload: {r_sig.text}")
            return
            
        signature_b64 = r_sig.json()["signature_b64"]
        
        # 4. Construir payload PQC final
        pqc_packet = {
            "gateway_id": "viper-gateway-b",
            "node_id": node_id,
            "kem_ciphertext_b64": ciphertext_b64,
            "encrypted_payload_b64": encrypted_payload,
            "signature_b64": signature_b64,
            "gateway_pub_sig_b64": gateway_pub_sig_key
        }
        
        # Publicar para o PLC
        pqc_payload_json = json.dumps(pqc_packet)
        client.publish(PQC_OUT_TOPIC, pqc_payload_json)
        print(f"[GATEWAY] [PQC ENVIADO] Publicado em {PQC_OUT_TOPIC}")
        print(f" -> KEM Ciphertext: {ciphertext_b64[:16]}...")
        print(f" -> Signature: {signature_b64[:16]}...")
        
    except Exception as e:
        print(f"[GATEWAY] Erro no fluxo de tradução PQC: {e}")

if __name__ == "__main__":
    print("==========================================================")
    print(" PQC EDGE GATEWAY TRANSLATOR INICIADO ")
    print("==========================================================")
    
    time.sleep(2)
    fetch_keys_from_server()
    
    client = mqtt.Client("msi_pqc_gateway_translator")
    client.on_connect = on_connect
    client.on_message = on_message
    
    while True:
        try:
            client.connect(MQTT_HOST, MQTT_PORT, 60)
            break
        except Exception as e:
            print(f"[GATEWAY] A aguardar broker EMQX em {MQTT_HOST}... Tentando em 5s.")
            time.sleep(5)
            
    client.loop_forever()
