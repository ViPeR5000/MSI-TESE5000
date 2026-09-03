import datetime
import base64
import os
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import oqs
from config import (
    KEM_ALGORITHM, SIG_ALGORITHM,
    SERVER_KYBER_PUB_FILE, SERVER_DILITHIUM_PUB_FILE,
    SERVER_KYBER_PRIV_SEALED, SERVER_DILITHIUM_PRIV_SEALED,
    TPM_PRIMARY_CTX_FILE
)
from tpm_manager import TPMManager

app = FastAPI(
    title="PQC Key Management Server",
    description="Servidor de Gestão de Chaves PQC (Kyber & Dilithium) para fornecer chaves seguras aos módulos ESP32 e Gateways.",
    version="1.0.0"
)

# === Estado Global de Monitorização === #
boot_time: datetime.datetime = datetime.datetime.utcnow()
last_key_rotation: datetime.datetime = datetime.datetime.utcnow()
handshake_counter: int = 0
server_logs: list = []
active_session_key: bytes = b"default_session_key_32bytes_long"
session_key_history: list = []   # rolling window of last 5 session keys (bytes)
KEY_HISTORY_SIZE = 20


def add_log(event_msg: str, log_type: str = "info"):
    """Adiciona um evento de log em memória para exibição no painel de monitorização."""
    global server_logs
    timestamp = datetime.datetime.utcnow()
    server_logs.append({
        "timestamp": timestamp.isoformat() + "Z",
        "event": event_msg,
        "type": log_type
    })
    # Limita o histórico de logs para evitar consumo excessivo de RAM
    if len(server_logs) > 50:
        server_logs.pop(0)
    print(f"[{log_type.upper()}] {event_msg}")

# === Inicialização do TPM === #
tpm_mgr = TPMManager(primary_ctx=TPM_PRIMARY_CTX_FILE)

# === Inicialização dos Algoritmos OQS & TPM === #
SERVER_KEM = None
SERVER_KEM_PUBKEY = None
SERVER_SIG = None
SERVER_SIG_PUBKEY = None

def generate_and_seal_keys():
    global SERVER_KEM, SERVER_KEM_PUBKEY, SERVER_SIG, SERVER_SIG_PUBKEY
    try:
        add_log("A gerar novos pares de chaves PQC...", "info")
        
        # 1. Instancia e gera KEM (Kyber)
        SERVER_KEM = oqs.KeyEncapsulation(KEM_ALGORITHM)
        SERVER_KEM_PUBKEY = SERVER_KEM.generate_keypair()
        
        # 2. Instancia e gera SIG (Dilithium)
        SERVER_SIG = oqs.Signature(SIG_ALGORITHM)
        SERVER_SIG_PUBKEY = SERVER_SIG.generate_keypair()
        
        # 3. Guarda as chaves públicas em plaintext
        with open(SERVER_KYBER_PUB_FILE, "wb") as f:
            f.write(SERVER_KEM_PUBKEY)
        with open(SERVER_DILITHIUM_PUB_FILE, "wb") as f:
            f.write(SERVER_SIG_PUBKEY)
            
        # 4. Sela as chaves privadas no TPM
        tpm_mgr.seal_key(SERVER_KEM.export_secret_key(), SERVER_KYBER_PRIV_SEALED)
        tpm_mgr.seal_key(SERVER_SIG.export_secret_key(), SERVER_DILITHIUM_PRIV_SEALED)
        
        add_log("Novas chaves PQC geradas e seladas no Let's Trust TPM com sucesso", "success")
        add_log(f"Algoritmo KEM: {KEM_ALGORITHM} (Chave Pública gerada e persistida)", "success")
        add_log(f"Algoritmo Assinatura: {SIG_ALGORITHM} (Chave Pública gerada e persistida)", "success")
    except Exception as e:
        add_log(f"Erro catastrófico na geração/selagem de chaves: {str(e)}", "warning")
        raise

def load_or_generate_keys():
    global SERVER_KEM, SERVER_KEM_PUBKEY, SERVER_SIG, SERVER_SIG_PUBKEY
    
    keys_exist = (
        os.path.exists(SERVER_KYBER_PUB_FILE) and
        os.path.exists(SERVER_DILITHIUM_PUB_FILE) and
        os.path.exists(SERVER_KYBER_PRIV_SEALED) and
        os.path.exists(SERVER_DILITHIUM_PRIV_SEALED)
    )
    
    if keys_exist:
        try:
            # 1. Carrega as chaves públicas do disco
            with open(SERVER_KYBER_PUB_FILE, "rb") as f:
                SERVER_KEM_PUBKEY = f.read()
            with open(SERVER_DILITHIUM_PUB_FILE, "rb") as f:
                SERVER_SIG_PUBKEY = f.read()
            
            # 2. Desselará as chaves privadas do TPM
            kem_priv = tpm_mgr.unseal_key(SERVER_KYBER_PRIV_SEALED)
            sig_priv = tpm_mgr.unseal_key(SERVER_DILITHIUM_PRIV_SEALED)
            
            # 3. Instancia os algoritmos OQS com as chaves privadas recuperadas
            SERVER_KEM = oqs.KeyEncapsulation(KEM_ALGORITHM, secret_key=kem_priv)
            SERVER_SIG = oqs.Signature(SIG_ALGORITHM, secret_key=sig_priv)
            
            add_log("Chaves PQC carregadas e desseladas do Let's Trust TPM com sucesso", "success")
            add_log(f"Algoritmo KEM: {KEM_ALGORITHM} (Chave Pública recarregada)", "success")
            add_log(f"Algoritmo Assinatura: {SIG_ALGORITHM} (Chave Pública recarregada)", "success")
        except Exception as e:
            add_log(f"Erro ao carregar chaves do TPM: {str(e)}. A gerar novas...", "warning")
            generate_and_seal_keys()
    else:
        generate_and_seal_keys()

# Executa o carregamento ou geração das chaves
load_or_generate_keys()

def _update_key_rotation():
    """Regera o par de chaves KEM (Kyber), sela no TPM e atualiza o estado global."""
    global SERVER_KEM, SERVER_KEM_PUBKEY, last_key_rotation
    try:
        SERVER_KEM = oqs.KeyEncapsulation(KEM_ALGORITHM)
        SERVER_KEM_PUBKEY = SERVER_KEM.generate_keypair()
        
        # Salva a nova chave pública
        with open(SERVER_KYBER_PUB_FILE, "wb") as f:
            f.write(SERVER_KEM_PUBKEY)
            
        # Sela a nova chave privada no TPM
        tpm_mgr.seal_key(SERVER_KEM.export_secret_key(), SERVER_KYBER_PRIV_SEALED)
        
        last_key_rotation = datetime.datetime.utcnow()
        add_log(f"Rotação de chaves KEM com Let's Trust TPM executada com sucesso ({KEM_ALGORITHM})", "warning")
        return base64.b64encode(SERVER_KEM_PUBKEY).decode('utf-8')
    except Exception as e:
        add_log(f"Falha ao rodar chaves KEM com TPM: {str(e)}", "warning")
        raise HTTPException(status_code=500, detail=f"Erro na rotação: {str(e)}")



# === Modelos Pydantic para a API === #
class ServerPubKeyResponse(BaseModel):
    kem_public_key_b64: str
    sig_public_key_b64: str

class KEMEncapsulateResponse(BaseModel):
    ciphertext_b64: str
    shared_secret_b64: str

class KEMDecapsulateRequest(BaseModel):
    ciphertext_b64: str

class KEMDecapsulateResponse(BaseModel):
    shared_secret_b64: str

class SignRequest(BaseModel):
    message_b64: str

class SignResponse(BaseModel):
    signature_b64: str

class VerifyRequest(BaseModel):
    message_b64: str
    signature_b64: str
    public_key_b64: str

class VerifyResponse(BaseModel):
    is_valid: bool


# === Endpoints REST da API === #

@app.get("/", response_class=HTMLResponse, tags=["Interface Visual"])
def root():
    """Serve o painel de controlo central do testbed (index de todos os serviços)."""
    html_path = os.path.join(os.path.dirname(__file__), "templates", "index.html")
    if os.path.exists(html_path):
        with open(html_path, "r", encoding="utf-8") as f:
            return f.read()
    return HTMLResponse(
        '{"status":"PQC Key Management Server RUNNING","dashboard":"/dashboard","monitor":"/monitor"}',
        media_type="application/json"
    )

@app.get("/dashboard", response_class=HTMLResponse, tags=["Interface Visual"])
def get_dashboard():
    """Serve a página HTML do painel de monitorização e controlo."""
    html_path = os.path.join(os.path.dirname(__file__), "templates", "dashboard.html")
    if os.path.exists(html_path):
        with open(html_path, "r", encoding="utf-8") as f:
            return f.read()
    else:
        return HTMLResponse(
            "<h2>Erro: O ficheiro templates/dashboard.html não foi encontrado!</h2>",
            status_code=404
        )

@app.get("/server/public_keys", response_model=ServerPubKeyResponse, tags=["Chaves do Servidor"])
def get_server_public_keys():
    """
    Retorna as chaves públicas KEM e SIG ativas no servidor.
    Invocado pelos ESP32 e Gateways para handshake ou validação de assinaturas.
    """
    return {
        "kem_public_key_b64": base64.b64encode(SERVER_KEM_PUBKEY).decode('utf-8'),
        "sig_public_key_b64": base64.b64encode(SERVER_SIG_PUBKEY).decode('utf-8')
    }

# --- KEM (Kyber) --- #

@app.post("/kem/encapsulate", response_model=KEMEncapsulateResponse, tags=["KEM (Kyber)"])
def kem_encapsulate():
    """
    Gera um segredo partilhado e encapsula-o usando a chave pública do servidor.
    Incrementa o contador de handshakes para monitorização.
    """
    global handshake_counter, active_session_key, session_key_history
    try:
        with oqs.KeyEncapsulation(KEM_ALGORITHM) as kem_client:
            ciphertext, shared_secret = kem_client.encap_secret(SERVER_KEM_PUBKEY)
            handshake_counter += 1
            active_session_key = shared_secret
            if not session_key_history or session_key_history[-1] != shared_secret:
                session_key_history.append(shared_secret)
                if len(session_key_history) > KEY_HISTORY_SIZE:
                    session_key_history.pop(0)
            add_log("Handshake KEM concluído com sucesso (Encapsulation)", "handshake")
            return {
                "ciphertext_b64": base64.b64encode(ciphertext).decode('utf-8'),
                "shared_secret_b64": base64.b64encode(shared_secret).decode('utf-8')
            }
    except Exception as e:
        add_log(f"Erro em /kem/encapsulate: {str(e)}", "warning")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/kem/decapsulate", response_model=KEMDecapsulateResponse, tags=["KEM (Kyber)"])
def kem_decapsulate(req: KEMDecapsulateRequest):
    """
    Decapsula um ciphertext usando a chave privada do servidor e devolve o segredo partilhado.
    Incrementa o contador de handshakes para monitorização.
    """
    global handshake_counter, active_session_key, session_key_history
    try:
        ciphertext = base64.b64decode(req.ciphertext_b64)
        shared_secret = SERVER_KEM.decap_secret(ciphertext)
        handshake_counter += 1
        active_session_key = shared_secret
        if not session_key_history or session_key_history[-1] != shared_secret:
            session_key_history.append(shared_secret)
            if len(session_key_history) > KEY_HISTORY_SIZE:
                session_key_history.pop(0)
        add_log("Handshake KEM concluído com sucesso (Decapsulation)", "handshake")
        return {
            "shared_secret_b64": base64.b64encode(shared_secret).decode('utf-8')
        }
    except Exception as e:
        add_log(f"Erro em /kem/decapsulate: {str(e)}", "warning")
        raise HTTPException(status_code=500, detail=f"Erro na decapsulação. Ciphertext inválido? ({str(e)})")

# --- Assinaturas Digitais (Dilithium) --- #

@app.post("/sig/sign", response_model=SignResponse, tags=["Assinaturas (Dilithium)"])
def sig_sign(req: SignRequest):
    """Gera uma assinatura digital Dilithium da mensagem recebida em Base64."""
    try:
        message = base64.b64decode(req.message_b64)
        signature = SERVER_SIG.sign(message)
        add_log("Assinatura Dilithium digital gerada para comando industrial", "success")
        return {
            "signature_b64": base64.b64encode(signature).decode('utf-8')
        }
    except Exception as e:
        add_log(f"Erro em /sig/sign: {str(e)}", "warning")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/sig/verify", response_model=VerifyResponse, tags=["Assinaturas (Dilithium)"])
def sig_verify(req: VerifyRequest):
    """Verifica a autenticidade e integridade de uma assinatura digital Dilithium."""
    try:
        message = base64.b64decode(req.message_b64)
        signature = base64.b64decode(req.signature_b64)
        public_key = base64.b64decode(req.public_key_b64)
        
        with oqs.Signature(SIG_ALGORITHM) as sig_verifier:
            is_valid = sig_verifier.verify(message, signature, public_key)
            if is_valid:
                add_log("Assinatura Dilithium verificada: AUTÊNTICA", "success")
            else:
                add_log("Assinatura Dilithium verificada: FALHA / FALSIFICADA", "warning")
            return {"is_valid": is_valid}
    except Exception as e:
        add_log(f"Erro em /sig/verify: {str(e)}", "warning")
        return {"is_valid": False}

# --- Endpoints de Monitorização --- #

@app.get("/monitor", tags=["Monitorização"])
def get_monitor():
    """Retorna o estado detalhado do servidor, chaves ativas, logs e o status do chip TPM 2.0."""
    uptime_seconds = int((datetime.datetime.utcnow() - boot_time).total_seconds())
    
    # Formatação de uptime hh:mm:ss
    h = uptime_seconds // 3600
    m = (uptime_seconds % 3600) // 60
    s = uptime_seconds % 60
    uptime_str = f"{h:02d}:{m:02d}:{s:02d}"

    return {
        "handshake_counter": handshake_counter,
        "last_key_rotation": last_key_rotation.isoformat() + "Z",
        "kem_algorithm": KEM_ALGORITHM,
        "sig_algorithm": SIG_ALGORITHM,
        "kem_public_key_b64": base64.b64encode(SERVER_KEM_PUBKEY).decode('utf-8'),
        "sig_public_key_b64": base64.b64encode(SERVER_SIG_PUBKEY).decode('utf-8'),
        "active_session_key_b64": base64.b64encode(active_session_key).decode('utf-8') if active_session_key else None,
        "recent_session_keys_b64": [base64.b64encode(k).decode('utf-8') for k in session_key_history],
        "server_uptime_str": uptime_str,
        "logs": server_logs,
        "tpm_available": tpm_mgr.tpm_available,
        "tpm_status": tpm_mgr.tpm_status,
        "tpm_info": tpm_mgr.tpm_info,
        "tpm_device": tpm_mgr.tpm_device
    }

@app.post("/monitor/force_rotation", tags=["Monitorização"])
def force_rotation():
    """Força uma nova rotação das chaves KEM e adiciona o evento ao registo."""
    new_pub = _update_key_rotation()
    return {"new_kem_public_key_b64": new_pub}
