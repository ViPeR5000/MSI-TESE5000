import base64, datetime, os
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey, ECDH
from cryptography.exceptions import InvalidSignature
from config import KEX_ALGORITHM, SIG_ALGORITHM, HKDF_INFO, HKDF_KEY_LEN
from tpm_ecc import TpmEcc

app = FastAPI(
    title="Classical Key Management Server (Charlie)",
    description="ECDH secp384r1 + ECDSA secp384r1. Drop-in classical analog of the PQC server.",
    version="1.0.0"
)

# === Estado Global === #
boot_time          = datetime.datetime.utcnow()
last_key_rotation  = datetime.datetime.utcnow()
handshake_counter  = 0
server_logs: list  = []
active_session_key: bytes = b""
session_key_history: list = []
KEY_HISTORY_SIZE = 5

# === Chave de Assinatura de Longa Duração (ECDSA P-384) === #
# Nativa no TPM 2.0 quando presente (chave privada nunca sai do chip); caso
# contrário, fallback de software. Ver tpm_ecc.py e [[phase-scheme]].
SIG = None
SERVER_SIG_PUB = None   # objeto cryptography (usado por verify e endpoints públicos)


def add_log(msg: str, t: str = "info"):
    global server_logs
    server_logs.append({"timestamp": datetime.datetime.utcnow().isoformat()+"Z",
                         "event": msg, "type": t})
    if len(server_logs) > 50: server_logs.pop(0)
    print(f"[{t.upper()}] {msg}")


def init_sig_key():
    global SIG, SERVER_SIG_PUB
    SIG = TpmEcc()
    SERVER_SIG_PUB = SIG.public_key
    add_log(f"Chave de assinatura ECDSA P-384 pronta — backend: {SIG.status}",
            "success" if SIG.available else "warning")


init_sig_key()


# === Modelos Pydantic === #
class KexRequest(BaseModel):
    node_id: str
    client_pub_b64: str   # uncompressed P-384 point, base64

class KexResponse(BaseModel):
    server_pub_b64: str   # server ephemeral public key

class SignRequest(BaseModel):
    message_b64: str

class SignResponse(BaseModel):
    signature_b64: str

class VerifyRequest(BaseModel):
    message_b64: str
    signature_b64: str
    public_key_b64: str   # DER-encoded P-384 public key, base64

class VerifyResponse(BaseModel):
    is_valid: bool


# === Endpoints === #

@app.get("/", response_class=HTMLResponse)
def root():
    return HTMLResponse(
        '{"status":"Classical Key Management Server RUNNING",'
        '"kex_algorithm":"' + KEX_ALGORITHM + '",'
        '"sig_algorithm":"' + SIG_ALGORITHM + '",'
        '"dashboard":"/dashboard","monitor":"/monitor"}',
        media_type="application/json")


@app.get("/dashboard", response_class=HTMLResponse)
def get_dashboard():
    html_path = os.path.join(os.path.dirname(__file__), "templates", "dashboard.html")
    if os.path.exists(html_path):
        with open(html_path, "r", encoding="utf-8") as f:
            return f.read()
    return HTMLResponse("<h2>dashboard.html não encontrado</h2>", status_code=404)


@app.post("/kex/exchange", response_model=KexResponse, tags=["KEX (ECDH)"])
def kex_exchange(req: KexRequest):
    """
    ECDH ephemeral key exchange (secp384r1).
    Client sends its ephemeral public key; server computes shared secret,
    derives AES-128 session key via HKDF-SHA256, returns its ephemeral public key.
    """
    global handshake_counter, active_session_key, session_key_history
    try:
        client_pub_bytes = base64.b64decode(req.client_pub_b64)
        client_pub = EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), client_pub_bytes)

        # Generate server ephemeral key pair
        srv_eph_priv = ec.generate_private_key(ec.SECP384R1())

        # ECDH → shared secret Z (48 bytes for P-384)
        z = srv_eph_priv.exchange(ECDH(), client_pub)

        # HKDF-SHA256 → 16-byte AES key  (info must match ecdh_kex.h)
        session_key = HKDF(
            algorithm=hashes.SHA256(),
            length=HKDF_KEY_LEN,
            salt=None,
            info=HKDF_INFO
        ).derive(z)

        active_session_key = session_key
        if not session_key_history or session_key_history[-1] != session_key:
            session_key_history.append(session_key)
            if len(session_key_history) > KEY_HISTORY_SIZE:
                session_key_history.pop(0)

        handshake_counter += 1
        add_log(f"KEX ECDH concluído para node {req.node_id} ({handshake_counter} total)", "handshake")

        srv_pub_bytes = srv_eph_priv.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint)

        return {"server_pub_b64": base64.b64encode(srv_pub_bytes).decode()}

    except Exception as e:
        add_log(f"Erro em /kex/exchange: {e}", "warning")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/sig/sign", response_model=SignResponse, tags=["Assinaturas (ECDSA)"])
def sig_sign(req: SignRequest):
    try:
        message   = base64.b64decode(req.message_b64)
        signature = SIG.sign(message)   # TPM-native (ou software fallback)
        add_log("Assinatura ECDSA P-384 gerada.", "success")
        return {"signature_b64": base64.b64encode(signature).decode()}
    except Exception as e:
        add_log(f"Erro em /sig/sign: {e}", "warning")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/sig/verify", response_model=VerifyResponse, tags=["Assinaturas (ECDSA)"])
def sig_verify(req: VerifyRequest):
    try:
        message   = base64.b64decode(req.message_b64)
        signature = base64.b64decode(req.signature_b64)
        pub_der   = base64.b64decode(req.public_key_b64)
        pub_key   = serialization.load_der_public_key(pub_der)
        pub_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        add_log("Assinatura ECDSA verificada: AUTÊNTICA.", "success")
        return {"is_valid": True}
    except InvalidSignature:
        add_log("Assinatura ECDSA verificada: FALHA.", "warning")
        return {"is_valid": False}
    except Exception as e:
        add_log(f"Erro em /sig/verify: {e}", "warning")
        return {"is_valid": False}


@app.get("/server/public_keys", tags=["Chaves do Servidor"])
def get_public_keys():
    pub_der = SERVER_SIG_PUB.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    return {
        "sig_algorithm": SIG_ALGORITHM,
        "sig_public_key_b64": base64.b64encode(pub_der).decode()
    }


@app.get("/monitor", tags=["Monitorização"])
def get_monitor():
    up = int((datetime.datetime.utcnow() - boot_time).total_seconds())
    h, m, s = up//3600, (up%3600)//60, up%60
    return {
        "phase": "charlie",
        "kex_algorithm": KEX_ALGORITHM,
        "sig_algorithm": SIG_ALGORITHM,
        "handshake_counter": handshake_counter,
        "last_key_rotation": last_key_rotation.isoformat()+"Z",
        "active_session_key_b64": base64.b64encode(active_session_key).decode() if active_session_key else None,
        "recent_session_keys_b64": [base64.b64encode(k).decode() for k in session_key_history],
        "server_uptime_str": f"{h:02d}:{m:02d}:{s:02d}",
        "tpm_backed": SIG.available,
        "tpm_status": SIG.status,
        "tpm_device": SIG.device,
        "logs": server_logs
    }


@app.post("/monitor/force_rotation", tags=["Monitorização"])
def force_rotation():
    """Regenera a chave ECDSA de longa duração (nativa no TPM quando presente)."""
    global SERVER_SIG_PUB, last_key_rotation
    SIG.regenerate()
    SERVER_SIG_PUB = SIG.public_key
    last_key_rotation = datetime.datetime.utcnow()
    add_log(f"Rotação forçada de chaves ECDSA P-384 concluída ({SIG.device}).", "warning")
    return {"new_sig_public_key_b64": base64.b64encode(SIG.public_der()).decode()}
