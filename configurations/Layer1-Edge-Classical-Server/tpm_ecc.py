"""
Native TPM 2.0 ECC P-384 signing key manager (Phase Charlie).

Unlike the Bravo PQC server — which can only *seal* an opaque Kyber/Dilithium
private blob into the TPM — a classical ECC key can be generated, held, and used
for signing entirely inside the TPM. That asymmetry is the thesis finding: the
classical stack gets hardware-native key custody that the post-quantum stack
cannot. This module drives the Infineon SLB 9670 via tpm2-tools:

  tpm2_createprimary  → ECC primary in the owner hierarchy
  tpm2_create -G ecc384 (sign) → ECDSA P-384 key whose private half never leaves
  tpm2_evictcontrol   → persist the key at a fixed handle across reboots
  tpm2_sign           → hardware ECDSA over a SHA-256 digest

The private scalar is never exported. Signatures come out as raw R||S and are
repacked into the DER (RFC 3279) form the `cryptography` verify side expects.
Falls back to a software `cryptography` key if no TPM is present, so the server
still runs on a box without the chip.
"""
import os
import shutil
import hashlib
import subprocess
import logging
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives import serialization, hashes

logger = logging.getLogger("TpmEcc")

_DIR          = os.path.join(os.path.dirname(__file__), "tpm")
_PRIMARY_CTX  = os.path.join(_DIR, "primary.ctx")
_KEY_PUB      = os.path.join(_DIR, "ecdsa.pub")
_KEY_PRIV     = os.path.join(_DIR, "ecdsa.priv")
_KEY_CTX      = os.path.join(_DIR, "ecdsa.ctx")
_PUB_PEM      = os.path.join(_DIR, "ecdsa_pub.pem")
_PERSIST      = "0x81010020"          # persistent handle for the ECDSA signing key
_TCTI         = "device:/dev/tpmrm0"
_P384_COORD   = 48                    # R and S width for secp384r1


def _tpm_available() -> bool:
    if shutil.which("tpm2_createprimary") is None:
        return False
    try:
        r = subprocess.run(["tpm2_getrandom", "4", "--hex", f"--tcti={_TCTI}"],
                           capture_output=True, timeout=10)
        return r.returncode == 0
    except Exception:
        return False


class TpmEcc:
    def __init__(self):
        self.available = _tpm_available()
        self._soft_priv = None          # software fallback ECDSA key
        self.public_key = None          # cryptography public-key object (both modes)

        if self.available:
            self.status = "ACTIVE (native ECC P-384 in Infineon SLB 9670)"
            self.device = "/dev/tpmrm0"
            try:
                self._ensure_hw_key()
                logger.info("TPM ECC P-384 signing key ready (hardware-native).")
            except Exception as e:
                logger.error(f"TPM init failed ({e}); falling back to software key.")
                self.available = False

        if not self.available:
            self.status = "SIMULATED (software ECDSA — no TPM)"
            self.device = "None"
            self._soft_priv = ec.generate_private_key(ec.SECP384R1())
            self.public_key = self._soft_priv.public_key()
            logger.warning("TPM not present — using software ECDSA fallback.")

    # ── hardware setup ──────────────────────────────────────────────────────────

    def _run(self, args):
        subprocess.run([*args, f"--tcti={_TCTI}"], capture_output=True, check=True)

    def _ensure_hw_key(self):
        os.makedirs(_DIR, exist_ok=True)
        handles = subprocess.run(["tpm2_getcap", "handles-persistent", f"--tcti={_TCTI}"],
                                 capture_output=True, text=True)
        if _PERSIST in handles.stdout and os.path.exists(_PUB_PEM):
            self._load_pub_pem()
            return
        self._create_hw_key()

    def _create_hw_key(self):
        # Primary key in the owner hierarchy (regenerable, never persisted).
        self._run(["tpm2_createprimary", "-C", "o", "-g", "sha256", "-G", "ecc", "-c", _PRIMARY_CTX])
        # Non-restricted ECDSA P-384 signing key: private half is TPM-resident.
        self._run(["tpm2_create", "-C", _PRIMARY_CTX, "-G", "ecc384",
                   "-u", _KEY_PUB, "-r", _KEY_PRIV,
                   "-a", "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign"])
        self._run(["tpm2_load", "-C", _PRIMARY_CTX, "-u", _KEY_PUB, "-r", _KEY_PRIV, "-c", _KEY_CTX])
        # Free any stale key at the handle, then persist ours.
        subprocess.run(["tpm2_evictcontrol", "-C", "o", "-c", _PERSIST, f"--tcti={_TCTI}"],
                       capture_output=True)
        self._run(["tpm2_evictcontrol", "-C", "o", "-c", _KEY_CTX, _PERSIST])
        # Export the public key (PEM) for clients and the verify path.
        self._run(["tpm2_readpublic", "-c", _PERSIST, "-f", "pem", "-o", _PUB_PEM])
        self._load_pub_pem()

    def _load_pub_pem(self):
        with open(_PUB_PEM, "rb") as f:
            self.public_key = serialization.load_pem_public_key(f.read())

    # ── signing ─────────────────────────────────────────────────────────────────

    def sign(self, message: bytes) -> bytes:
        """ECDSA-SHA256 signature, DER-encoded (matches cryptography's verify)."""
        if not self.available:
            return self._soft_priv.sign(message, ec.ECDSA(hashes.SHA256()))

        digest = hashlib.sha256(message).digest()
        dfile = os.path.join(_DIR, "d.bin")
        sfile = os.path.join(_DIR, "sig.bin")
        with open(dfile, "wb") as f:
            f.write(digest)
        # -d: input is a pre-computed digest; -f plain: signature-only output.
        self._run(["tpm2_sign", "-c", _PERSIST, "-g", "sha256", "-d", "-f", "plain",
                   "-o", sfile, dfile])
        with open(sfile, "rb") as f:
            raw = f.read()
        # tpm2-tools ≥5.x emits a DER SEQUENCE (0x30…) directly; older builds emit
        # raw R||S (2×coord). Return DER either way — it's what verify expects.
        if raw and raw[0] == 0x30:
            return raw
        if len(raw) == 2 * _P384_COORD:
            r = int.from_bytes(raw[:_P384_COORD], "big")
            s = int.from_bytes(raw[_P384_COORD:], "big")
            return encode_dss_signature(r, s)
        raise RuntimeError(f"unexpected TPM signature length {len(raw)}")

    def public_der(self) -> bytes:
        return self.public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)

    def regenerate(self):
        """Fresh long-term signing key (hardware evict+recreate, or new software key)."""
        if self.available:
            self._create_hw_key()
        else:
            self._soft_priv = ec.generate_private_key(ec.SECP384R1())
            self.public_key = self._soft_priv.public_key()


if __name__ == "__main__":
    # Self-check: sign with whatever backend is present, verify with the public key.
    logging.basicConfig(level=logging.INFO)
    t = TpmEcc()
    msg = b"charlie industrial command: OPEN VALVE 3"
    sig = t.sign(msg)
    t.public_key.verify(sig, msg, ec.ECDSA(hashes.SHA256()))
    print(f"OK — backend={'TPM' if t.available else 'software'}, sig={len(sig)}B DER, verified.")
