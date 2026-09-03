KEX_ALGORITHM = "ECDH-secp384r1"
SIG_ALGORITHM = "ECDSA-secp384r1"

SERVER_ECDSA_PUB_FILE    = "server_ecdsa.pub.pem"
SERVER_ECDSA_PRIV_FILE   = "server_ecdsa.priv.pem"   # TPM-backed in production
TPM_PRIMARY_CTX_FILE     = "tpm_primary.ctx"

HKDF_INFO    = b"charlie-aes-key"   # must match ecdh_kex.h
HKDF_KEY_LEN = 16                   # AES-128
