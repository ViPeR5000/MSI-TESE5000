# Algoritmos PQC baseados nos padrões NIST
KEM_ALGORITHM = "Kyber768"
SIG_ALGORITHM = "ML-DSA-65"

# Ficheiros das chaves públicas (plaintext para partilha com clientes)
SERVER_KYBER_PUB_FILE = "server_kyber.pub"
SERVER_DILITHIUM_PUB_FILE = "server_dilithium.pub"

# Ficheiros das chaves privadas seladas pelo TPM 2.0 (ou em fallback local)
SERVER_KYBER_PRIV_SEALED = "server_kyber.priv.tpm"
SERVER_DILITHIUM_PRIV_SEALED = "server_dilithium.priv.tpm"

# Nome do contexto do objeto primário do TPM
TPM_PRIMARY_CTX_FILE = "tpm_primary.ctx"
