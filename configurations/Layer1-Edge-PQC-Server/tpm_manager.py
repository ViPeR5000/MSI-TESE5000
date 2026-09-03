import os
import shutil
import subprocess
import tempfile
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("TPMManager")

def is_tpm2_tools_available():
    """Verifica se os utilitários tpm2-tools estão instalados no sistema."""
    return shutil.which("tpm2_createprimary") is not None

def is_tpm_hardware_available():
    """Verifica se o chip TPM 2.0 físico está conectado e a responder a comandos."""
    if not is_tpm2_tools_available():
        return False
    try:
        # Verifica dispositivo directamente sem passar pelo TABRMD (mais rápido e fiável)
        result = subprocess.run(
            ["tpm2_getrandom", "4", "--hex", "--tcti=device:/dev/tpmrm0"],
            capture_output=True,
            timeout=10
        )
        if result.returncode == 0:
            return True
        # Fallback: tenta sem tcti explícito
        result2 = subprocess.run(
            ["tpm2_getrandom", "4", "--hex"],
            capture_output=True,
            timeout=10
        )
        return result2.returncode == 0
    except Exception:
        return False

class TPMManager:
    def __init__(self, primary_ctx="tpm_primary.ctx"):
        self.primary_ctx = primary_ctx
        self.tpm_available = is_tpm_hardware_available()
        self.tpm_status = "ACTIVE (Hardware: Let's Trust TPM 2.0)" if self.tpm_available else "SIMULATED (Software Fallback)"
        self.tpm_info = "Infineon OPTIGA™ SLB 9670 via TPM2-TSS" if self.tpm_available else "Emulação de Armazenamento Seguro por Software"
        self.tpm_device = "/dev/tpmrm0 (Resiliente a Concorrência)" if self.tpm_available else "None (Simulação)"

        if self.tpm_available:
            logger.info("Let's Trust TPM 2.0 Hardware detetado e operacional!")
        else:
            logger.warning("Let's Trust TPM 2.0 Hardware não detetado ou tpm2-tools em falta. A ativar Software Fallback!")

    def seal_key(self, key_bytes: bytes, priv_sealed_path: str) -> bool:
        """
        Sela a chave privada usando o chip TPM.
        Se o hardware TPM não estiver disponível, faz o fallback para guardar em ficheiro de software local.
        """
        if self.tpm_available:
            temp_secret_path = None
            try:
                # 1. Escreve a chave privada temporariamente num ficheiro seguro
                with tempfile.NamedTemporaryFile(delete=False) as temp_secret:
                    temp_secret.write(key_bytes)
                    temp_secret_path = temp_secret.name

                # Limpa contextos anteriores se existirem
                if os.path.exists(self.primary_ctx):
                    os.remove(self.primary_ctx)

                # 2. Cria a chave de armazenamento primária (SRK) na hierarquia Owner
                subprocess.run(
                    ["tpm2_createprimary", "-C", "o", "-c", self.primary_ctx,
                     "--tcti=device:/dev/tpmrm0"],
                    check=True, capture_output=True
                )

                # 3. Cria o objeto selado no TPM
                pub_blob = f"{priv_sealed_path}.pub"
                priv_blob = f"{priv_sealed_path}.priv"

                if os.path.exists(pub_blob): os.remove(pub_blob)
                if os.path.exists(priv_blob): os.remove(priv_blob)

                subprocess.run(
                    [
                        "tpm2_create",
                        "-C", self.primary_ctx,
                        "-i", temp_secret_path,
                        "-u", pub_blob,
                        "-r", priv_blob,
                        "--tcti=device:/dev/tpmrm0"
                    ],
                    check=True, capture_output=True
                )

                # 4. Limpa ficheiros temporários e o contexto do primário
                if temp_secret_path and os.path.exists(temp_secret_path):
                    os.remove(temp_secret_path)
                if os.path.exists(self.primary_ctx):
                    os.remove(self.primary_ctx)

                # Escreve um marcador de texto para identificar que o ficheiro principal está selado no TPM
                with open(priv_sealed_path, "w", encoding="utf-8") as f:
                    f.write("TPM_SEALED")

                logger.info(f"Chave privada pós-quântica selada com sucesso no TPM: {priv_sealed_path}")
                return True
            except Exception as e:
                logger.error(f"Falha ao selar chave via TPM: {e}. A tentar Software Fallback de persistência...")
                if temp_secret_path and os.path.exists(temp_secret_path):
                    os.remove(temp_secret_path)
                if os.path.exists(self.primary_ctx):
                    os.remove(self.primary_ctx)
                
                # Desativa o TPM para forçar o fallback de persistência
                self.tpm_available = False
                self.tpm_status = "SIMULATED (Software Fallback)"
                self.tpm_info = "Emulação de Armazenamento Seguro por Software"
                self.tpm_device = "None (Simulação)"

        # Software Fallback
        try:
            with open(priv_sealed_path, "wb") as f:
                f.write(key_bytes)
            logger.info(f"Software Fallback: Chave guardada diretamente no disco em {priv_sealed_path}")
            return True
        except Exception as sw_err:
            logger.error(f"Erro no Software Fallback de escrita de chaves: {sw_err}")
            return False

    def unseal_key(self, priv_sealed_path: str) -> bytes:
        """
        Desselará (unseal) a chave privada usando o chip TPM.
        Se o hardware TPM não estiver disponível, carrega a chave do fallback em software.
        """
        if self.tpm_available:
            object_ctx = "sealed_object.ctx"
            pub_blob = f"{priv_sealed_path}.pub"
            priv_blob = f"{priv_sealed_path}.priv"

            # Chave legacy (software-fallback sem blobs TPM): carregar directamente
            # sem desactivar tpm_available — próxima rotação selará no hardware
            if not os.path.exists(pub_blob) or not os.path.exists(priv_blob):
                if os.path.exists(priv_sealed_path):
                    with open(priv_sealed_path, "rb") as f:
                        content = f.read()
                    if content.strip() != b"TPM_SEALED":
                        logger.info(f"Chave legacy (software-fallback) carregada: {priv_sealed_path}. Próxima rotação usará o TPM hardware.")
                        return content
                raise RuntimeError(
                    f"A chave em {priv_sealed_path} está marcada como TPM_SEALED mas os blobs estão em falta."
                )

            try:

                # Limpa contextos anteriores se existirem
                if os.path.exists(self.primary_ctx): os.remove(self.primary_ctx)
                if os.path.exists(object_ctx): os.remove(object_ctx)

                # 1. Cria a chave primária
                subprocess.run(
                    ["tpm2_createprimary", "-C", "o", "-c", self.primary_ctx,
                     "--tcti=device:/dev/tpmrm0"],
                    check=True, capture_output=True
                )

                # 2. Carrega o objeto selado
                subprocess.run(
                    [
                        "tpm2_load",
                        "-C", self.primary_ctx,
                        "-u", pub_blob,
                        "-r", priv_blob,
                        "-c", object_ctx,
                        "--tcti=device:/dev/tpmrm0"
                    ],
                    check=True, capture_output=True
                )

                # 3. Desselará o objeto e obtém a chave privada original
                result = subprocess.run(
                    ["tpm2_unseal", "-c", object_ctx, "--tcti=device:/dev/tpmrm0"],
                    check=True, capture_output=True
                )
                key_bytes = result.stdout

                # 4. Limpa contextos
                if os.path.exists(self.primary_ctx): os.remove(self.primary_ctx)
                if os.path.exists(object_ctx): os.remove(object_ctx)

                logger.info(f"Chave privada desselada e carregada com sucesso do TPM a partir de {priv_sealed_path}")
                return key_bytes
            except Exception as e:
                logger.error(f"Erro ao desselar chave via hardware TPM: {e}. A tentar Software Fallback de leitura...")
                if os.path.exists(self.primary_ctx): os.remove(self.primary_ctx)
                if os.path.exists(object_ctx): os.remove(object_ctx)
                
                self.tpm_available = False
                self.tpm_status = "SIMULATED (Software Fallback)"
                self.tpm_info = "Emulação de Armazenamento Seguro por Software"
                self.tpm_device = "None (Simulação)"

        # Software Fallback
        if os.path.exists(priv_sealed_path):
            with open(priv_sealed_path, "rb") as f:
                content = f.read()
                if content == b"TPM_SEALED":
                    raise RuntimeError(
                        f"A chave em {priv_sealed_path} está marcada como selada no hardware TPM, "
                        "mas o chip físico Let's Trust TPM 2.0 não está operacional neste sistema de momento!"
                    )
                return content
        else:
            raise FileNotFoundError(f"Ficheiro de chave privada não encontrado: {priv_sealed_path}")
