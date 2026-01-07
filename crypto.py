"""
Módulo Criptográfico para Sistema de Mensageria Segura

Implementa:
- ECDHE (Elliptic Curve Diffie-Hellman Ephemeral) para troca de chaves
- AES-128-GCM (AEAD) para cifragem autenticada
- RSA para assinatura digital
- HKDF para derivação de chaves conforme TLS 1.3
"""

import os
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime


class CryptoUtils:
    """Utilitários criptográficos com garantias de segurança"""
    
    # Constantes de segurança
    NONCE_SIZE = 12  # 96 bits para GCM (recomendado)
    KEY_SIZE = 16    # 128 bits para AES-128
    CLIENT_ID_SIZE = 16
    SEQ_NO_SIZE = 8
    
    @staticmethod
    def generate_ecdhe_keypair():
        """
        Gera par de chaves ECDHE efêmero
        
        SECP256R1 (P-256): curva recomendada pelo NIST
        Oferece ~128 bits de segurança, equivalente a RSA-3072
        
        Returns:
            tuple: (private_key, public_key_bytes)
        """
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        return private_key, public_key_bytes
    
    @staticmethod
    def compute_ecdh_shared_secret(private_key, peer_public_key_bytes):
        """
        Calcula segredo compartilhado via ECDH
        
        ECDH: ambas as partes combinam sua chave privada com a chave 
        pública da outra parte para chegar ao mesmo segredo compartilhado
        
        Args:
            private_key: Chave privada ECDHE local
            peer_public_key_bytes: Chave pública do peer (formato X962)
            
        Returns:
            bytes: Segredo compartilhado Z
        """
        peer_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), peer_public_key_bytes
        )
        shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
        return shared_secret
    
    @staticmethod
    def derive_keys(shared_secret, salt, context_c2s=b"c2s", context_s2c=b"s2c"):
        """
        Deriva chaves usando HKDF conforme TLS 1.3
        
        HKDF (HMAC-based Key Derivation Function):
        - Extract: gera PRK (Pseudo-Random Key) a partir do segredo e salt
        - Expand: deriva múltiplas chaves do PRK com contextos diferentes
        
        Por que contextos diferentes?
        - Garante que Key_c2s ≠ Key_s2c
        - Previne reflexão de mensagens
        - Cada direção tem seu próprio espaço de chaves
        
        Args:
            shared_secret: Segredo compartilhado Z do ECDH
            salt: Salt aleatório (aumenta entropia)
            context_c2s: Contexto para chave cliente→servidor
            context_s2c: Contexto para chave servidor→cliente
            
        Returns:
            tuple: (key_c2s, key_s2c)
        """
        # Extract: PRK = HKDF-Extract(salt, IKM)
        hkdf_extract = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # Gera 256 bits de PRK
            salt=salt,
            info=None
        )
        prk = hkdf_extract.derive(shared_secret)
        
        # Expand: OKM = HKDF-Expand(PRK, info, L)
        key_c2s = HKDF(
            algorithm=hashes.SHA256(),
            length=CryptoUtils.KEY_SIZE,
            salt=None,
            info=context_c2s
        ).derive(prk)
        
        key_s2c = HKDF(
            algorithm=hashes.SHA256(),
            length=CryptoUtils.KEY_SIZE,
            salt=None,
            info=context_s2c
        ).derive(prk)
        
        return key_c2s, key_s2c
    
    @staticmethod
    def generate_rsa_keypair_and_cert(common_name="SecureMessaging Server"):
        """
        Gera par RSA e certificado autoassinado
        
        RSA é usado APENAS para assinatura digital da chave ECDHE efêmera,
        não para cifragem de dados (que seria lento e sem forward secrecy)
        
        Args:
            common_name: Nome do servidor no certificado
            
        Returns:
            tuple: (private_key, certificate_bytes)
        """
        # Gera chave RSA-2048
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Cria certificado autoassinado
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).sign(private_key, hashes.SHA256())
        
        cert_bytes = cert.public_bytes(serialization.Encoding.PEM)
        
        return private_key, cert_bytes
    
    @staticmethod
    def sign_data(private_key, data):
        """
        Assina dados com RSA-PSS
        
        PSS (Probabilistic Signature Scheme): mais seguro que PKCS#1 v1.5
        Usa padding probabilístico (não determinístico)
        
        Args:
            private_key: Chave privada RSA
            data: Dados a assinar
            
        Returns:
            bytes: Assinatura digital
        """
        signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature
    
    @staticmethod
    def verify_signature(cert_bytes, signature, data):
        """
        Verifica assinatura RSA-PSS
        
        Args:
            cert_bytes: Certificado em formato PEM
            signature: Assinatura a verificar
            data: Dados originais
            
        Returns:
            bool: True se válida, False caso contrário
        """
        try:
            cert = x509.load_pem_x509_certificate(cert_bytes)
            public_key = cert.public_key()
            
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
    
    @staticmethod
    def encrypt_message(key, nonce, plaintext, aad):
        """
        Cifra mensagem com AES-128-GCM
        
        GCM (Galois/Counter Mode): modo AEAD
        - Autenticação: garante integridade e autenticidade
        - Encryption: garante confidencialidade
        
        AAD (Additional Authenticated Data):
        - Dados autenticados mas NÃO cifrados
        - Usamos: sender_id | recipient_id | seq_no
        - Tag de autenticação cobre AAD + ciphertext
        
        Por que nonce único?
        - Reutilizar nonce com mesma chave = DESASTRE
        - Vazamento de XOR entre plaintexts
        - Quebra completa da segurança
        
        Args:
            key: Chave AES-128 (16 bytes)
            nonce: Nonce único (12 bytes)
            plaintext: Dados a cifrar
            aad: Additional Authenticated Data
            
        Returns:
            bytes: ciphertext + tag (tag tem 16 bytes no final)
        """
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
        return ciphertext  # Inclui tag automaticamente
    
    @staticmethod
    def decrypt_message(key, nonce, ciphertext, aad):
        """
        Decifra e autentica mensagem com AES-128-GCM
        
        Ordem de operações (importante!):
        1. Verifica tag de autenticação
        2. Se válida, decifra
        3. Se inválida, rejeita ANTES de decifrar
        
        Isso previne ataques de padding oracle e timing
        
        Args:
            key: Chave AES-128 (16 bytes)
            nonce: Nonce (12 bytes)
            ciphertext: ciphertext + tag
            aad: Additional Authenticated Data
            
        Returns:
            bytes: plaintext se válido
            
        Raises:
            Exception: Se autenticação falhar
        """
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, aad)  # Lança exceção se tag inválida
        return plaintext
    
    @staticmethod
    def generate_nonce():
        """
        Gera nonce criptograficamente seguro
        
        Usa os.urandom: fonte de entropia do SO
        - No Linux: /dev/urandom
        - No Windows: CryptGenRandom
        
        Returns:
            bytes: 12 bytes aleatórios
        """
        return os.urandom(CryptoUtils.NONCE_SIZE)
    
    @staticmethod
    def generate_salt():
        """
        Gera salt aleatório para HKDF
        
        Salt aumenta entropia e previne ataques de pré-computação
        
        Returns:
            bytes: 32 bytes aleatórios
        """
        return os.urandom(32)
    
    @staticmethod
    def generate_client_id():
        """
        Gera identificador único de cliente
        
        Returns:
            bytes: 16 bytes aleatórios
        """
        return os.urandom(CryptoUtils.CLIENT_ID_SIZE)