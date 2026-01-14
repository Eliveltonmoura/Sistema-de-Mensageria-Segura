"""
Cliente de Mensageria Segura

Funcionalidades:
- Handshake ECDHE autenticado com RSA
- Derivação de chaves via HKDF
- Envio e recebimento de mensagens cifradas AES-128-GCM
- Proteção anti-replay com sequence numbers
"""

import asyncio
import struct
import sys
from crypto import CryptoUtils


class SecureMessagingClient:
    def __init__(self, host="127.0.0.1", port=8888):
        self.host = host
        self.port = port

        self.client_id = CryptoUtils.generate_client_id()

        self.reader = None
        self.writer = None

        # Estado da sessão
        self.key_c2s = None
        self.key_s2c = None
        self.seq_send = 0
        self.seq_recv = 0

    async def connect(self):
        """Conecta ao servidor e executa o handshake"""
        print(f"[+] Conectando ao servidor {self.host}:{self.port}...")
        self.reader, self.writer = await asyncio.open_connection(self.host, self.port)

        await self.perform_handshake()

        print("[✓] Conexão segura estabelecida")
        print(f"Seu ID: {self.client_id.hex()}")
        print("-" * 60)

    async def perform_handshake(self):
        """
        Handshake ECDHE + RSA

        Cliente → Servidor: client_id | pk_C
        Servidor → Cliente: pk_S | cert | signature | salt
        """

        # 1️⃣ Gera ECDHE do cliente
        sk_C, pk_C = CryptoUtils.generate_ecdhe_keypair()

        # 2️⃣ Envia client_id + pk_C
        self.writer.write(self.client_id + pk_C)
        await self.writer.drain()

        # 3️⃣ Recebe resposta do servidor
        pk_S = await self.reader.readexactly(65)

        cert_len = struct.unpack("!I", await self.reader.readexactly(4))[0]
        cert_bytes = await self.reader.readexactly(cert_len)

        sig_len = struct.unpack("!I", await self.reader.readexactly(4))[0]
        signature = await self.reader.readexactly(sig_len)

        salt = await self.reader.readexactly(32)

        # 4️⃣ Verifica assinatura RSA
        signed_data = pk_S + self.client_id + salt

        valid = CryptoUtils.verify_signature(
            cert_bytes,
            signature,
            signed_data
        )

        if not valid:
            raise Exception("Assinatura RSA inválida! Possível MITM.")

        # 5️⃣ Deriva chaves
        shared_secret = CryptoUtils.compute_ecdh_shared_secret(sk_C, pk_S)
        self.key_c2s, self.key_s2c = CryptoUtils.derive_keys(shared_secret, salt)

    async def send_message(self, recipient_id_hex, message):
        """Envia mensagem cifrada para outro cliente"""
        recipient_id = bytes.fromhex(recipient_id_hex)

        nonce = CryptoUtils.generate_nonce()
        seq_no = self.seq_send
        seq_no_bytes = struct.pack("!Q", seq_no)
        self.seq_send += 1

        aad = self.client_id + recipient_id + seq_no_bytes

        ciphertext = CryptoUtils.encrypt_message(
            self.key_c2s,
            nonce,
            message.encode(),
            aad
        )

        payload = (
            nonce +
            self.client_id +
            recipient_id +
            seq_no_bytes +
            ciphertext
        )

        self.writer.write(struct.pack("!I", len(payload)) + payload)
        await self.writer.drain()

    async def receive_loop(self):
        """Recebe mensagens do servidor"""
        while True:
            try:
                size_data = await self.reader.readexactly(4)
                msg_size = struct.unpack("!I", size_data)[0]

                data = await self.reader.readexactly(msg_size)

                nonce = data[:12]
                sender_id = data[12:28]
                recipient_id = data[28:44]
                seq_no_bytes = data[44:52]
                ciphertext = data[52:]

                seq_no = struct.unpack("!Q", seq_no_bytes)[0]

                # Anti-replay
                if seq_no != self.seq_recv:
                    print("[!] Replay ou mensagem fora de ordem detectada")
                    continue

                self.seq_recv += 1

                aad = sender_id + recipient_id + seq_no_bytes

                plaintext = CryptoUtils.decrypt_message(
                    self.key_s2c,
                    nonce,
                    ciphertext,
                    aad
                )

                print("\n" + "=" * 60)
                print(f"📨 Nova mensagem de {sender_id.hex()[:8]}...")
                print("=" * 60)
                print(plaintext.decode())
                print("=" * 60)

            except asyncio.IncompleteReadError:
                print("[!] Conexão encerrada pelo servidor")
                break
            except Exception as e:
                print(f"[!] Erro ao receber mensagem: {e}")

    async def input_loop(self):
        loop = asyncio.get_running_loop()

        while True:
            cmd = await loop.run_in_executor(None, input, "Comando: ")
            cmd = cmd.strip()

            if cmd.lower() in {"exit", "quit"}:
                print("[*] Encerrando cliente...")
                self.writer.close()
                await self.writer.wait_closed()
                return

            if cmd.startswith("send "):
                _, recipient, *msg = cmd.split(" ")
                message = " ".join(msg)
                await self.send_message(recipient, message)
            else:
                print("Uso: send <recipient_id_hex> <mensagem>")

    async def run(self):
        await self.connect()
        await asyncio.gather(
            self.receive_loop(),
            self.input_loop()
        )


if __name__ == "__main__":
    client = SecureMessagingClient()
    asyncio.run(client.run())
