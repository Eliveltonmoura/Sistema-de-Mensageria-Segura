"""
Servidor de Mensageria Segura

Funcionalidades:
- Handshake ECDHE com cada cliente
- Assinatura RSA da chave efêmera (autenticidade)
- Roteamento de mensagens cifradas entre clientes
- Proteção contra replay (sequence numbers)
- Gerenciamento de sessões multi-cliente
"""

import asyncio
import struct
from crypto import CryptoUtils

class SecureMessagingServer:
    def __init__(self, host='127.0.0.1', port=8888):
        self.host = host
        self.port = port
        
        # Estrutura de sessões conforme especificação
        self.sessions = {}
        
        # Gera par RSA e certificado do servidor (permanente durante execução)
        print("[*] Gerando par de chaves RSA e certificado...")
        self.rsa_private_key, self.server_cert = CryptoUtils.generate_rsa_keypair_and_cert()
        print("[✓] Servidor pronto para aceitar conexões")
    
    async def handle_client(self, reader, writer):
        """
        Gerencia conexão de um cliente
        
        Fluxo:
        1. Handshake (estabelece chaves de sessão)
        2. Loop de mensagens
        3. Cleanup na desconexão
        """
        client_addr = writer.get_extra_info('peername')
        print(f"\n[+] Nova conexão de {client_addr}")
        
        client_id = None
        
        try:
            # ===== FASE 1: HANDSHAKE =====
            client_id = await self.perform_handshake(reader, writer)
            
            if not client_id:
                print(f"[!] Handshake falhou para {client_addr}")
                return
            
            print(f"[✓] Handshake completo com cliente {client_id.hex()[:8]}...")
            
            # ===== FASE 2: LOOP DE MENSAGENS =====
            await self.message_loop(reader, writer, client_id)
            
        except asyncio.CancelledError:
            print(f"[!] Conexão cancelada: {client_addr}")
        except Exception as e:
            print(f"[!] Erro com cliente {client_addr}: {e}")
        finally:
            # ===== FASE 3: CLEANUP =====
            if client_id and client_id in self.sessions:
                del self.sessions[client_id]
                print(f"[-] Cliente {client_id.hex()[:8]}... desconectado")
            writer.close()
            await writer.wait_closed()
    
    async def perform_handshake(self, reader, writer):
        """
        Executa handshake ECDHE + assinatura RSA
        
        Protocolo:
        1. Cliente → Servidor: client_id (16B) | pk_C
        2. Servidor → Cliente: pk_S | cert | signature | salt
        3. Ambos derivam chaves via HKDF
        
        Segurança:
        - Forward Secrecy: chaves ECDHE são efêmeras
        - Autenticidade: servidor assina pk_S com RSA
        - Freshness: salt aleatório por sessão
        
        Returns:
            bytes: client_id se sucesso, None se falha
        """
        
        # 1️⃣ Recebe: client_id + pk_C
        data = await reader.read(1024)
        if len(data) < CryptoUtils.CLIENT_ID_SIZE + 65:  # 16 + 65 bytes (chave pública P-256)
            print("[!] Handshake incompleto")
            return None
        
        client_id = data[:CryptoUtils.CLIENT_ID_SIZE]
        pk_C = data[CryptoUtils.CLIENT_ID_SIZE:]
        
        print(f"[→] Recebido client_id: {client_id.hex()[:8]}... pk_C: {len(pk_C)} bytes")
        
        # 2️⃣ Gera par ECDHE efêmero do servidor
        sk_S, pk_S = CryptoUtils.generate_ecdhe_keypair()
        salt = CryptoUtils.generate_salt()
        
        # 3️⃣ Assina pk_S || client_id || salt
        # Por que assinar esses campos?
        # - pk_S: garante que servidor gerou esta chave
        # - client_id: vincula assinatura a este cliente específico
        # - salt: inclui salt no contexto autenticado
        signature_data = pk_S + client_id + salt
        signature = CryptoUtils.sign_data(self.rsa_private_key, signature_data)
        
        # 4️⃣ Envia: pk_S | len(cert) | cert | len(sig) | sig | salt
        response = (
            pk_S +
            struct.pack("!I", len(self.server_cert)) + self.server_cert +
            struct.pack("!I", len(signature)) + signature +
            salt
        )
        
        writer.write(response)
        await writer.drain()
        print(f"[←] Enviado pk_S, certificado, assinatura e salt")
        
        # 5️⃣ Deriva chaves de sessão
        shared_secret = CryptoUtils.compute_ecdh_shared_secret(sk_S, pk_C)
        key_c2s, key_s2c = CryptoUtils.derive_keys(shared_secret, salt)
        
        # 6️⃣ Armazena sessão
        self.sessions[client_id] = {
            "writer": writer,
            "key_c2s": key_c2s,
            "key_s2c": key_s2c,
            "seq_recv": 0,  # Próximo seq_no esperado do cliente
            "seq_send": 0,  # Próximo seq_no a enviar
            "salt": salt
        }
        
        print(f"[✓] Chaves derivadas para cliente {client_id.hex()[:8]}...")
        
        return client_id
    
    async def message_loop(self, reader, writer, client_id):
        """
        Loop principal de processamento de mensagens
        
        Para cada mensagem:
        1. Decifra e autentica (cliente → servidor)
        2. Valida sequence number (anti-replay)
        3. Re-cifra (servidor → destinatário)
        4. Roteia para destinatário
        """
        session = self.sessions[client_id]
        
        while True:
            # Lê tamanho da mensagem (4 bytes)
            size_data = await reader.readexactly(4)
            msg_size = struct.unpack("!I", size_data)[0]
            
            if msg_size > 65536:  # Limite de segurança
                print(f"[!] Mensagem muito grande de {client_id.hex()[:8]}...")
                break
            
            # Lê mensagem completa
            encrypted_msg = await reader.readexactly(msg_size)
            
            # Parseia mensagem: nonce | sender | recipient | seq_no | ciphertext+tag
            if len(encrypted_msg) < 12 + 16 + 16 + 8:
                print(f"[!] Mensagem malformada")
                continue
            
            nonce = encrypted_msg[:12]
            sender_id = encrypted_msg[12:28]
            recipient_id = encrypted_msg[28:44]
            seq_no_bytes = encrypted_msg[44:52]
            ciphertext = encrypted_msg[52:]
            
            seq_no = struct.unpack("!Q", seq_no_bytes)[0]
            
            # ===== VALIDAÇÕES DE SEGURANÇA =====
            
            # 1. Sender deve ser o cliente autenticado
            if sender_id != client_id:
                print(f"[!] Spoofing detectado! sender={sender_id.hex()[:8]} != client={client_id.hex()[:8]}")
                continue
            
            # 2. Anti-replay: sequence number deve ser monotônico
            if seq_no != session["seq_recv"]:
                print(f"[!] Replay detectado! Esperado seq={session['seq_recv']}, recebido={seq_no}")
                continue
            
            session["seq_recv"] += 1
            
            # 3. Decifra e autentica com key_c2s
            aad = sender_id + recipient_id + seq_no_bytes
            
            try:
                plaintext = CryptoUtils.decrypt_message(
                    session["key_c2s"],
                    nonce,
                    ciphertext,
                    aad
                )
            except Exception as e:
                print(f"[!] Falha na autenticação da mensagem: {e}")
                continue
            
            print(f"[✓] Mensagem de {sender_id.hex()[:8]}... para {recipient_id.hex()[:8]}... ({len(plaintext)} bytes)")
            
            # ===== ROTEAMENTO =====
            
            if recipient_id not in self.sessions:
                print(f"[!] Destinatário {recipient_id.hex()[:8]}... não conectado")
                # Poderia enviar mensagem de erro ao remetente
                continue
            
            # Re-cifra com key_s2c do destinatário
            recipient_session = self.sessions[recipient_id]
            
            new_nonce = CryptoUtils.generate_nonce()
            new_seq = recipient_session["seq_send"]
            new_seq_bytes = struct.pack("!Q", new_seq)
            recipient_session["seq_send"] += 1
            
            new_aad = sender_id + recipient_id + new_seq_bytes
            
            new_ciphertext = CryptoUtils.encrypt_message(
                recipient_session["key_s2c"],
                new_nonce,
                plaintext,
                new_aad
            )
            
            # Monta mensagem re-cifrada
            forwarded_msg = (
                new_nonce +
                sender_id +
                recipient_id +
                new_seq_bytes +
                new_ciphertext
            )
            
            # Envia para destinatário
            recipient_writer = recipient_session["writer"]
            recipient_writer.write(struct.pack("!I", len(forwarded_msg)) + forwarded_msg)
            await recipient_writer.drain()
            
            print(f"[↔] Mensagem roteada para {recipient_id.hex()[:8]}...")
    
    async def start(self):
        """Inicia servidor"""
        server = await asyncio.start_server(
            self.handle_client,
            self.host,
            self.port
        )
        
        addr = server.sockets[0].getsockname()
        print(f"\n{'='*60}")
        print(f"🔒 Servidor de Mensageria Segura")
        print(f"{'='*60}")
        print(f"Escutando em {addr[0]}:{addr[1]}")
        print(f"\nRecursos de Segurança:")
        print(f"  ✓ ECDHE (P-256) - Forward Secrecy")
        print(f"  ✓ AES-128-GCM - Cifragem Autenticada")
        print(f"  ✓ RSA-2048 - Assinatura Digital")
        print(f"  ✓ HKDF (SHA-256) - Derivação de Chaves")
        print(f"  ✓ Anti-Replay Protection")
        print(f"{'='*60}\n")
        
        async with server:
            await server.serve_forever()


if __name__ == "__main__":
    server = SecureMessagingServer()
    try:
        asyncio.run(server.start())
    except KeyboardInterrupt:
        print("\n[*] Servidor encerrado")