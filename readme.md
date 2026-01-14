
# 🔒 Sistema de Mensageria Segura (Secure Messaging)

Este projeto implementa uma aplicação de mensageria multi-cliente segura, focada em garantir a confidencialidade, integridade e autenticidade das comunicações sem depender de bibliotecas de TLS prontas, utilizando primitivas criptográficas modernas.

## 🛡️ Garantias de Segurança Implementadas

O sistema foi desenhado para cumprir os seguintes requisitos rigorosos:

* 
**Confidencialidade**: Mensagens protegidas com **AES-128-GCM** (AEAD), tornando-as ilegíveis para terceiros.


* 
**Integridade**: Detecção de alterações não autorizadas através da **Tag de autenticação** do AES-GCM.


* 
**Autenticidade do Servidor**: O servidor é autenticado via **Certificado RSA-2048** autoassinado, garantindo que o cliente se liga ao servidor legítimo.


* **Sigilo Perfeito (Forward Secrecy)**: Utilização de chaves efêmeras **ECDHE (P-256)**. Mesmo que a chave RSA do servidor seja comprometida no futuro, as conversas passadas permanecem seguras.


* 
**Proteção Anti-Replay**: Uso de números de sequência (**seq_no**) monotónicos para evitar a retransmissão de mensagens capturadas.



## 🏗️ Arquitetura do Protocolo

### 1. Handshake e Derivação de Chaves

O processo de estabelecimento de sessão segue o padrão de segurança do TLS 1.3:

1. O Cliente envia o seu ID e chave pública efêmera `pk_C`.


2. O Servidor responde com a sua chave pública `pk_S`, o seu certificado RSA e uma assinatura digital.


3. A assinatura do servidor cobre `pk_S || client_id || salt` para garantir o vínculo com a sessão atual.


4. Ambos derivam chaves direcionais (`Key_c2s` e `Key_s2c`) usando **HKDF-SHA256**.



### 2. Estrutura da Mensagem (Frame)

Cada pacote enviado na rede possui a seguinte estrutura protegida:
`[nonce (12B)] + [sender_id (16B)] + [recipient_id (16B)] + [seq_no (8B)] + [ciphertext + tag]`

O `sender_id`, `recipient_id` e `seq_no` são incluídos como **AAD** (Additional Authenticated Data), garantindo que estes metadados não possam ser alterados sem serem detetados.

## 🚀 Como Executar

### Pré-requisitos

* Python 3.10+
* Biblioteca `cryptography`

```bash
pip install cryptography

```

### Passo 1: Iniciar o Servidor

O servidor gera automaticamente o par de chaves RSA e o certificado ao iniciar.

```bash
python server.py

```

### Passo 2: Iniciar os Clientes

Abra terminais diferentes para cada cliente:

```bash
python client.py

```

### Passo 3: Trocar Mensagens

1. Ao iniciar, o cliente exibirá o seu **ID único**.
2. Para enviar uma mensagem, use o comando:
`send <ID_DESTINATARIO> <MENSAGEM>`

## 📂 Estrutura do Código

* `crypto.py`: Implementação das primitivas (ECDHE, AES-GCM, RSA, HKDF).
* `server.py`: Gestão de múltiplas ligações, roteamento e validação de segurança.
* `client.py`: Interface do utilizador e lógica de cifragem ponta-a-ponta com o servidor.

---

**Nota Académica**: Trabalho desenvolvido para a disciplina de Segurança 