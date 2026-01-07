# 🔒 Sistema de Mensageria Segura

Implementação acadêmica de um sistema cliente-servidor de mensageria com criptografia de ponta, sem uso de TLS pronto.

## 📋 Características de Segurança

### ✅ Implementado

- **ECDHE (P-256)**: Troca de chaves com sigilo perfeito (Forward Secrecy)
- **AES-128-GCM**: Cifragem autenticada (AEAD - Authenticated Encryption with Associated Data)
- **RSA-2048**: Assinatura digital da chave efêmera do servidor
- **HKDF (SHA-256)**: Derivação de chaves conforme TLS 1.3
- **Anti-Replay**: Proteção via sequence numbers monotônicos
- **Separação de chaves**: Chaves diferentes para cada direção (c2s / s2c)
- **Validação de integridade**: Tag de autenticação GCM

### ❌ Proteções Garantidas

- ✅ **Confidencialidade**: Mensagens cifradas com AES-128
- ✅ **Integridade**: Tag GCM detecta modificações
- ✅ **Autenticidade**: Assinatura RSA prova identidade do servidor
- ✅ **Forward Secrecy**: Chaves ECDHE efêmeras descartadas após sessão
- ✅ **Anti-MITM**: Validação de certificado e assinatura
- ✅ **Anti-Replay**: Sequence numbers impedem retransmissão

---

## 🏗️ Arquitetura do Protocolo

### 1️⃣ Handshake (Estabelecimento de Sessão)

```
Cliente                                    Servidor
   |                                          |
   | 1. client_id (16B) + pk_C               |
   |----------------------------------------->|
   |                                          |
   |     2. pk_S + cert + signature + salt   |
   |<-----------------------------------------|
   |                                          |
   | 3. Valida cert e signature               |
   |    Se inválido → ABORTA                  |
   |                                          |
   | 4. Deriva chaves via HKDF                |
   |    Z = ECDH(sk_C, pk_S)                  |
   |    PRK = HKDF-Extract(salt, Z)           |
   |    Key_c2s = HKDF-Expand(PRK, "c2s")     |
   |    Key_s2c = HKDF-Expand(PRK, "s2c")     |
```

#### Por que essa estrutura?

- **client_id**: Identifica cliente unicamente
- **pk_C / pk_S**: Chaves públicas ECDHE efêmeras
- **signature**: RSA_sign(pk_S || client_id || salt)
  - Garante que pk_S foi gerada pelo servidor legítimo
  - Vincula assinatura ao cliente específico
  - Inclui salt no contexto autenticado
- **salt**: Aleatoriedade para HKDF (previne pré-computação)

### 2️⃣ Estrutura da Mensagem

```
+----------------+------------------+------------------+
| nonce (12B)    | sender_id (16B)  | recipient_id(16B)|
+----------------+------------------+------------------+
| seq_no (8B)    | ciphertext + tag (variável)        |
+-----------------------------------------------------|
```

- **nonce**: Único por mensagem (NUNCA reutilizado com mesma chave)
- **sender_id / recipient_id**: Identificação de origem e destino
- **seq_no**: Contador monotônico (anti-replay)
- **AAD**: `sender_id || recipient_id || seq_no` (autenticado mas não cifrado)
- **tag**: 16 bytes de autenticação GCM

### 3️⃣ Fluxo de Mensagens

```
Cliente A                     Servidor                    Cliente B
    |                            |                            |
    | Cifra com Key_c2s          |                            |
    |--------------------------->|                            |
    |                            | 1. Decifra com Key_c2s     |
    |                            | 2. Valida tag              |
    |                            | 3. Valida seq_no           |
    |                            | 4. Re-cifra com Key_s2c(B) |
    |                            |--------------------------->|
    |                            |                            | Decifra com Key_s2c
    |                            |                            | Valida tag
```

#### Por que re-cifrar no servidor?

- Servidor não pode ler conteúdo (confidencialidade end-to-middle)
- Cada cliente tem chaves de sessão únicas
- Servidor atua como roteador autenticado

---

## 📦 Dependências

```bash
pip install cryptography
```

**Biblioteca**: `cryptography` (Python Cryptographic Authority)
- Implementações auditadas e testadas
- Conformidade com padrões NIST/IETF
- Proteções contra timing attacks

---

## 🚀 Como Executar

### 1. Inicie o servidor

```bash
python server.py
```

Saída esperada:
```
[*] Gerando par de chaves RSA e certificado...
[✓] Servidor pronto para aceitar conexões

============================================================
🔒 Servidor de Mensageria Segura
============================================================
Escutando em 127.0.0.1:8888

Recursos de Segurança:
  ✓ ECDHE (P-256) - Forward Secrecy
  ✓ AES-128-GCM - Cifragem Autenticada
  ✓ RSA-2048 - Assinatura Digital
  ✓ HKDF (SHA-256) - Derivação de Chaves
  ✓ Anti-Replay Protection
============================================================
```

### 2. Inicie clientes (em terminais separados)

**Cliente 1:**
```bash
python client.py
```

**Cliente 2:**
```bash
python client.py
```

### 3. Envie mensagens

No **Cliente 1**, copie o ID exibido. Exemplo:
```
Seu ID: a1b2c3d4e5f67890a1b2c3d4e5f67890
```

No **Cliente 2**, envie uma mensagem:
```
Comando: send a1b2c3d4e5f67890a1b2c3d4e5f67890 Olá, mensagem segura!
```

O **Cliente 1** receberá:
```
============================================================
📨 Nova Mensagem de f9e8d7c6...
============================================================
Olá, mensagem segura!
============================================================
```

---

## 🧪 Cenários de Teste

### Teste 1: Comunicação Básica
1. Inicie servidor
2. Conecte 2 clientes
3. Troque mensagens bidirecionais
4. ✅ Verificar recepção correta

### Teste 2: Múltiplos Clientes
1. Conecte 3+ clientes
2. Cliente A → Cliente B
3. Cliente B → Cliente C
4. Cliente C → Cliente A
5. ✅ Verificar roteamento correto

### Teste 3: Desconexão e Reconexão
1. Cliente A se desconecta
2. Cliente B tenta enviar para A
3. ✅ Servidor deve rejeitar (destinatário offline)
4. Cliente A reconecta (novo ID)
5. ✅ Nova sessão estabelecida

### Teste 4: Validação de Integridade
1. Modifique `encrypt_message()` para corromper tag
2. Tente enviar mensagem
3. ✅ Decifração deve falhar no receptor

### Teste 5: Anti-Replay
1. Capture mensagem cifrada (Wireshark)
2. Retransmita mesma mensagem
3. ✅ Servidor/Cliente deve rejeitar (seq_no incorreto)

---

## 🔐 Decisões Criptográficas

### Por que ECDHE (P-256)?

**Vantagens:**
- **Forward Secrecy**: Chaves efêmeras protegem sessões passadas
- **Eficiência**: Chaves menores que RSA para mesma segurança
- **Padrão**: Usado em TLS 1.3

**Alternativas rejeitadas:**
- ❌ **DHE**: Chaves maiores, mais lento
- ❌ **RSA key exchange**: Sem forward secrecy

### Por que AES-128-GCM?

**Vantagens:**
- **AEAD**: Autenticação integrada (não precisa HMAC separado)
- **Performance**: Aceleração por hardware (AES-NI)
- **Segurança**: Resistente a padding oracle

**Alternativas rejeitadas:**
- ❌ **AES-CBC + HMAC**: Mais lento, vulnerável a ataques (Lucky13)
- ❌ **ChaCha20-Poly1305**: Sem aceleração em muitos CPUs

### Por que RSA apenas para assinatura?

**Motivo:**
- RSA para **cifragem** não tem forward secrecy
- RSA para **assinatura** autentica chaves ECDHE efêmeras
- Combinação oferece ambos: autenticidade + forward secrecy

### Por que HKDF?

**Vantagens:**
- **Padronizado**: RFC 5869, usado em TLS 1.3
- **Seguro**: Baseado em HMAC
- **Flexível**: Deriva múltiplas chaves de um segredo

**Estrutura:**
1. **Extract**: `PRK = HMAC(salt, IKM)` - Concentra entropia
2. **Expand**: `OKM = HMAC(PRK, info || counter)` - Gera chaves

### Por que sequence numbers?

**Proteção contra:**
- **Replay attack**: Retransmitir mensagem antiga
- **Reorder attack**: Embaralhar ordem das mensagens

**Implementação:**
- Contador monotônico por sessão
- Servidor/Cliente rejeitam seq_no != esperado

---

## ⚠️ Limitações Conhecidas

### 1. Certificado Autoassinado
- **Problema**: Sem PKI real, não há validação de cadeia
- **Solução para produção**: Usar Let's Encrypt ou CA corporativa

### 2. Sem Perfect Forward Secrecy entre clientes
- **Problema**: Servidor pode ler mensagens (precisa re-cifrar)
- **Solução avançada**: Implementar Signal Protocol (Double Ratchet)

### 3. Sem autenticação de clientes
- **Problema**: Qualquer um pode se conectar
- **Solução**: Adicionar autenticação via senha ou certificado cliente

### 4. Sem persistência de mensagens
- **Problema**: Mensagens perdidas se destinatário offline
- **Solução**: Fila de mensagens no servidor

### 5. Sem proteção contra DoS
- **Problema**: Servidor pode ser sobrecarregado
- **Solução**: Rate limiting, CAPTCHAs

---

## 🛡️ Análise de Ameaças

| Ameaça | Proteção | Implementado |
|--------|----------|--------------|
| **Espionagem (eavesdropping)** | AES-128-GCM | ✅ |
| **MITM (Man-in-the-Middle)** | Assinatura RSA | ✅ |
| **Replay attack** | Sequence numbers | ✅ |
| **Modificação de mensagens** | Tag GCM | ✅ |
| **Key compromise** | Forward Secrecy (ECDHE) | ✅ |
| **Negação de serviço (DoS)** | Rate limiting | ❌ |
| **Injeção de mensagens** | AAD + tag | ✅ |

---

## 📚 Referências

1. **RFC 8446** - TLS 1.3 (HKDF, ECDHE, estrutura geral)
2. **RFC 5869** - HKDF (Key Derivation)
3. **NIST SP 800-38D** - GCM Mode
4. **NIST FIPS 186-4** - Digital Signature Standard (ECDSA/RSA)
5. **Cryptography Engineering** - Ferguson, Schneier, Kohno

---

## 👨‍💻 Autor

Trabalho acadêmico - Segurança de Redes

---

## 📝 Notas Finais

### O que NÃO fazer em produção:

1. ❌ Usar certificado autoassinado sem validação manual
2. ❌ Aceitar conexões sem autenticação de cliente
3. ❌ Rodar sem logs de auditoria
4. ❌ Ignorar proteções contra DoS
5. ❌ Implementar criptografia do zero (use TLS!)

### O que SEMPRE fazer:

1. ✅ Usar bibliotecas auditadas (`cryptography`, `openssl`)
2. ✅ Nunca reutilizar nonces
3. ✅ Validar TODAS as entradas
4. ✅ Usar chaves efêmeras (forward secrecy)
5. ✅ Logs de segurança (tentativas de replay, falhas de autenticação)

---

**Este código é para fins educacionais. Para produção, use TLS 1.3!**