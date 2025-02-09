# Gerador e Verificador de Assinaturas Digitais RSA

## Visão Geral
Este projeto implementa um sistema de assinatura digital RSA com padding OAEP para assinatura e verificação de arquivos. A implementação utiliza SHA-3 para hashing e codificação BASE64 para formatação de assinaturas.

## Funcionalidades Principais
- Geração de chaves RSA com primos de 1024+ bits
- Implementação OAEP (Optimal Asymmetric Encryption Padding)
- Hash SHA-3 para resumos de mensagens
- Codificação BASE64 para formatação de assinaturas
- Fluxo completo de geração e verificação de assinaturas

## Estrutura do Projeto
```
rsa_signature/
├── src/
│   ├── crypto/
│   │   ├── __init__.py         # Inicialização do módulo de criptografia
│   │   ├── rsa.py              # Implementação principal do RSA
│   │   ├── oaep.py             # Implementação do padding OAEP
│   │   └── prime.py            # Geração de números primos
│   ├── hash/
│   │   └── sha3.py             # Interface de hash SHA-3
│   ├── signature/
│   │   ├── signer.py           # Lógica de assinatura
└── main.py                     # Ponto de entrada da aplicação
└── mensagem.txt                # Mensagem de teste para a execução do programa
```

## Instalação

1. Clone o repositório:
```bash
git clone <https://github.com/emanuelob/CIC0201-Seminario-RSA-OAEP.git>
cd CIC0201-Seminario-RSA-OAEP
```

2. Execute o projeto:
```bash
python main.py
```

## Como Funciona

O sistema opera em três fases principais:

### 1. Geração de Chaves e Criptografia
- Gera chaves RSA seguras usando números primos de no mínimo 1024 bits
- Aplica teste de primalidade de Miller-Rabin
- Implementa padding OAEP para segurança aprimorada

### 2. Geração de Assinatura
- Calcula o hash SHA-3 da mensagem de entrada
- Assina o hash usando a chave privada RSA
- Formata a assinatura usando codificação BASE64

### 3. Verificação de Assinatura
- Parsing do documento assinado em BASE64 e aplicação da função de hash criptográfica na mensagem em claro 
- Após o parsing, decifra a assinatura usando a chave pública
- Verifica a integridade da mensagem comparando hashes

## Testes

Os testes para os componentes estão localizados na main.py:
- Você pode alterar a mensagem.txt após a assinatura para verificar a integridade
- Você pode testar com mensagens/arquivos maiores que 190 bytes não suportados pelo OAEP
