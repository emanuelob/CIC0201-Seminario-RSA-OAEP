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
│   ├── utils/
│   │   ├── base64_handler.py   # Utilitários de codificação BASE64
└── main.py                     # Ponto de entrada da aplicação
└── requirements.txt            # Dependências do projeto
```

## Instalação

1. Clone o repositório:
```bash
git clone <https://github.com/emanuelob/CIC0201-Seminario-RSA-OAEP.git>
cd CIC0201-Seminario-RSA-OAEP
```

2. Instale a dependência necessária:
```bash
pip install gmpy2
```

3. Executando o projeto:
```bash
python main.py
```

## Como Funciona

O sistema opera em três fases principais:

### 1. Geração de Chaves e Criptografia
- Gera chaves RSA seguras usando números primos de no mínimo 1024 bits
- Implementa padding OAEP para segurança aprimorada
- Utiliza geração eficiente de primos com a biblioteca gmpy2

### 2. Geração de Assinatura
- Calcula o hash SHA-3 da mensagem de entrada
- Assina o hash usando a chave privada RSA
- Formata a assinatura usando codificação BASE64 com metadados

### 3. Verificação de Assinatura
- Analisa o documento assinado para extrair componentes
- Decifra a assinatura usando a chave pública
- Verifica a integridade da mensagem comparando hashes

## Testes

Os testes para os componentes estão localizados na main.py:
- Criptografia/descriptografia RSA com OAEP
- Geração e verificação de assinaturas
- Cálculo e verificação de hash
- Codificação/decodificação BASE64
