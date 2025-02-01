from src.crypto import RSA, OAEP
from src.signature.signer import Signer
from src.utils.base64_handler import Base64Handler

def test_rsa_oaep(bits=1024, test_message=b"Teste de RSA com OAEP"):
    print("="*50)
    print("Iniciando teste de RSA com OAEP...")
    print("="*50)

    # 1. Gera as chaves RSA
    print("\n[1/5] Inicializando RSA e gerando chaves...")
    rsa = RSA()
    rsa.generate_keys(bits)

    # 2. Inicializa o OAEP
    print("\n[2/5] Configurando OAEP...")
    n_bytes = (rsa.n.bit_length() + 7) // 8  # Converte bits para bytes
    print(f"Tamanho do módulo n em bytes: {n_bytes}")
    oaep = OAEP(n_bytes)

    # 3. Prepara a mensagem
    print("\n[3/5] Preparando mensagem para cifração...")
    print(f"Mensagem original: {test_message}")
    print(f"Tamanho da mensagem: {len(test_message)} bytes")

    # Aplica padding OAEP
    try:
        padded_message = oaep.pad(test_message)
        print(f"Padding OAEP aplicado. Novo tamanho: {len(padded_message)} bytes")
        
        # Converte para inteiro
        padded_int = int.from_bytes(padded_message, 'big')
        
    except ValueError as e:
        print(f"Erro no padding OAEP: {e}")
        return

    # 4. Cifra a mensagem
    print("\n[4/5] Cifrando mensagem...")
    try:
        ciphertext = rsa.encrypt(padded_int)
        print(f"Mensagem cifrada (hex): {hex(ciphertext)[:50]}...")
        
    except Exception as e:
        print(f"Erro na cifração: {e}")
        return

    # 5. Decifra a mensagem
    print("\n[5/5] Decifrando mensagem...")
    try:
        # Decifra
        decrypted_int = rsa.decrypt(ciphertext)
        print("Decifração RSA concluída")
        
        # Converte de volta para bytes
        decrypted_padded = decrypted_int.to_bytes(n_bytes, 'big')
        
        # Remove padding
        decrypted_message = oaep.unpad(decrypted_padded)        
        print(f"\nPadding OAEP removido. Mensagem decifrada: {decrypted_message}")
        
        # Verifica se a mensagem foi recuperada corretamente
        if decrypted_message == test_message:
            print("\n Teste concluído com sucesso! Mensagem recuperada corretamente.")
        else:
            print("\n Erro: A mensagem decifrada não corresponde à original!")
            print(f"Original : {test_message}")
            print(f"Decifrada: {decrypted_message}")
            
    except Exception as e:
        print(f"Erro na decifração: {e}")
        return

def test_signature(bits=1024, test_message=b"Mensagem para ser assinada"):
    print("="*50)
    print("Iniciando teste de Assinatura Digital...")
    print("="*50)

    # 1. Gera as chaves RSA
    print("\n[1/3] Inicializando RSA e gerando chaves...")
    rsa = RSA()
    rsa.generate_keys(bits)

    # 2. Cria e executa o assinador
    print("\n[2/3] Assinando mensagem...")
    signer = Signer(rsa)
    signed_document = signer.sign_message(test_message)
    print(f"\nDocumento assinado (primeiros 100 caracteres):\n{signed_document[:100]}...")

    # 3. Demonstra a separação dos componentes
    print("\n[3/3] Componentes do documento assinado...")
    base64_handler = Base64Handler()
    try:
        message, signature, public_key = base64_handler.parse_signature(signed_document)
        print(f"\nMensagem recuperada: {message}")
        print(f"Tamanho da assinatura: {len(signature)} bytes")
        print(f"Chave pública recuperada (e): {public_key[0]}")
        print("\nTeste de assinatura concluído com sucesso!")
    except Exception as e:
        print(f"Erro ao processar documento assinado: {e}")

def main():
    # Teste do RSA com OAEP
    print("\n=== Teste 1: RSA com OAEP ===")
    test_rsa_oaep(bits=1024, test_message=b"Teste de RSA com OAEP")

    # Teste da Assinatura Digital
    print("\n=== Teste 2: Assinatura Digital ===")
    test_signature(bits=1024, test_message=b"Mensagem para ser assinada")

if __name__ == "__main__":
    main()