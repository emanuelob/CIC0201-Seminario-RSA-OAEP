from src.crypto import RSA
from src.signature.signer import Signer

def main():
    rsa = RSA()  # Criar instância para uso no menu
    signer = Signer(rsa)

    while True:
        print("\n===== MENU PRINCIPAL =====")
        print("1. Gerar chaves RSA")
        print("2. Cifrar mensagem (ler de um arquivo)")
        print("3. Decifrar mensagem")
        print("4. Assinar mensagem")
        print("5. Verificar assinatura")
        print("6. Sair")
        
        opcao = input("Escolha uma opção: ")

        if opcao == "1":
            print("\nGerando chaves RSA...")
            rsa.generate_keys(bits=1024)
            print("Chaves geradas e salvas em arquivos!")

        elif opcao == "2":
            print("\nCifrando mensagem...")
            rsa.encrypt_from_file()
            print("Operação concluída.")

        elif opcao == "3":
            print("\nDecifrando mensagem...")
            rsa.decrypt_from_file()
            print("Operação concluída.")

        elif opcao == "4":
            print("\nAssinando mensagem...")
            signer.sign_message_from_file()
            print("Operação concluída.")

        elif opcao == "5":
            print("\nVerificando assinatura...")
            signer.verify_signature_from_file()
            print("Operação concluída.")

        elif opcao == "6":
            print("Saindo...")
            break

        else:
            print("Opção inválida. Tente novamente.")

if __name__ == "__main__":
    main()
