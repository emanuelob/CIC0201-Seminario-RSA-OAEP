from ..hash.sha3 import calculate_hash
from ..utils.base64_handler import Base64Handler
import os

class Signer:
    def __init__(self, rsa):
        """
        Inicializa o assinador com uma instância RSA.
        
        Args:
            rsa: Instância da classe RSA com chaves geradas
        """
        self.rsa = rsa
        self.base64_handler = Base64Handler()

    def sign_message(self, message: bytes) -> str:
        """
        Assina uma mensagem usando RSA e SHA-3.
        
        Args:
            message (bytes): Mensagem para assinar
            
        Returns:
            str: Documento assinado em formato BASE64
        """        
        # 1. Calcula o hash da mensagem
        message_hash = calculate_hash(message)
        
        # 2. Converte o hash para inteiro
        hash_int = int.from_bytes(message_hash, 'big')
        
        # 3. Cifra o hash (assina) usando a chave privada
        signature_int = self.rsa.decrypt(hash_int)  #usa decrypt pois assinar é cifrar com d
        
        # 4. Converte a assinatura para bytes
        signature = signature_int.to_bytes((signature_int.bit_length() + 7) // 8, 'big')
        
        # 5. Formata o resultado
        formatted_signature = self.base64_handler.format_signature(
            message,
            signature,
            self.rsa.public_key
        )
        
        print("Assinatura concluída com sucesso!")
        return formatted_signature

    def verify_signature(self, signed_document: str) -> bool:
        """
        Verifica se uma assinatura digital é válida.
        
        Args:
            signed_document (str): Documento assinado em formato BASE64.
        
        Returns:
            bool: True se a assinatura for válida, False caso contrário.
        """
        try:
            # 1. Parsing do documento assinado e decifração da mensagem (BASE64)
            message, signature, public_key = self.base64_handler.parse_signature(signed_document)
            
            # 2. Calcula o hash da mensagem original
            calculated_hash = calculate_hash(message)
            calculated_hash_int = int.from_bytes(calculated_hash, 'big')
            
            # 3. Decifração da assinatura (usando chave pública)
            signature_int = int.from_bytes(signature, 'big')
            decrypted_hash_int = pow(signature_int, public_key[0], public_key[1])  # signature^e mod n
            
            # 4. Verificação: compara o hash calculado com o hash decifrado
            return calculated_hash_int == decrypted_hash_int
            
        except Exception as e:
            raise ValueError(f"Erro na verificação da assinatura: {e}")
        
    def sign_message_from_file(self, input_file="mensagem.txt", output_file="assinatura.txt"):
        """
        Lê uma mensagem de um arquivo, assina usando RSA e salva a assinatura em outro arquivo.
        """
        if not os.path.exists(input_file):
            print(f"Erro: Arquivo '{input_file}' não encontrado.")
            return

        # Garante que a chave privada e pública sejam carregadas corretamente
        if not self.rsa.load_private_key():
            print("Erro: Não foi possível carregar a chave privada.")
            return

        if not self.rsa.load_public_key():
            print("Erro: Não foi possível carregar a chave pública.")
            return

        # Lendo a mensagem do arquivo
        with open(input_file, "r", encoding="utf-8") as file:
            message = file.read().strip()

        # Convertendo para bytes
        message_bytes = message.encode()

        # Calcula o hash da mensagem
        message_hash = calculate_hash(message_bytes)

        # Converte o hash para inteiro
        hash_int = int.from_bytes(message_hash, 'big')

        # Assina (cifra com a chave privada)
        signature_int = self.rsa.decrypt(hash_int)  # Assinatura = Hash^d mod n

        # Converte a assinatura para bytes
        signature = signature_int.to_bytes((signature_int.bit_length() + 7) // 8, 'big')

        # Agora temos certeza de que a chave pública está carregada corretamente
        formatted_signature = self.base64_handler.format_signature(
            message_bytes, signature, self.rsa.public_key
        )

        # Salva a assinatura no arquivo
        with open(output_file, "w", encoding="utf-8") as file:
            file.write(formatted_signature)

        print(f"Assinatura salva em '{output_file}'.")

    def verify_signature_from_file(self, signature_file="assinatura.txt"):
        """
        Lê uma assinatura de um arquivo, verifica a autenticidade e informa se é válida.
        """
        if not os.path.exists(signature_file):
            print(f"Erro: Arquivo '{signature_file}' não encontrado.")
            return

        # Garante que a chave pública seja carregada corretamente
        if not self.rsa.load_public_key():
            print("Erro: Não foi possível carregar a chave pública.")
            return

        # Lendo a assinatura do arquivo
        with open(signature_file, "r", encoding="utf-8") as file:
            signed_document = file.read().strip()

        try:
            # 1. Parsing do documento assinado e decifração da mensagem (BASE64)
            message, signature, public_key = self.base64_handler.parse_signature(signed_document)

            # 2. Calcula o hash da mensagem original
            calculated_hash = calculate_hash(message)
            calculated_hash_int = int.from_bytes(calculated_hash, 'big')

            # 3. Decifração da assinatura (usando chave pública)
            signature_int = int.from_bytes(signature, 'big')
            decrypted_hash_int = pow(signature_int, public_key[0], public_key[1])  # signature^e mod n

            # 4. Verificação: compara o hash calculado com o hash decifrado
            if calculated_hash_int == decrypted_hash_int:
                print("✅ Assinatura válida! A mensagem não foi alterada.")
                return True
            else:
                print("❌ Assinatura inválida! A mensagem pode ter sido alterada.")
                return False

        except Exception as e:
            print(f"Erro na verificação da assinatura: {e}")
            return False
