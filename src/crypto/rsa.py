import os
from .prime import generate_large_prime
from .oaep import OAEP
import time

class RSA:
    def __init__(self):
        self.public_key = None
        self.private_key = None
        self.n = None
    
    def generate_keys(self, bits=1024):
        """
        Gera as chaves pública e privada RSA e salva em arquivos.
        
        Args:
            bits (int): Tamanho em bits de cada primo
        """
        
        # Gera primeiro primo
        start_time = time.time()
        p = generate_large_prime(bits)
        end_time = time.time()
        print(f"Tempo para gerar o primeiro primo: {end_time - start_time} segundos.")
        # print(f"Primo p = {p}")
        # print(f"Bits: {p.bit_length()}")

        # Gera segundo primo (garantindo que seja diferente do primeiro)
        max_attempts = 5
        attempts = 0
        
        while attempts < max_attempts:
            q = generate_large_prime(bits)
            if p != q:
                break
            attempts += 1
        
        if p == q:
            raise ValueError("Não foi possível gerar primos distintos após várias tentativas")

        # print(f"Primo q = {q}")
        # print(f"Bits: {q.bit_length()}")
           
        # Calcula n e phi(n)
        self.n = p * q
        phi = (p - 1) * (q - 1)
        
        # Escolhe o expoente público e (2^16 + 1)
        e = 65537  
        
        # Calcula o expoente privado d --> d * e ≡ 1 (mod phi)
        d = pow(e, -1, phi)  # Inverso multiplicativo modular
        
        self.public_key = (e, self.n)
        self.private_key = (d, self.n)
        
        # Salva as chaves em arquivos
        self.salvar_chaves_em_arquivos()

    def salvar_chaves_em_arquivos(self):
        """
        Salva as chaves RSA geradas em arquivos de texto.
        """
        with open("chave_publica.txt", "w") as pub_file:
            pub_file.write(f"{self.public_key[0]}\n{self.public_key[1]}")
        
        with open("chave_privada.txt", "w") as priv_file:
            priv_file.write(f"{self.private_key[0]}\n{self.private_key[1]}")
        
        print("Chaves RSA salvas em 'chave_publica.txt' e 'chave_privada.txt'.")

    def encrypt(self, message: int) -> int:
        """
        Cifra uma mensagem usando RSA.
        """
        e, d = self.private_key
        cipher = pow(message, e, d)
        # print("Mensagem cifrada com sucesso: ", cipher)
        return cipher
    
    def decrypt(self, ciphertext: int) -> int:
        """
        Decifra uma mensagem usando RSA.
        """
        e, n = self.public_key
        message = pow(ciphertext, e, n)
        # print("Mensagem decifrada com sucesso", message)
        return message
    
    def encrypt_with_oaep(self, message_bytes: bytes) -> int:
        """
        Cifra uma mensagem usando RSA com padding OAEP.
        
        Args:
            message_bytes (bytes): Mensagem em bytes para ser cifrada
            
        Returns:
            int: Mensagem cifrada
        """
        if not self.private_key:
            raise ValueError("Chave privada não disponível")
            
        # Cria instância OAEP com tamanho do módulo RSA
        n_bytes = (self.n.bit_length() + 7) // 8
        oaep = OAEP(n_bytes)
        
        # Aplica padding OAEP
        padded_message = oaep.pad(message_bytes)
        padded_int = int.from_bytes(padded_message, 'big')
        
        if padded_int >= self.n:
            raise ValueError("Mensagem muito grande após padding OAEP")
            
        # Cifra com RSA
        return self.encrypt(padded_int)

    def decrypt_with_oaep(self, ciphertext: int) -> bytes:
        """
        Decifra uma mensagem usando RSA e remove o padding OAEP.
        
        Args:
            ciphertext (int): Mensagem cifrada
            
        Returns:
            bytes: Mensagem original em bytes
        """
        if not self.public_key:
            raise ValueError("Chave pública não disponível")
            
        # Decifra com RSA
        padded_int = self.decrypt(ciphertext)
        
        # Cria instância OAEP com tamanho do módulo RSA
        n_bytes = (self.n.bit_length() + 7) // 8
        oaep = OAEP(n_bytes)
        
        # Converte para bytes e remove padding OAEP
        padded_bytes = padded_int.to_bytes(n_bytes, 'big')
        return oaep.unpad(padded_bytes)

    def encrypt_from_file(self, input_file="mensagem.txt", output_file="mensagem_cifrada.txt"):
        """
        Lê uma mensagem de um arquivo, aplica OAEP, cifra com RSA e salva em outro arquivo.
        """
        if not os.path.exists("chave_privada.txt"):
            print("Erro: Arquivo 'chave_privada.txt' não encontrado. Gere as chaves primeiro.")
            return

        # Carrega a chave pública
        if not self.load_public_key():
            return

        try:
            # Lê a mensagem do arquivo
            with open(input_file, "r", encoding="utf-8") as file:
                message = file.read().strip()

            # Converte a mensagem para bytes e aplica OAEP + RSA
            message_bytes = message.encode('utf-8')
            cipher_int = self.encrypt_with_oaep(message_bytes)
            
            # Salva o resultado
            with open(output_file, "w") as file:
                file.write(str(cipher_int))
                
            print(f"Mensagem cifrada salva em '{output_file}'.")
            
        except Exception as e:
            print(f"Erro no processo de cifração: {e}")
            return

    def decrypt_from_file(self, input_file="mensagem_cifrada.txt", output_file="mensagem_decifrada.txt"):
        """
        Lê mensagem cifrada, decifra com RSA, remove OAEP e salva resultado.
        """
        if not os.path.exists("chave_publica.txt"):
            print("Erro: Arquivo 'chave_publica.txt' não encontrado. Gere as chaves primeiro.")
            return

        # Carrega a chave privada
        if not self.load_private_key():
            return

        try:
            # Lê a mensagem cifrada
            with open(input_file, "r") as file:
                cipher_int = int(file.read().strip())

            # Decifra com RSA e remove OAEP
            message_bytes = self.decrypt_with_oaep(cipher_int)
            message = message_bytes.decode('utf-8')
            
            # Salva a mensagem decifrada
            with open(output_file, "w", encoding="utf-8") as file:
                file.write(message)
                
            print(f"Mensagem decifrada salva em '{output_file}'.")
                
        except Exception as e:
            print(f"Erro no processo de decifração: {e}")
            return

    def load_private_key(self, private_key_file="chave_privada.txt"):
        """
        Carrega a chave privada do arquivo e armazena na instância da classe.
        """
        if not os.path.exists(private_key_file):
            print(f"Erro: Arquivo '{private_key_file}' não encontrado. Gere as chaves primeiro.")
            return False

        with open(private_key_file, "r") as file:
            try:
                d = int(file.readline().strip())
                n = int(file.readline().strip())
                self.private_key = (d, n)
                return True
            except ValueError:
                print("Erro ao carregar a chave privada.")
                return False
    
    def load_public_key(self, public_key_file="chave_publica.txt"):
        """
        Carrega a chave pública do arquivo e armazena na instância da classe.
        """
        if not os.path.exists(public_key_file):
            print(f"Erro: Arquivo '{public_key_file}' não encontrado. Gere as chaves primeiro.")
            return False

        with open(public_key_file, "r") as file:
            try:
                e = int(file.readline().strip())
                n = int(file.readline().strip())
                self.public_key = (e, n)
                return True
            except ValueError:
                print("Erro ao carregar a chave pública.")
                return False