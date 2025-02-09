import os
from .prime import generate_prime

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
        p = generate_prime(bits)
        print(f"Primo p = {p}")
        
        # Gera segundo primo (garantindo que seja diferente do primeiro)
        max_attempts = 5
        attempts = 0
        
        while attempts < max_attempts:
            q = generate_prime(bits)
            if p != q:
                break
            attempts += 1
        
        if p == q:
            raise ValueError("Não foi possível gerar primos distintos após várias tentativas")
            
        print(f"Primo q = {q}")

        # Calcula n e phi(n)
        self.n = p * q
        phi = (p - 1) * (q - 1)
        
        # Escolhe o expoente público e
        e = 65537  # Valor comum para o expoente público
        
        # Calcula o expoente privado d
        d = pow(e, -1, phi)  # Inverso multiplicativo modular
        
        self.public_key = (e, self.n)
        self.private_key = (d, self.n)
        
        print(f"Chave pública: {self.public_key}")
        print(f"Chave privada: {self.private_key}")

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
        Cifra uma mensagem usando RSA puro (sem padding).
        """
        e, n = self.public_key
        cipher = pow(message, e, n)
        print("Mensagem cifrada com sucesso: ", cipher)
        return cipher
    
    def decrypt(self, ciphertext: int) -> int:
        """
        Decifra uma mensagem usando RSA puro (sem padding).
        """
        d, n = self.private_key
        message = pow(ciphertext, d, n)
        print("Mensagem decifrada com sucesso", message)
        return message

    def encrypt_from_file(self, input_file="mensagem.txt", output_file="mensagem_cifrada.txt"):
        """
        Lê uma mensagem de um arquivo, cifra com RSA e salva em outro arquivo.
        """
        if not os.path.exists("chave_publica.txt"):
            print("Erro: Arquivo 'chave_publica.txt' não encontrado. Gere as chaves primeiro.")
            return

        # Lendo a chave pública do arquivo
        with open("chave_publica.txt", "r") as pub_file:
            e = int(pub_file.readline().strip())
            n = int(pub_file.readline().strip())

        # Lendo a mensagem do arquivo
        with open(input_file, "r", encoding="utf-8") as file:
            message = file.read().strip()

        # Convertendo a mensagem para inteiro
        message_int = int.from_bytes(message.encode(), 'big')

        if message_int >= n:
            print("Erro: A mensagem é muito grande para ser cifrada com essa chave RSA.")
            return

        # Cifrando a mensagem
        cipher = pow(message_int, e, n)

        # Salvando o resultado cifrado
        with open(output_file, "w") as file:
            file.write(str(cipher))

        print(f"Mensagem cifrada salva em '{output_file}'.")
         
    def decrypt_from_file(self, input_file="mensagem_cifrada.txt", output_file="mensagem_decifrada.txt"):
        """
        Lê um arquivo com a mensagem cifrada, decifra com RSA e salva o resultado em outro arquivo.
        """
        if not os.path.exists("chave_privada.txt"):
            print("Erro: Arquivo 'chave_privada.txt' não encontrado. Gere as chaves primeiro.")
            return

        # Lendo a chave privada do arquivo
        with open("chave_privada.txt", "r") as priv_file:
            d = int(priv_file.readline().strip())
            n = int(priv_file.readline().strip())

        # Lendo a mensagem cifrada do arquivo
        with open(input_file, "r") as file:
            ciphertext = int(file.read().strip())

        # Decifrando a mensagem
        message_int = pow(ciphertext, d, n)

        # Convertendo de inteiro para string
        try:
            message_bytes = message_int.to_bytes((message_int.bit_length() + 7) // 8, 'big')
            message = message_bytes.decode()
        except Exception as e:
            print("Erro ao converter a mensagem decifrada:", e)
            return

        # Salvando a mensagem decifrada
        with open(output_file, "w", encoding="utf-8") as file:
            file.write(message)

        print(f"Mensagem decifrada salva em '{output_file}'.")

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