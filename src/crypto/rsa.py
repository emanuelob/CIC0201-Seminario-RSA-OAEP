from .prime import generate_prime

class RSA:
    def __init__(self):
        self.public_key = None
        self.private_key = None
        self.n = None
    
    def generate_keys(self, bits=1024):
        """
        Gera as chaves pública e privada RSA.
        
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