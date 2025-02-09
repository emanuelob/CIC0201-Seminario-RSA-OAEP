import os
from hashlib import sha256

class OAEP:
    def __init__(self, n_len):
        self.k = n_len  # Tamanho em bytes do módulo RSA
        self.hLen = 32  # SHA-256 produz 32 bytes
        self.maxMessageLength = self.k - 2 * self.hLen - 2
        print(f"Tamanho máximo de mensagem: {self.maxMessageLength} bytes")
    
    def mgf1(self, seed: bytes, length: int) -> bytes:
        mask = b''
        counter = 0
        while len(mask) < length:
            C = counter.to_bytes(4, 'big')
            mask += sha256(seed + C).digest()
            counter += 1
        return mask[:length]
    
    def pad(self, message: bytes) -> bytes:
        print("\nIniciando padding OAEP...")
        
        if len(message) > self.maxMessageLength:
            raise ValueError(f"Mensagem muito longa: {len(message)} > {self.maxMessageLength}")
        
        lHash = sha256(b'').digest()
        PS = b'\x00' * (self.k - len(message) - 2 * self.hLen - 2)
        DB = lHash + PS + b'\x01' + message
        
        seed = os.urandom(self.hLen)

        dbMask = self.mgf1(seed, self.k - self.hLen - 1)
        maskedDB = bytes(a ^ b for a, b in zip(DB, dbMask))
        seedMask = self.mgf1(maskedDB, self.hLen)
        maskedSeed = bytes(a ^ b for a, b in zip(seed, seedMask))       
        
        return b'\x00' + maskedSeed + maskedDB
    
    def unpad(self, padded: bytes) -> bytes:
        print("\nIniciando remoção do padding OAEP...")
        
        maskedSeed = padded[1:1+self.hLen]
        maskedDB = padded[1+self.hLen:]
        
        seedMask = self.mgf1(maskedDB, self.hLen)
        seed = bytes(a ^ b for a, b in zip(maskedSeed, seedMask))
        dbMask = self.mgf1(seed, self.k - self.hLen - 1)
        DB = bytes(a ^ b for a, b in zip(maskedDB, dbMask))
        
        lHash = DB[:self.hLen]
        i = self.hLen
        while i < len(DB) and DB[i] == 0:
            i += 1
            
        if i >= len(DB) or DB[i] != 1:
            raise ValueError("Erro na decifração: padding inválido")
        
        mensagem = DB[i+1:]
        return mensagem