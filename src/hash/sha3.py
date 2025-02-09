from hashlib import sha3_256

def calculate_hash(message: bytes) -> bytes:
    """
    Calcula o hash SHA-3 (256 bits) de uma mensagem.
    
    Args:
        message (bytes): Mensagem para calcular o hash
        
    Returns:
        bytes: Hash SHA-3 da mensagem
    """
    hasher = sha3_256()
    hasher.update(message)
    hash_value = hasher.digest()
    # print(f"Hash calculado (hex): {hash_value.hex()[:100]}...")
    return hash_value