from gmpy2 import random_state, next_prime, mpz_urandomb
import random
import sys

def generate_prime(bits):
    """
    Gera um número primo com o número especificado de bits.
    
    Args:
        bits (int): Número de bits do primo desejado
    
    Returns:
        int: Número primo
    """
    print(f"Iniciando geração de primo de {bits} bits...")
    
    # Usa o random do sistema para seed
    seed = random.randint(0, sys.maxsize)
    rand_state = random_state(seed)

    while True:
        try:
            # Gera número aleatório e garante que seja ímpar e tenha o tamanho correto
            num = mpz_urandomb(rand_state, bits)
            num |= (1 << (bits - 1)) | 1  # Garante bits-1 e faz o número ser ímpar
            
            prime = next_prime(num)
            
            # Verifica se o primo tem o tamanho correto
            if prime.bit_length() == bits:
                return int(prime)
                        
        except Exception as e:
            print(f"Erro durante geração: {e}")
            print("Tentando novamente com nova seed...")
            seed = random.randint(0, sys.maxsize)
            rand_state = random_state(seed)