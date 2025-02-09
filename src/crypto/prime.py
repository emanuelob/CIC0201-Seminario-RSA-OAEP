import random

def miller_rabin(n, k=40):  # Teste de primalidade probabilística
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False

    # Escreve n-1 como 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False

    return True

def generate_large_prime(bits):
    while True:
        prime = random.getrandbits(bits)
        prime |= (1 << bits - 1) | 1  # Garante que o número tem o tamanho correto e é ímpar
        if miller_rabin(prime):
            return prime
        
def gcd_euclides(a: int, b: int) -> int:
    """
    Calcula o MDC de dois números usando o algoritmo de Euclides.
    """
    while b:
        a, b = b, a % b
    return a
