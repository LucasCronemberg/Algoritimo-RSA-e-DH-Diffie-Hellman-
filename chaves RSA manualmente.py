import random
from sympy import isprime

# Função para gerar números primos grandes
def generate_large_prime(keysize):
    while True:
        num = random.getrandbits(keysize)
        if isprime(num):
            return num

# Função para calcular o GCD
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

# Função para calcular o inverso modular
def modinv(a, m):
    m0, x0, x1 = m, 0, 1
    if m == 1:
        return 0
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    if x1 < 0:
        x1 += m0
    return x1

# Geração das chaves RSA
def generate_rsa_keys(keysize):
    e = 65537
    p = generate_large_prime(keysize // 2)
    q = generate_large_prime(keysize // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    d = modinv(e, phi)
    return ((e, n), (d, n))

keysize = 2048
public_key, private_key = generate_rsa_keys(keysize)

print("Chave pública:", public_key)
print("Chave privada:", private_key)
