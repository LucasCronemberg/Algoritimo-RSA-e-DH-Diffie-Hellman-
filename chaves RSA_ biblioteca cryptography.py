from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Geração das chaves RSA
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

public_key = private_key.public_key()

# Serialização das chaves
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Salvando as chaves em arquivos
with open('private_key.pem', 'wb') as f:
    f.write(private_pem)

with open('public_key.pem', 'wb') as f:
    f.write(public_pem)

print("Chaves RSA geradas e salvas em arquivos 'private_key.pem' e 'public_key.pem'")
