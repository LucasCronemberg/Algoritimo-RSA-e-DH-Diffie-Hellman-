import socket
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import dh
import os

# Geração dos parâmetros DH
parameters = dh.generate_parameters(generator=2, key_size=2048)
private_key = parameters.generate_private_key()
public_key = private_key.public_key()

# Iniciar o servidor
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('200.145.184.166', 40665))
server.listen(1)

print("Servidor aguardando conexão...")

conn, addr = server.accept()
print(f"Conectado por {addr}")

# Enviar chave pública
conn.send(public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))

# Receber chave pública do cliente
client_public_bytes = conn.recv(1024)
client_public_key = serialization.load_pem_public_key(client_public_bytes)

# Gerar chave simétrica
shared_key = private_key.exchange(client_public_key)
kdf = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'handshake data',
    backend=default_backend()
)
key = kdf.derive(shared_key)

# Criptografia AES
iv = os.urandom(16)
cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
encryptor = cipher.encryptor()
decryptor = cipher.decryptor()

# Comunicação segura
while True:
    encrypted_msg = conn.recv(1024)
    if not encrypted_msg:
        break
    decrypted_msg = decryptor.update(encrypted_msg) + decryptor.finalize()
    print(f"Mensagem recebida: {decrypted_msg.decode()}")

    msg = input("Digite uma mensagem para enviar: ").encode()
    encrypted_msg = encryptor.update(msg) + encryptor.finalize()
    conn.send(encrypted_msg)

conn.close()
