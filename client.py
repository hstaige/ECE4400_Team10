#Multithread Socket Code goes to Digamber
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

from encryption import AES_Encrypt

import socket
ClientMultiSocket = socket.socket()
host = '127.0.0.1'
port = 2004
print('Waiting for connection response')

def client_RSA_handshake(ClientSocket):
    public_key_bytes = ClientSocket.recv(2048)
    print(public_key_bytes)
    public_key = RSA.import_key(public_key_bytes)

    session_key = get_random_bytes(16)
    cipher_rsa = PKCS1_OAEP.new(public_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    print('SENDING ENC SESSION KEY')
    print(enc_session_key)
    ClientSocket.send(enc_session_key)

    print(ClientSocket.recv(1024))

    return session_key

try:
    ClientMultiSocket.connect((host, port))
except socket.error as e:
    print(str(e))

session_key = client_RSA_handshake(ClientMultiSocket)
while True:
    Input = input('Hey there: ')
    ciphertext = AES_Encrypt(str.encode(Input), session_key)
    ClientMultiSocket.send(ciphertext)
    res = ClientMultiSocket.recv(1024)
    print(res.decode('utf-8'))
ClientMultiSocket.close()
