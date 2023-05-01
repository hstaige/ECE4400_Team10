#Multithread Socket Code goes to Digamber
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

from encryption import AES_Encrypt
from encryption import ASCON_Encrypt
import time
import sys
import socket
ClientMultiSocket = socket.socket()
host = '172.17.3.18'
#host = '192.168.1.123'
port = 2004
print('Waiting for connection response')

def client_RSA_handshake(ClientSocket):
    start_time_network = time.time()
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
    finish_latency = time.time()
    
    print('network latency: ', end = '')
    print(finish_latency - start_time_network)
    return session_key
    
try:
    ClientMultiSocket.connect((host, port))
except socket.error as e:
    print(str(e))

session_key = client_RSA_handshake(ClientMultiSocket)
if True:
    print('enter something: ', end = '')
    Input = input()
    start_time = time.time()
    ciphertext = ASCON_Encrypt(str.encode(Input), session_key)
    ClientMultiSocket.send(ciphertext)
    res = ClientMultiSocket.recv(1024)
    numbytes = len(res.decode('utf-8'))
    print(res.decode('utf-8'))
    finish_time = time.time()
    print('time: ',end = '')
    print(finish_time-start_time,flush=True)
    print('byte efficiency: ', end='')
    print(round(100*(numbytes-16)/(numbytes+8),2), end ='')
    print('%')
    print('message size: ', end = '')
    print(numbytes-16)
    print('throughput: ', end='')
    print(round((numbytes-16)/(finish_time-start_time),2),end ='')
    print(' in Bytes/s')

    ClientMultiSocket.close()
ClientMultiSocket.close()
sys.exit()