#Multithread Socket Code goes to Digamber
import time
import socket
import os
from _thread import *
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

from encryption import AES_Decrypt
from encryption import ASCON_Decrypt
start_time = time.time()
ServerSideSocket = socket.socket()
#host = '172.17.3.18'
host = '192.168.1.123'
port = 2004
ThreadCount = 0

try:
    ServerSideSocket.bind((host, port))
except socket.error as e:
    print(str(e))
print('Socket is listening..')
ServerSideSocket.listen(5)

def server_RSA_handshake(connection):
    print('Starting RSA handshake')
    key = RSA.generate(2048)
    public_key, private_key = key.publickey(), key

    connection.send(public_key.export_key())
    enc_session_key = connection.recv(1024)
    print('Rec enc session key')
    print(enc_session_key)

    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    connection.send(str.encode('Server is working:'))

    return session_key



def multi_threaded_client(connection):
    session_key = server_RSA_handshake(connection)

    while True:
        data = connection.recv(2048)
        if not data:
            break

        print('Recieved Encrypted Message')
        print(data)
        data = ASCON_Decrypt(data, session_key)

        if data.decode('utf-8') == 'exit': break

        response = 'Server message: '  + data.decode('utf-8')
        connection.sendall(str.encode(response))
    connection.close()

while True:
    Client, address = ServerSideSocket.accept()
    print('Connected to: ' + address[0] + ':' + str(address[1]))
    start_new_thread(multi_threaded_client, (Client, ))
    ThreadCount += 1
    print('Thread Number: ' + str(ThreadCount))
ServerSideSocket.close()
