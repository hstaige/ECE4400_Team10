#Multithread Socket Code goes to Digamber
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from encryption import Decode_Encryption_Method
import socket
import time

ClientMultiSocket = socket.socket()
#host = '127.0.0.1'
host = '172.17.2.16'
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

    print(ClientSocket.recv(1024).decode('utf-8'))

    return session_key

def recv_experiment_details(ClientSocket):
    print('Starting to recieve experiment details')
    config = dict()
    config['enc_method'] = int(ClientSocket.recv(1024).decode('utf-8'))
    ClientMultiSocket.send(str.encode('Received'))
    config['packet_bytes'] = int(ClientSocket.recv(1024).decode('utf-8'))
    ClientMultiSocket.send(str.encode('Received'))
    config['n_packets_bundled'] = int(ClientSocket.recv(1024).decode('utf-8'))
    ClientMultiSocket.send(str.encode('Received'))
    config['packets_per_sec'] = int(ClientSocket.recv(1024).decode('utf-8'))
    ClientMultiSocket.send(str.encode('Received'))
    config['tot_packets'] = int(ClientSocket.recv(1024).decode('utf-8'))
    ClientMultiSocket.send(str.encode('Received'))

    time.sleep(0.5)
    print('recieved details')
    ClientSocket.send(str.encode('Good to go!'))
    print('and sent confirmation back.')

    return config

def await_syncronization(ClientSocket):
    ClientSocket.recv(1024)

def run_experiment(ClientSocket, config, session_key):
    encryption_method, decryption_method = Decode_Encryption_Method(config['enc_method'])

    prev_time = time.time()
    bundle, bundle_size = bytes(), 0
    for packet_num in range(config['tot_packets']):

        #print(f'Adding packet {packet_num}')
        data = str.encode(str(packet_num))
        data += str.encode('0') * (config['packet_bytes'] - len(data))
        bundle += data
        bundle_size += 1

        while time.time() - prev_time <  1 / config['packets_per_sec']:
            continue

        if bundle_size == config['n_packets_bundled']:
            ciphertext = encryption_method(bundle, session_key)
            ClientSocket.send(ciphertext)
            ClientSocket.recv(1024)

            packet_delay = time.time() - prev_time
            packet_delay = round(packet_delay, 6)
            ClientSocket.send(str.encode(str(packet_delay)))
            ClientSocket.recv(1024)

            bundle, bundle_size = bytes(), 0


        prev_time = time.time()
    ClientSocket.send(encryption_method(str.encode('exit'), session_key))
    print('Done with experiment!')

def stop_experiment(ClientMutliSocket):
    return False

try:
    ClientMultiSocket.connect((host, port))
except socket.error as e:
    print(str(e))

while True:
    config = recv_experiment_details(ClientMultiSocket)
    session_key = client_RSA_handshake(ClientMultiSocket)
    await_syncronization(ClientMultiSocket)
    run_experiment(ClientMultiSocket, config, session_key)
    print('howdy')
    if stop_experiment(ClientMultiSocket):
        break
