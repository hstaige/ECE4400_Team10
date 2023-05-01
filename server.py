#Multithread Socket Code goes to Digamber

import socket
import os
import pandas as pd
from _thread import *
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from threading import Barrier
import time

from encryption import Decode_Encryption_Method

ServerSideSocket = socket.socket()
host = '127.0.0.1'
port = 2004
ThreadCount = 0
num_clients = 2

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


def send_experiment_details(connection, config):
    for experiment_parameter in ['enc_method', 'packet_bytes', 'n_packets_bundled', 'packets_per_sec', 'tot_packets']:
        print(f'Sent {experiment_parameter}')
        connection.sendall(str.encode(str(config[experiment_parameter])))
        connection.recv(1024)
    good_to_go = connection.recv(2048)

    return Decode_Encryption_Method(config['enc_method'])

def synchronize_clients(connection, barrier):
    barrier.wait()
    connection.send(str.encode('All synchronized!'))
    barrier.reset()

def multi_threaded_client(connection, barrier, config):

    print(f'Beginning experiment with {config}')

    encryption_method, decryption_method = send_experiment_details(connection, config)
    session_key = server_RSA_handshake(connection)
    synchronize_clients(connection, barrier)

    delays, start_time = [], time.time()

    while True:
        data = connection.recv(2048)

        #print('Recieved Encrypted Message')
        #print(data)
        data = decryption_method(data, session_key)

        if data.decode('utf-8') == 'exit': break


        response = 'Server message: ' + data.decode('utf-8')
        connection.sendall(str.encode(response))

        delay = connection.recv(2048)
        delays.append(float(delay.decode('utf-8')))
        connection.send(str.encode('good_to_go'))

    delta_time = time.time() - start_time
    return delays, delta_time



def config_generator():
    for enc_method in range(1,4):
        for packet_bytes in [8, 16, 32, 64]:
            for n_packets_bundled in [1, 2, 4, 8]:
                for packets_per_sec in [16, 64, 128, 256]:
                    for tot_packets in [100]:
                        yield {'enc_method': enc_method, 'packet_bytes': packet_bytes, 'n_packets_bundled': n_packets_bundled,
                                'packets_per_sec': packets_per_sec, 'tot_packets': tot_packets}

def save_experiment_data(df, config, delays, delta_time, threadcount):
    experiment_results = config
    experiment_results['Average Delay'] = sum(delays) / len(delays)
    experiment_results['Maximum Delay'] = max(delays)
    experiment_results['Minimum Delay'] = min(delays)
    experiment_results['Delta Time'] = delta_time
    df = df._append(experiment_results, ignore_index = True)
    df.to_csv(f'./Results/Client{threadcount}', mode = 'w', index = False)
    return df






def manage_experiments(Client, barrier, threadcount):
    experiment_df = pd.DataFrame(columns = ['enc_method', 'packet_bytes', 'n_packets_bundled', 'packets_per_sec'] + ['Average Delay', 'Maximum Delay', 'Minimum Delay', 'Delta Time'])
    for config in config_generator():
        delays, delta_time = multi_threaded_client(Client, barrier, config)
        experiment_df = save_experiment_data(experiment_df, config, delays, delta_time, threadcount)
    Client.close()
    print('All done!')


barrier = Barrier(num_clients)
while True:
    Client, address = ServerSideSocket.accept()
    print('Connected to: ' + address[0] + ':' + str(address[1]))
    start_new_thread(manage_experiments, (Client, barrier, ThreadCount))
    ThreadCount += 1
    print('Thread Number: ' + str(ThreadCount))
ServerSideSocket.close()
