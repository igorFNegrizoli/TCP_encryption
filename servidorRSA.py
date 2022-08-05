import socket
import time
from socket import SHUT_RDWR
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


HOST = "127.0.0.1"  # The server's hostname or IP address
PORT = 65432  # The port used by the server
# FILE_LEN_BYTES = 104857600
FILE_LEN_BYTES = 10000
PACKET_SIZE = 86
KEY_SIZE = 1024

def servidorRSA(host=HOST, port=PORT):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # determina as opçoes do socket e conecta
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)
        s.connect((host, port))
        print(f"Connected by {(host, port)}")
        data_sent = 0
        blocos_gerados = 0

        #le a chave publica
        print('Waiting for key')
        client_public_key = s.recv(KEY_SIZE)
        # print(f'Server received public key: {client_public_key} with len: {len(client_public_key)}')
        server_cipher = PKCS1_OAEP.new(RSA.import_key(client_public_key))

        #envia dados enquanto o contador de dados for menor que 100MB
        data_buffer = b''
        end_flag = False
        while(data_sent < FILE_LEN_BYTES):
            data_left = FILE_LEN_BYTES-data_sent
            #trata a situação em que menos que o tamanho maximo do pacote deve ser enviado (considerando o tamanho do cabeçalho)
            if(data_left < PACKET_SIZE):
                data = b"u"*data_left
                data_sent += data_left
                end_flag = True
            else:
                data =  b"m"*(PACKET_SIZE)
                data_sent += PACKET_SIZE

            #encripta a seçao de dados
            ciphertext = server_cipher.encrypt(data)
            #envia o ciphertext
            # print(f'enviou ciphertext: {ciphertext} len: {len(ciphertext)}')
            data_buffer += ciphertext

            if (len(data_buffer) >= 1000 or end_flag):
                # print(f'sent {len(data_buffer)} bytes')
                s.send(data_buffer)
                data_buffer = b''                

            blocos_gerados += 1

        s.shutdown(SHUT_RDWR)
        s.close()

if __name__ == "__main__":
    servidorRSA(HOST, PORT)