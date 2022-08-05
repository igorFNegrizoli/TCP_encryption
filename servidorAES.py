import socket
import time
from socket import SHUT_RDWR
from Crypto.Cipher import AES


HOST = "127.0.0.1"  # The server's hostname or IP address
PORT = 65432  # The port used by the server
FILE_LEN_BYTES = 104857600
# FILE_LEN_BYTES = 10000
PACKET_SIZE = 1024
CRYPTO_KEY = b'Sixteen byte key'#128 bits key
#tamanho da nonce + tamanho da tag
HEADER_LEN = 32

def servidorAES(host=HOST, port=PORT):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # determina as opçoes do socket e conecta
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)
        s.connect((host, port))
        print(f"Connected by {(host, port)}")
        data_sent = 0
        blocos_gerados = 0

        #envia a chave
        s.send(CRYPTO_KEY)

        #envia dados enquanto o contador de dados for menor que 100MB
        while(data_sent < FILE_LEN_BYTES):
            cipher = AES.new(CRYPTO_KEY, AES.MODE_EAX)
            nonce = cipher.nonce
            data_left = FILE_LEN_BYTES-data_sent

            #trata a situação em que menos que o tamanho maximo do pacote deve ser enviado (considerando o tamanho do cabeçalho)
            if(data_left + HEADER_LEN < PACKET_SIZE):
                data = b"u"*data_left
                data_sent += data_left
            else:
                data =  b"m"*(PACKET_SIZE-HEADER_LEN)
                data_sent += PACKET_SIZE-HEADER_LEN
            #encripta a seçao de dados
            ciphertext, tag = cipher.encrypt_and_digest(data)
            #envia o cabeçalho em plaintext (nonce + tag) e o ciphertext
            s.send(nonce + tag + ciphertext)
            blocos_gerados += 1
        s.shutdown(SHUT_RDWR)
        s.close()
    # print(f"All {data_sent} bytes of data sent. Blocos gerados: {blocos_gerados}")
    return data_sent, blocos_gerados

if __name__ == "__main__":
    servidorAES(HOST, PORT)