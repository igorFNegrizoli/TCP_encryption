import socket
import time
from socket import SHUT_RDWR
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

HOST = "127.0.0.1"  # The server's hostname or IP address
PORT = 65432  # The port used by the server
PACKET_SIZE = 1024
#tamanho da nonce + tamanho da tag

def clienteRSA(host=HOST, port=PORT):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        conn, addr = s.accept() #Só avança a linha quando a conexao é estabelecida
        data_received = 0
        blocos_recebidos = 0
        print(f"Connected by {addr}")

        tempo_inicial = time.time()

        client_rsa_key = RSA.generate(1024)
        client_private_key = client_rsa_key.export_key()
        client_public_key = client_rsa_key.public_key().export_key()
        #envia a chave
        #print(f'Client sent key: {client_public_key}')
        conn.send(client_public_key)
        client_cipher = PKCS1_OAEP.new(client_rsa_key)
        print('Receiving data')
        #lê os dados enquento eles sao enviados
        while True:
            packet = conn.recv(PACKET_SIZE)
            #se nao receber nada sai do loop
            #print(f'recovered {packet}')
            if not packet:
                break
            ciphertexts = []
            for i in range(0, len(packet), 128):
                if len(packet) >= i+128:
                    ciphertexts.append(packet[i:i+128])
                else:
                    ciphertexts.append(packet[i:])
            blocos_recebidos += 1
            for ciphertext in ciphertexts:
                
                #decripta a seçao de dados
                # print(f'Ciphertext recebido: {ciphertext} with len: {len(ciphertext)}')
                plaintext = client_cipher.decrypt(ciphertext)
                data_received += len(plaintext)
                # print(f'Server sent: {plaintext} | {len(plaintext)} bytes')

        s.close()
        tempo_final = time.time() - tempo_inicial
        print(f'All data received. Received {data_received} bytes in {blocos_recebidos} blocks ')
        print(f'Time taken: {tempo_final}')
        return tempo_final, data_received, blocos_recebidos

if __name__ == "__main__":
    clienteRSA(HOST, PORT)