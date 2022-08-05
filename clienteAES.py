import socket
import time
from Crypto.Cipher import AES

from sqlalchemy import true

HOST = "127.0.0.1"  # Standard loopback interface address (localhost)
PORT = 65432  # Port to listen on (non-privileged ports are > 1023)
PACKET_SIZE = 1024
KEY_SIZE = 16

def clienteAES(host=HOST, port=PORT):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        conn, addr = s.accept() #Só avança a linha quando a conexao é estabelecida
        data_received = 0
        blocos_recebidos = 0
        print(f"Connected by {addr}")

        #le a chave
        print('Waiting for key')
        key = conn.recv(KEY_SIZE)
        #começa a contar o tempo
        tempo_inicial = time.time()

        #lê os dados enquento eles sao enviados
        while True:
            data = conn.recv(PACKET_SIZE)
            #se nao receber nada sai do loop
            if not data:
                break
            blocos_recebidos += 1
            #processa o cabeçalho
            nonce = data[:16]
            tag = data[16:32]
            ciphertext = data[32:]
            data_received += len(ciphertext)
            cipher = AES.new(key, AES.MODE_EAX, nonce)
            #decripta a seçao de dados
            decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
            # print(f'Server sent: {decrypted_data} | {len(ciphertext)} bytes')  
        tempo_final = time.time() - tempo_inicial
        print(f'All data received. Received {data_received} bytes in {blocos_recebidos} blocks ')
        print(f'Fime taken: {tempo_final}')
        s.close()
        return tempo_final, data_received, blocos_recebidos

if __name__ == "__main__":
    clienteAES(HOST, PORT)